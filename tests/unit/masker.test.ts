import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { maskSecrets, maskValue } from '../../src/audit/masker.js';
import { ALL_SECRET_PATTERNS } from '../../src/detection/secrets.js';
import { SqliteAuditStore } from '../../src/audit/storage.js';
import { AuditLoggerImpl } from '../../src/audit/logger.js';
import type { JsonRpcMessage, ScanResult } from '../../src/types.js';

/**
 * Build test tokens at runtime to avoid triggering GitHub push protection.
 * These are NOT real credentials — they are constructed fake values.
 */
const T = {
  github: ['ghp', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234'].join('_'),
  stripeLive: ['sk', 'live', 'abcdefghijklmnopqrstuvwx'].join('_'),
};

describe('maskValue', () => {
  it('should mask long secrets with prefix and suffix', () => {
    const result = maskValue('AKIAIOSFODNN7EXAMPLE');
    expect(result).toBe('AKIA************MPLE');
    expect(result).not.toContain('IOSFODNN7EXA');
  });

  it('should fully redact short secrets (< 12 chars)', () => {
    expect(maskValue('short_key')).toBe('[REDACTED]');
    expect(maskValue('abc')).toBe('[REDACTED]');
  });

  it('should handle exactly 12 char secrets with partial masking', () => {
    const result = maskValue('123456789012');
    expect(result).toBe('1234****9012');
  });
});

describe('maskSecrets', () => {
  it('should mask AWS access keys', () => {
    const text = 'My key is AKIAIOSFODNN7EXAMPLE and it works';
    const result = maskSecrets(text, ALL_SECRET_PATTERNS);
    expect(result).toContain('AKIA');
    expect(result).toContain('MPLE');
    expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('should mask GitHub tokens', () => {
    const token = T.github;
    const text = `Authorization: token ${token}`;
    const result = maskSecrets(text, ALL_SECRET_PATTERNS);
    expect(result).not.toContain(token);
  });

  it('should mask Stripe keys', () => {
    const key = T.stripeLive;
    const text = `stripe.api_key = "${key}"`;
    const result = maskSecrets(text, ALL_SECRET_PATTERNS);
    expect(result).not.toContain(key);
  });

  it('should mask JWT tokens', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const text = `Bearer ${jwt}`;
    const result = maskSecrets(text, ALL_SECRET_PATTERNS);
    expect(result).not.toContain(jwt);
  });

  it('should return text unchanged when no secrets present', () => {
    const text = 'This is a normal log message with no secrets at all.';
    const result = maskSecrets(text, ALL_SECRET_PATTERNS);
    expect(result).toBe(text);
  });

  it('should mask multiple secrets in the same text', () => {
    const text = `AWS: AKIAIOSFODNN7EXAMPLE, GitHub: ${T.github}`;
    const result = maskSecrets(text, ALL_SECRET_PATTERNS);
    expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(result).not.toContain(T.github);
  });

  it('should handle empty text', () => {
    expect(maskSecrets('', ALL_SECRET_PATTERNS)).toBe('');
  });

  it('should handle empty patterns array', () => {
    const text = 'AKIAIOSFODNN7EXAMPLE';
    expect(maskSecrets(text, [])).toBe(text);
  });
});

describe('Secret masking in audit DB', () => {
  let store: SqliteAuditStore;
  let dir: string;
  let logger: AuditLoggerImpl;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-fence-masker-test-'));
    store = new SqliteAuditStore(join(dir, 'test.db'));
    logger = new AuditLoggerImpl(store);
  });

  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('should store masked secrets in the message column', async () => {
    const awsKey = 'AKIAIOSFODNN7EXAMPLE';
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { content: [{ type: 'text', text: `Here is the key: ${awsKey}` }] },
    };

    const result: ScanResult = {
      decision: 'warn',
      findings: [
        { ruleId: 'SEC-001', message: `AWS key found: ${awsKey}`, severity: 'critical', category: 'secret', confidence: 0.95 },
      ],
      score: 0.8,
      direction: 'response',
      timestamp: Date.now(),
    };

    await logger.log(message, result);

    const events = store.query();
    expect(events).toHaveLength(1);

    // The stored message should NOT contain the raw AWS key
    expect(events[0]!.message).not.toContain(awsKey);
    // But should contain the masked prefix
    expect(events[0]!.message).toContain('AKIA');

    // The stored findings should also be masked
    expect(events[0]!.findings).not.toContain(awsKey);
  });

  it('should mask secrets in findings messages', async () => {
    const token = T.github;
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { token },
    };

    const result: ScanResult = {
      decision: 'warn',
      findings: [
        { ruleId: 'SEC-010', message: `GitHub token detected: ${token}`, severity: 'critical', category: 'secret', confidence: 0.95 },
      ],
      score: 0.8,
      direction: 'response',
      timestamp: Date.now(),
    };

    await logger.log(message, result);

    const events = store.query();
    const storedFindings = events[0]!.findings;
    expect(storedFindings).not.toContain(token);
  });
});
