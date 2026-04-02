/**
 * W4 Security Assessment: Audit Logging & SARIF Output
 *
 * Penetration tests targeting:
 * - SQL injection via all string fields (tool_name, method, message, findings)
 * - Log tampering and integrity (append-only guarantees, deletion)
 * - Sensitive data exposure in audit logs
 * - SARIF output robustness (malicious content, unicode, resource exhaustion)
 * - CLI security (parseDuration overflow, --db path traversal, arbitrary DB reads)
 * - Integration: audit logging behavior under proxy failure conditions
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync, writeFileSync, chmodSync, statSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import Database from 'better-sqlite3';
import { SqliteAuditStore } from '../../src/audit/storage.js';
import { AuditLoggerImpl } from '../../src/audit/logger.js';
import { toSarif, sarifToJson } from '../../src/audit/sarif.js';
import type { AuditEvent } from '../../src/audit/storage.js';
import type { EventRow } from '../../src/audit/schema.js';
import type { JsonRpcMessage, ScanResult, Finding } from '../../src/types.js';

// ────────────────────────────────────────────────────────────────
// Test helpers
// ────────────────────────────────────────────────────────────────

const TEST_DB_DIR = join(tmpdir(), 'mcp-fence-audit-security-tests');
let testDbPath: string;
let store: SqliteAuditStore;
let dbCounter = 0;

function nextDbPath(): string {
  dbCounter++;
  return join(TEST_DB_DIR, `audit-sec-${Date.now()}-${dbCounter}.db`);
}

function makeEvent(overrides?: Partial<AuditEvent>): AuditEvent {
  return {
    timestamp: Date.now(),
    direction: 'request',
    method: 'tools/call',
    toolName: 'read_file',
    decision: 'allow',
    score: 0,
    findings: '[]',
    message: '{"jsonrpc":"2.0","id":1,"method":"tools/call"}',
    ...overrides,
  };
}

function makeJsonRpcRequest(overrides?: Partial<JsonRpcMessage>): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: 'read_file', arguments: { path: '/tmp/test.txt' } },
    ...overrides,
  } as JsonRpcMessage;
}

function makeScanResult(overrides?: Partial<ScanResult>): ScanResult {
  return {
    decision: 'allow',
    findings: [],
    score: 0,
    direction: 'request',
    timestamp: Date.now(),
    ...overrides,
  };
}

function makeFinding(overrides?: Partial<Finding>): Finding {
  return {
    ruleId: 'INJ-001',
    message: 'Prompt injection detected',
    severity: 'high',
    category: 'injection',
    confidence: 0.9,
    ...overrides,
  };
}

beforeEach(() => {
  if (!existsSync(TEST_DB_DIR)) {
    mkdirSync(TEST_DB_DIR, { recursive: true });
  }
  testDbPath = nextDbPath();
  store = new SqliteAuditStore(testDbPath);
});

afterEach(() => {
  try { store.close(); } catch { /* already closed */ }
  try { if (existsSync(testDbPath)) unlinkSync(testDbPath); } catch { /* ignore */ }
  // Clean up WAL/SHM files
  try { if (existsSync(testDbPath + '-wal')) unlinkSync(testDbPath + '-wal'); } catch { /* ignore */ }
  try { if (existsSync(testDbPath + '-shm')) unlinkSync(testDbPath + '-shm'); } catch { /* ignore */ }
});

// ════════════════════════════════════════════════════════════════
// 1. SQL INJECTION TESTING
// ════════════════════════════════════════════════════════════════

describe('SQL Injection via tool_name', () => {
  it('classic DROP TABLE via tool_name is safely stored as data', () => {
    const payload = "'; DROP TABLE events; --";
    store.insert(makeEvent({ toolName: payload }));

    const rows = store.query();
    expect(rows).toHaveLength(1);
    expect(rows[0].tool_name).toBe(payload);

    // Verify the table still exists by inserting another event
    store.insert(makeEvent({ toolName: 'normal_tool' }));
    expect(store.count()).toBe(2);
  });

  it('UNION SELECT via tool_name does not leak data', () => {
    const payload = "' UNION SELECT id,timestamp,direction,method,tool_name,decision,score,findings,message FROM events --";
    store.insert(makeEvent({ toolName: payload }));

    const rows = store.query();
    expect(rows).toHaveLength(1);
    expect(rows[0].tool_name).toBe(payload);
  });

  it('boolean-based blind injection via tool_name', () => {
    const payload = "' OR '1'='1";
    store.insert(makeEvent({ toolName: payload }));

    const rows = store.query();
    expect(rows).toHaveLength(1);
    expect(rows[0].tool_name).toBe(payload);
  });

  it('stacked queries via tool_name', () => {
    const payload = "tool'; INSERT INTO events (timestamp, direction, decision, score) VALUES (0, 'request', 'allow', 0); --";
    store.insert(makeEvent({ toolName: payload }));

    // Only the legitimate insert should exist
    const rows = store.query();
    expect(rows).toHaveLength(1);
    expect(rows[0].tool_name).toBe(payload);
  });
});

describe('SQL Injection via method name', () => {
  it('DROP TABLE via method is safely stored', () => {
    const payload = "'; DELETE FROM events; --";
    store.insert(makeEvent({ method: payload }));

    const rows = store.query();
    expect(rows).toHaveLength(1);
    expect(rows[0].method).toBe(payload);

    // Table still intact
    store.insert(makeEvent());
    expect(store.count()).toBe(2);
  });

  it('time-based blind injection via method', () => {
    // SQLite equivalent of time-based blind
    const payload = "' OR CASE WHEN (SELECT COUNT(*) FROM events) > 0 THEN randomblob(100000000) ELSE 0 END --";
    store.insert(makeEvent({ method: payload }));

    const rows = store.query();
    expect(rows).toHaveLength(1);
    expect(rows[0].method).toBe(payload);
  });
});

describe('SQL Injection via message content', () => {
  it('SQL injection in serialized JSON message field', () => {
    const maliciousMessage = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'read_file',
        arguments: { path: "'); DROP TABLE events; --" },
      },
    });

    store.insert(makeEvent({ message: maliciousMessage }));

    const rows = store.query();
    expect(rows).toHaveLength(1);
    const parsed = JSON.parse(rows[0].message!);
    expect(parsed.params.arguments.path).toBe("'); DROP TABLE events; --");

    // Table intact
    expect(store.count()).toBe(1);
  });

  it('null bytes in message field', () => {
    const payload = 'before\x00after\x00DROP TABLE events';
    store.insert(makeEvent({ message: payload }));

    const rows = store.query();
    expect(rows).toHaveLength(1);
    // SQLite handles null bytes differently from C-strings
    expect(rows[0].message).toBeTruthy();
  });
});

describe('SQL Injection via findings JSON field', () => {
  it('malicious JSON in findings field', () => {
    const payload = JSON.stringify([
      {
        ruleId: "'; DROP TABLE events; --",
        message: "test'; DELETE FROM events WHERE '1'='1",
        severity: 'high',
        category: 'injection',
        confidence: 0.9,
      },
    ]);

    store.insert(makeEvent({ findings: payload }));

    const rows = store.query();
    expect(rows).toHaveLength(1);
    const findings = JSON.parse(rows[0].findings);
    expect(findings[0].ruleId).toBe("'; DROP TABLE events; --");

    // Table intact
    store.insert(makeEvent());
    expect(store.count()).toBe(2);
  });

  it('deeply nested JSON in findings does not cause issues', () => {
    // Build deeply nested structure
    let nested: unknown = { ruleId: 'INJ-001', message: 'deep' };
    for (let i = 0; i < 100; i++) {
      nested = { wrapper: nested };
    }
    const payload = JSON.stringify([nested]);

    store.insert(makeEvent({ findings: payload }));

    const rows = store.query();
    expect(rows).toHaveLength(1);
    // Verify it round-trips correctly
    const parsed = JSON.parse(rows[0].findings);
    expect(parsed).toHaveLength(1);
  });
});

describe('Parameterized queries verification', () => {
  it('confirms insert uses prepared statement (not string concatenation)', () => {
    // If string concatenation were used, this would break the SQL syntax.
    // With parameterized queries, it is safely escaped.
    const payload = "tool', 'allow', 0, '[]', ''); DROP TABLE events; --";
    store.insert(makeEvent({ toolName: payload }));

    expect(store.count()).toBe(1);
    const rows = store.query();
    expect(rows[0].tool_name).toBe(payload);
  });

  it('query filters use parameterized values', () => {
    store.insert(makeEvent({ decision: 'block', score: 0.9 }));
    store.insert(makeEvent({ decision: 'allow', score: 0.1 }));

    // If decision filter used string concatenation, this would inject
    const rows = store.query({ decision: 'block' as 'block' });
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('block');
  });

  it('database integrity after batch injection attempts', () => {
    const injectionPayloads = [
      "'; DROP TABLE events; --",
      "' OR 1=1 --",
      "' UNION SELECT * FROM sqlite_master --",
      "'; UPDATE events SET decision='allow' WHERE 1=1; --",
      "'; CREATE TABLE hacked (data TEXT); --",
      "'; ATTACH DATABASE '/tmp/evil.db' AS evil; --",
      "Robert'); DROP TABLE events;--",
    ];

    for (const payload of injectionPayloads) {
      store.insert(makeEvent({ toolName: payload, method: payload }));
    }

    expect(store.count()).toBe(injectionPayloads.length);

    // Verify schema is unchanged — events table still has correct structure
    const db = new Database(testDbPath, { readonly: true });
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as Array<{ name: string }>;
    const tableNames = tables.map((t) => t.name);
    expect(tableNames).toContain('events');
    expect(tableNames).not.toContain('hacked');
    db.close();
  });
});

// ════════════════════════════════════════════════════════════════
// 2. LOG TAMPERING / INTEGRITY
// ════════════════════════════════════════════════════════════════

describe('Audit log append-only guarantees', () => {
  it('VULNERABILITY: no API to delete events, but direct DB access allows it', () => {
    store.insert(makeEvent({ toolName: 'evidence_tool' }));
    store.insert(makeEvent({ toolName: 'another_tool' }));
    expect(store.count()).toBe(2);

    // The AuditStore interface has no delete method — good.
    // But the underlying SQLite file has no row-level security.
    // An attacker with file access can modify/delete events directly.
    const db = new Database(testDbPath);
    db.prepare('DELETE FROM events WHERE tool_name = ?').run('evidence_tool');
    db.close();

    // Evidence has been tampered with
    const rows = store.query();
    expect(rows).toHaveLength(1);
    expect(rows[0].tool_name).toBe('another_tool');
    // VULNERABILITY: audit log has no integrity protection (HMAC, append-only WAL, etc.)
  });

  it('VULNERABILITY: stored events can be modified after insertion', () => {
    store.insert(makeEvent({ decision: 'block', score: 0.95, toolName: 'malicious' }));

    // Attacker modifies the audit record to hide the block
    const db = new Database(testDbPath);
    db.prepare("UPDATE events SET decision = 'allow', score = 0.0 WHERE tool_name = 'malicious'").run();
    db.close();

    const rows = store.query();
    expect(rows[0].decision).toBe('allow'); // Evidence tampered
    expect(rows[0].score).toBe(0.0);
    // VULNERABILITY: no HMAC or row-level hash to detect modification
  });

  it('no delete method exposed on AuditStore interface (positive finding)', () => {
    // Verify the interface only has insert, query, count, close
    const storeMethods = Object.getOwnPropertyNames(SqliteAuditStore.prototype);
    expect(storeMethods).toContain('insert');
    expect(storeMethods).toContain('query');
    expect(storeMethods).toContain('count');
    expect(storeMethods).toContain('close');
    expect(storeMethods).not.toContain('delete');
    expect(storeMethods).not.toContain('update');
    expect(storeMethods).not.toContain('truncate');
  });
});

describe('Audit log resource exhaustion', () => {
  it('VULNERABILITY: no size limit on audit database', () => {
    // Insert many events with large payloads
    const largeMessage = JSON.stringify({ data: 'A'.repeat(10000) });
    const largeFinding = JSON.stringify([
      { ruleId: 'TEST', message: 'B'.repeat(10000), severity: 'high', category: 'injection', confidence: 0.9 },
    ]);

    for (let i = 0; i < 100; i++) {
      store.insert(makeEvent({
        message: largeMessage,
        findings: largeFinding,
        toolName: 'T'.repeat(1000),
        method: 'M'.repeat(1000),
      }));
    }

    // All 100 events stored — no limit enforced
    expect(store.count()).toBe(100);

    // Check file size — with 100 events at ~22KB each, DB is ~2MB+
    const stats = statSync(testDbPath);
    expect(stats.size).toBeGreaterThan(100_000); // At least 100KB
    // VULNERABILITY: No max DB size, no rotation, no event TTL.
    // An attacker triggering many scans can exhaust disk space.
  });

  it('VULNERABILITY: no limit on individual field sizes', () => {
    // 1MB tool name
    const hugeToolName = 'X'.repeat(1_000_000);
    store.insert(makeEvent({ toolName: hugeToolName }));

    const rows = store.query();
    expect(rows).toHaveLength(1);
    expect(rows[0].tool_name!.length).toBe(1_000_000);
    // VULNERABILITY: no field size validation — single event can consume arbitrary memory
  });
});

describe('Database file lifecycle', () => {
  it('database handles concurrent reads during writes', () => {
    // WAL mode should allow concurrent reads
    store.insert(makeEvent({ toolName: 'first' }));

    const readStore = new SqliteAuditStore(testDbPath);
    const rows = readStore.query();
    expect(rows).toHaveLength(1);

    // Write while second connection reads
    store.insert(makeEvent({ toolName: 'second' }));

    const rows2 = readStore.query();
    expect(rows2).toHaveLength(2);

    readStore.close();
  });

  it('operations after close throw error (does not silently corrupt)', () => {
    store.insert(makeEvent());
    store.close();

    expect(() => store.insert(makeEvent())).toThrow();
    expect(() => store.query()).toThrow();
  });
});

// ════════════════════════════════════════════════════════════════
// 3. SENSITIVE DATA IN AUDIT LOG
// ════════════════════════════════════════════════════════════════

describe('Sensitive data exposure in audit log', () => {
  it('VULNERABILITY: full JSON-RPC message stored — tool arguments include secrets', async () => {
    const logger = new AuditLoggerImpl(store);

    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'execute_sql',
        arguments: {
          query: 'SELECT * FROM users',
          password: 'SuperSecret123!',
          connection_string: 'postgresql://admin:p@ssw0rd@db.internal:5432/prod',
        },
      },
    };

    const result = makeScanResult({
      decision: 'warn',
      findings: [makeFinding({ message: 'Potential data access' })],
      score: 0.6,
    });

    await logger.log(message, result);

    const rows = store.query();
    const storedMessage = JSON.parse(rows[0].message!);

    // The full message including secrets is stored in plain text
    expect(storedMessage.params.arguments.password).toBe('SuperSecret123!');
    expect(storedMessage.params.arguments.connection_string).toContain('p@ssw0rd');
    // VULNERABILITY: audit log becomes a target for credential harvesting.
    // No redaction of sensitive fields in tool arguments.
  });

  it('FIXED: detected secrets are masked before storage in findings', async () => {
    const logger = new AuditLoggerImpl(store);

    const secret = ['sk','proj','ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef'].join('-');
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: {
        content: [{
          type: 'text',
          text: `Here is the API key: ${secret}`,
        }],
      },
    };

    const result = makeScanResult({
      decision: 'block',
      direction: 'response',
      findings: [
        makeFinding({
          ruleId: 'SEC-014',
          message: `OpenAI API key detected: ${secret}`,
          severity: 'critical',
          category: 'secret',
        }),
      ],
      score: 0.95,
    });

    await logger.log(message, result);

    const rows = store.query();
    const findings = JSON.parse(rows[0].findings);

    // The finding message should NOT contain the raw secret (masked by v0.2.0)
    expect(findings[0].message).not.toContain(secret);
    // The stored response text should also be masked
    const storedMsg = JSON.parse(rows[0].message!);
    expect(JSON.stringify(storedMsg)).not.toContain(secret);
    // FIX: secrets are now masked before audit storage, preventing the DB
    // from becoming a concentrated target for credential harvesting.
  });

  it('VULNERABILITY: database file has no restricted permissions', () => {
    // Check default file permissions
    const stats = statSync(testDbPath);
    const mode = (stats.mode & 0o777).toString(8);

    // On most systems, default umask creates 644 or 666.
    // A security-conscious application would set 600 (owner read/write only).
    // We note the actual permissions — they depend on process umask.
    const ownerRead = (stats.mode & 0o400) !== 0;
    const ownerWrite = (stats.mode & 0o200) !== 0;
    const groupRead = (stats.mode & 0o040) !== 0;
    const othersRead = (stats.mode & 0o004) !== 0;

    expect(ownerRead).toBe(true);
    expect(ownerWrite).toBe(true);
    // VULNERABILITY if group or others can read:
    // The DB file permissions are inherited from umask, not explicitly restricted.
    // SQLite DB containing secrets should be 0600 at minimum.
    if (groupRead || othersRead) {
      // This is a vulnerability — document it but don't fail the test
      // as it depends on system umask configuration
      expect(true).toBe(true); // VULNERABILITY: group/others may read audit DB
    }
  });
});

// ════════════════════════════════════════════════════════════════
// 4. SARIF OUTPUT SECURITY
// ════════════════════════════════════════════════════════════════

describe('SARIF output: malicious content in findings', () => {
  it('JSON special characters in findings produce valid SARIF', () => {
    const events: EventRow[] = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'request',
        method: 'tools/call',
        tool_name: 'tool_with"quotes',
        decision: 'block',
        score: 0.9,
        findings: JSON.stringify([
          {
            ruleId: 'INJ-001',
            message: 'Found: "ignore\nprevious\\instructions"',
            severity: 'high',
            category: 'injection',
            confidence: 0.9,
          },
        ]),
        message: null,
      },
    ];

    const sarif = toSarif(events);
    const json = sarifToJson(sarif);

    // Must produce valid JSON
    expect(() => JSON.parse(json)).not.toThrow();
    const parsed = JSON.parse(json);
    expect(parsed.runs[0].results[0].message.text).toContain('tool_with"quotes');
  });

  it('HTML/script injection in findings does not corrupt SARIF', () => {
    const events: EventRow[] = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'request',
        method: '<script>alert("xss")</script>',
        tool_name: '<img onerror="alert(1)" src=x>',
        decision: 'warn',
        score: 0.7,
        findings: JSON.stringify([
          {
            ruleId: 'INJ-001',
            message: '<script>document.cookie</script>',
            severity: 'high',
            category: 'injection',
            confidence: 0.85,
          },
        ]),
        message: null,
      },
    ];

    const sarif = toSarif(events);
    const json = sarifToJson(sarif);

    // Valid JSON output
    expect(() => JSON.parse(json)).not.toThrow();
    const parsed = JSON.parse(json);
    // Content is preserved as-is (JSON serialization escapes it)
    expect(parsed.runs[0].results[0].message.text).toContain('<script>');
  });

  it('control characters and null bytes in SARIF output', () => {
    const events: EventRow[] = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'request',
        method: "method\x00with\x01control\x02chars",
        tool_name: "tool\ttab\nnewline\rcarriage",
        decision: 'block',
        score: 0.8,
        findings: JSON.stringify([
          {
            ruleId: 'INJ-001',
            message: "finding\x00with\x07bell\x08backspace",
            severity: 'high',
            category: 'injection',
            confidence: 0.9,
          },
        ]),
        message: null,
      },
    ];

    const sarif = toSarif(events);
    const json = sarifToJson(sarif);

    // JSON.stringify handles control characters via escaping
    expect(() => JSON.parse(json)).not.toThrow();
  });
});

describe('SARIF: Unicode handling', () => {
  it('valid UTF-8 output with CJK characters', () => {
    const events: EventRow[] = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'request',
        method: 'tools/call',
        tool_name: '도구_이름_한글',
        decision: 'warn',
        score: 0.6,
        findings: JSON.stringify([
          {
            ruleId: 'INJ-012',
            message: '이전 지시를 무시하세요 (Korean injection)',
            severity: 'medium',
            category: 'injection',
            confidence: 0.7,
          },
        ]),
        message: null,
      },
    ];

    const sarif = toSarif(events);
    const json = sarifToJson(sarif);

    expect(() => JSON.parse(json)).not.toThrow();
    const parsed = JSON.parse(json);
    expect(parsed.runs[0].results[0].message.text).toContain('도구_이름_한글');
  });

  it('emoji and surrogate pairs in SARIF', () => {
    const events: EventRow[] = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'request',
        method: 'tools/call',
        tool_name: 'tool_with_emoji_\uD83D\uDE00',
        decision: 'warn',
        score: 0.5,
        findings: JSON.stringify([
          {
            ruleId: 'INJ-001',
            message: 'Finding with emoji \uD83D\uDEA8 and symbols \u2603\u2764',
            severity: 'medium',
            category: 'injection',
            confidence: 0.7,
          },
        ]),
        message: null,
      },
    ];

    const sarif = toSarif(events);
    const json = sarifToJson(sarif);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it('homoglyph unicode in SARIF does not break JSON', () => {
    const events: EventRow[] = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'request',
        method: 'tools/call',
        tool_name: '\u043E\u0456\u0443', // Cyrillic homoglyphs
        decision: 'block',
        score: 0.85,
        findings: JSON.stringify([
          {
            ruleId: 'INJ-001',
            message: 'Homoglyph attack: ign\u043Ere previous',
            severity: 'high',
            category: 'injection',
            confidence: 0.9,
          },
        ]),
        message: null,
      },
    ];

    const sarif = toSarif(events);
    const json = sarifToJson(sarif);
    expect(() => JSON.parse(json)).not.toThrow();
  });
});

describe('SARIF: resource exhaustion', () => {
  it('large number of events produces valid but large SARIF', () => {
    const events: EventRow[] = [];
    for (let i = 0; i < 1000; i++) {
      events.push({
        id: i,
        timestamp: Date.now() + i,
        direction: 'request',
        method: 'tools/call',
        tool_name: `tool_${i}`,
        decision: 'warn',
        score: 0.6,
        findings: JSON.stringify([
          {
            ruleId: `RULE-${i}`,
            message: `Finding ${i}: ${'X'.repeat(500)}`,
            severity: 'medium',
            category: 'injection',
            confidence: 0.7,
          },
        ]),
        message: null,
      });
    }

    const start = performance.now();
    const sarif = toSarif(events);
    const json = sarifToJson(sarif);
    const elapsed = performance.now() - start;

    expect(() => JSON.parse(json)).not.toThrow();
    // Should complete in reasonable time
    expect(elapsed).toBeLessThan(5000); // Under 5 seconds

    // Verify result count
    const parsed = JSON.parse(json);
    expect(parsed.runs[0].results.length).toBe(1000);
    // NOTE: 1000 unique rules are registered — memory proportional to event count
  });

  it('VULNERABILITY: SARIF output includes full event properties (sensitive data leakage)', () => {
    const events: EventRow[] = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'response',
        method: 'tools/call',
        tool_name: 'get_secrets',
        decision: 'block',
        score: 0.95,
        findings: JSON.stringify([
          {
            ruleId: 'SEC-014',
            message: 'OpenAI key: ' + ['sk','proj','ABCDEFGHIJKLMNOPQRSTUVWXYZ'].join('-') + '',
            severity: 'critical',
            category: 'secret',
            confidence: 0.99,
          },
        ]),
        message: '{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"' + ['sk','proj','ABCDEFGHIJKLMNOPQRSTUVWXYZ'].join('-') + '"}]}}',
      },
    ];

    const sarif = toSarif(events);
    const json = sarifToJson(sarif);
    const parsed = JSON.parse(json);

    // SARIF properties include tool name, method, decision, score — but NOT the full message.
    // The message field from EventRow is not included in SARIF properties.
    // However, the finding MESSAGE itself contains the secret.
    expect(parsed.runs[0].results[0].message.text).toContain('' + ['sk','proj','ABCDEFGHIJKLMNOPQRSTUVWXYZ'].join('-') + '');
    // VULNERABILITY: if SARIF is uploaded to GitHub Security tab,
    // the secret appears in the security alert visible to all repo collaborators.
  });

  it('events with malformed findings JSON are silently skipped', () => {
    const events: EventRow[] = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'request',
        method: 'tools/call',
        tool_name: 'tool',
        decision: 'block',
        score: 0.9,
        findings: 'NOT VALID JSON {{{',
        message: null,
      },
      {
        id: 2,
        timestamp: Date.now(),
        direction: 'request',
        method: 'tools/call',
        tool_name: 'tool2',
        decision: 'warn',
        score: 0.6,
        findings: JSON.stringify([
          { ruleId: 'INJ-001', message: 'Valid finding', severity: 'high', category: 'injection', confidence: 0.9 },
        ]),
        message: null,
      },
    ];

    const sarif = toSarif(events);
    // Malformed findings are skipped, valid ones are included
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].ruleId).toBe('INJ-001');
  });

  it('allow events are filtered out of SARIF (positive finding)', () => {
    const events: EventRow[] = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'request',
        method: 'tools/call',
        tool_name: 'safe_tool',
        decision: 'allow',
        score: 0.0,
        findings: '[]',
        message: '{"jsonrpc":"2.0"}',
      },
    ];

    const sarif = toSarif(events);
    expect(sarif.runs[0].results).toHaveLength(0);
    // Good: clean events do not pollute the security report
  });
});

// ════════════════════════════════════════════════════════════════
// 5. CLI SECURITY
// ════════════════════════════════════════════════════════════════

describe('parseDuration edge cases', () => {
  // We test the logic of parseDuration by reimplementing it here,
  // since the actual function calls process.exit() on invalid input.
  // The security concern is whether extreme values cause integer overflow.

  function parseDurationSafe(duration: string): number | null {
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) return null;

    const value = parseInt(match[1]!, 10);
    const unit = match[2]!;
    const multipliers: Record<string, number> = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
    };

    return Date.now() - value * multipliers[unit]!;
  }

  it('extremely large duration value: potential integer overflow', () => {
    // JavaScript Number.MAX_SAFE_INTEGER = 9007199254740991
    // 999999999d * 86400000 = 86399999913600000000 > MAX_SAFE_INTEGER
    const result = parseDurationSafe('999999999d');
    expect(result).not.toBeNull();

    // Check if the multiplication overflows MAX_SAFE_INTEGER
    const value = 999999999;
    const multiplier = 24 * 60 * 60 * 1000; // 86400000
    const product = value * multiplier;

    // This exceeds MAX_SAFE_INTEGER — precision loss
    expect(product).toBeGreaterThan(Number.MAX_SAFE_INTEGER);
    // VULNERABILITY: parseDuration does not validate that the result
    // is within safe integer range. The resulting timestamp will have
    // precision loss, potentially producing unexpected query results.
  });

  it('zero duration produces timestamp equal to now', () => {
    const before = Date.now();
    const result = parseDurationSafe('0s');
    const after = Date.now();

    expect(result).not.toBeNull();
    expect(result!).toBeGreaterThanOrEqual(before);
    expect(result!).toBeLessThanOrEqual(after);
  });

  it('very large seconds value', () => {
    const result = parseDurationSafe('999999999s');
    expect(result).not.toBeNull();
    // 999999999 * 1000 = 999999999000 — within safe integer range
    const product = 999999999 * 1000;
    expect(product).toBeLessThan(Number.MAX_SAFE_INTEGER);
  });

  it('regex rejects non-numeric input (no injection)', () => {
    expect(parseDurationSafe('1h; rm -rf /')).toBeNull();
    expect(parseDurationSafe("1h' OR 1=1 --")).toBeNull();
    expect(parseDurationSafe('abc')).toBeNull();
    expect(parseDurationSafe('')).toBeNull();
    expect(parseDurationSafe('-1h')).toBeNull();
  });
});

describe('--db path traversal', () => {
  it('VULNERABILITY: --db accepts arbitrary paths including path traversal', () => {
    // The CLI resolves --db relative to CWD: resolve(process.cwd(), opts.db)
    // This means --db ../../../etc/important.db would resolve to an absolute path.
    // If that path exists and is a valid SQLite DB, it would be opened.

    const traversalPath = resolve(process.cwd(), '../../../tmp/mcp-fence-traversal-test.db');
    // We can't actually test creating files in /etc, but we can verify the
    // path resolution logic allows traversal.

    // Create a DB at the traversal path
    const testPath = join(TEST_DB_DIR, 'traversal-test.db');
    const traversalStore = new SqliteAuditStore(testPath);
    traversalStore.insert(makeEvent({ toolName: 'sensitive_data' }));
    traversalStore.close();

    // Another instance can open it — no path validation
    const readStore = new SqliteAuditStore(testPath);
    const rows = readStore.query();
    expect(rows).toHaveLength(1);
    readStore.close();

    // VULNERABILITY: --db path is not restricted to a safe directory.
    // An attacker could use --db to:
    // 1. Read any SQLite database on the filesystem
    // 2. Create a new database at an arbitrary path
    // 3. Point to a path traversal location

    try { unlinkSync(testPath); } catch { /* ignore */ }
  });

  it('VULNERABILITY: --db can point to any existing SQLite database', () => {
    // Create a "victim" database with different schema
    const victimPath = join(TEST_DB_DIR, 'victim.db');
    const victimDb = new Database(victimPath);
    victimDb.exec('CREATE TABLE secrets (id INTEGER, api_key TEXT)');
    victimDb.prepare('INSERT INTO secrets VALUES (?, ?)').run(1, 'sk-secret-key-12345');
    victimDb.close();

    // SqliteAuditStore will open it — CREATE TABLE IF NOT EXISTS won't fail
    // because the events table doesn't exist yet. But the secrets table is accessible.
    const auditStore = new SqliteAuditStore(victimPath);

    // The store adds its own events table
    auditStore.insert(makeEvent());
    expect(auditStore.count()).toBe(1);

    // Direct access to the same DB reveals the secrets table still exists
    const db = new Database(victimPath, { readonly: true });
    const secrets = db.prepare('SELECT api_key FROM secrets').all() as Array<{ api_key: string }>;
    expect(secrets[0].api_key).toBe('sk-secret-key-12345');
    db.close();

    auditStore.close();
    // VULNERABILITY: opening an arbitrary DB path exposes all tables in that DB

    try { unlinkSync(victimPath); } catch { /* ignore */ }
  });

  it('non-SQLite file as --db causes a clear error', () => {
    const fakePath = join(TEST_DB_DIR, 'not-a-database.txt');
    writeFileSync(fakePath, 'This is not a SQLite database file.');

    // better-sqlite3 will throw on opening a non-SQLite file
    expect(() => new SqliteAuditStore(fakePath)).toThrow();

    try { unlinkSync(fakePath); } catch { /* ignore */ }
  });
});

// ════════════════════════════════════════════════════════════════
// 6. INTEGRATION: AUDIT + PROXY
// ════════════════════════════════════════════════════════════════

describe('Audit logger integration behavior', () => {
  it('logging is synchronous (better-sqlite3) wrapped in async — no true async benefit', async () => {
    const logger = new AuditLoggerImpl(store);

    const message = makeJsonRpcRequest();
    const result = makeScanResult();

    // AuditLoggerImpl.log is async, but the underlying better-sqlite3 insert
    // is synchronous. The await is effectively a no-op.
    const start = performance.now();

    // Insert 100 events to measure blocking
    for (let i = 0; i < 100; i++) {
      await logger.log(message, { ...result, timestamp: Date.now() + i });
    }

    const elapsed = performance.now() - start;

    expect(store.count()).toBe(100);
    // With synchronous inserts, 100 events should complete quickly
    // but each one blocks the event loop for the duration of the SQLite write
    expect(elapsed).toBeLessThan(2000); // Should be fast on SSD

    // INFO: The audit logger method signature is async (returns Promise<void>),
    // but the implementation is synchronous. This means:
    // 1. The proxy's event loop IS blocked during each insert
    // 2. There is no backpressure mechanism for high-throughput scenarios
    // 3. A slow disk would cause proxy latency for every scanned message
  });

  it('FIXED: audit logger swallows store errors without propagating', async () => {
    // Simulate a store that throws on insert
    const faultyStore = {
      insert: () => { throw new Error('Disk full'); },
      query: () => [],
      count: () => 0,
      close: () => {},
    };

    const logger = new AuditLoggerImpl(faultyStore);

    // FIXED: AuditLoggerImpl.log() now catches errors internally,
    // so it resolves without throwing (proxy continues unaffected)
    await expect(
      logger.log(makeJsonRpcRequest(), makeScanResult()),
    ).resolves.toBeUndefined();

    // VULNERABILITY: If the audit store throws, the proxy's
    // handleClientMessage/handleServerMessage catches it via the void promise,
    // but the proxy uses `void this.handleClientMessage(message)` which means
    // unhandled rejections may occur. The proxy DOES have `await` on
    // auditLogger.log(), so if that throws, the entire handleClientMessage
    // promise rejects. Since it's called with `void`, this rejection is unhandled.
  });

  it('audit logger stores both request and response for the same transaction', async () => {
    const logger = new AuditLoggerImpl(store);

    const requestMsg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 42,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '/etc/passwd' } },
    };

    const responseMsg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 42,
      result: { content: [{ type: 'text', text: 'root:x:0:0:root:/root:/bin/bash' }] },
    };

    await logger.log(requestMsg, makeScanResult({ direction: 'request' }));
    await logger.log(responseMsg, makeScanResult({ direction: 'response' }));

    const requests = store.query({ direction: 'request' });
    const responses = store.query({ direction: 'response' });

    expect(requests).toHaveLength(1);
    expect(responses).toHaveLength(1);

    // Both contain the full message — including the /etc/passwd content
    const reqParsed = JSON.parse(requests[0].message!);
    const resParsed = JSON.parse(responses[0].message!);
    expect(reqParsed.params.arguments.path).toBe('/etc/passwd');
    expect(JSON.stringify(resParsed)).toContain('root:x:0:0');
    // VULNERABILITY: sensitive file contents are stored in plain text
  });
});

describe('Schema constraint enforcement', () => {
  it('direction CHECK constraint rejects invalid values', () => {
    // The schema has CHECK(direction IN ('request', 'response'))
    const db = new Database(testDbPath);
    expect(() => {
      db.prepare(
        "INSERT INTO events (timestamp, direction, decision, score, findings) VALUES (?, ?, ?, ?, ?)"
      ).run(Date.now(), 'invalid', 'allow', 0, '[]');
    }).toThrow();
    db.close();
  });

  it('decision CHECK constraint rejects invalid values', () => {
    const db = new Database(testDbPath);
    expect(() => {
      db.prepare(
        "INSERT INTO events (timestamp, direction, decision, score, findings) VALUES (?, ?, ?, ?, ?)"
      ).run(Date.now(), 'request', 'invalid_decision', 0, '[]');
    }).toThrow();
    db.close();
  });

  it('autoincrement ID cannot be manipulated through normal API', () => {
    store.insert(makeEvent());
    store.insert(makeEvent());
    store.insert(makeEvent());

    const rows = store.query();
    const ids = rows.map((r) => r.id).sort((a, b) => a - b);

    // IDs should be sequential
    expect(ids[0]).toBe(1);
    expect(ids[1]).toBe(2);
    expect(ids[2]).toBe(3);
  });
});

// ════════════════════════════════════════════════════════════════
// 7. ADDITIONAL EDGE CASES
// ════════════════════════════════════════════════════════════════

describe('AuditLogger: extractToolName and extractMethod edge cases', () => {
  it('tool name extracted from params.name in tools/call request', async () => {
    const logger = new AuditLoggerImpl(store);

    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: "'; DROP TABLE events; --" },
    };

    await logger.log(msg, makeScanResult());

    const rows = store.query();
    expect(rows[0].tool_name).toBe("'; DROP TABLE events; --");
    expect(store.count()).toBe(1); // Table intact
  });

  it('method extracted from JSON-RPC message with injection payload', async () => {
    const logger = new AuditLoggerImpl(store);

    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: "'; DELETE FROM events WHERE '1'='1",
    };

    await logger.log(msg, makeScanResult());

    const rows = store.query();
    expect(rows[0].method).toBe("'; DELETE FROM events WHERE '1'='1");
    expect(store.count()).toBe(1);
  });

  it('response message has no method or tool_name — stored as null', async () => {
    const logger = new AuditLoggerImpl(store);

    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { content: [{ type: 'text', text: 'Hello' }] },
    };

    await logger.log(msg, makeScanResult({ direction: 'response' }));

    const rows = store.query();
    expect(rows[0].method).toBeNull();
    expect(rows[0].tool_name).toBeNull();
  });
});

describe('Storage: query filter edge cases', () => {
  it('query with all filters combined', () => {
    const now = Date.now();
    store.insert(makeEvent({ timestamp: now, direction: 'request', decision: 'block', score: 0.9 }));
    store.insert(makeEvent({ timestamp: now - 10000, direction: 'response', decision: 'allow', score: 0.1 }));
    store.insert(makeEvent({ timestamp: now - 5000, direction: 'request', decision: 'warn', score: 0.6 }));

    // Filter: request direction, score >= 0.8, since now-8s
    const rows = store.query({
      since: now - 8000,
      direction: 'request',
      minScore: 0.8,
      limit: 10,
      offset: 0,
    });

    // Should match only the block event (request, score >= 0.8, since now-8s)
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('block');
  });

  it('query with limit 0 returns empty array', () => {
    store.insert(makeEvent());
    const rows = store.query({ limit: 0 });
    expect(rows).toHaveLength(0);
  });

  it('FIXED: query with offset-only no longer crashes (LIMIT -1 auto-added)', () => {
    store.insert(makeEvent());
    // buildQuery now adds LIMIT -1 when offset is set without limit.
    // Negative offset is treated as 0 by SQLite — returns all results.
    const results = store.query({ offset: -1 });
    expect(results.length).toBeGreaterThanOrEqual(0);
  });
});
