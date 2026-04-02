import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync, writeFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import Database from 'better-sqlite3';
import { SqliteAuditStore, getOrCreateHmacKey } from '../../src/audit/storage.js';
import { AuditLoggerImpl } from '../../src/audit/logger.js';
import { toSarif, sarifToJson } from '../../src/audit/sarif.js';
import type { JsonRpcMessage, ScanResult, Finding } from '../../src/types.js';

function tempDb(): { store: SqliteAuditStore; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-fence-test-'));
  const store = new SqliteAuditStore(join(dir, 'test.db'));
  return { store, dir };
}

describe('SqliteAuditStore', () => {
  let store: SqliteAuditStore;
  let dir: string;

  beforeEach(() => {
    ({ store, dir } = tempDb());
  });

  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('should insert and query events', () => {
    store.insert({
      timestamp: 1000,
      direction: 'request',
      method: 'tools/call',
      toolName: 'read_file',
      decision: 'allow',
      score: 0,
      findings: '[]',
    });

    const events = store.query();
    expect(events).toHaveLength(1);
    expect(events[0]!.method).toBe('tools/call');
    expect(events[0]!.tool_name).toBe('read_file');
    expect(events[0]!.decision).toBe('allow');
  });

  it('should filter by decision', () => {
    store.insert({ timestamp: 1000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });
    store.insert({ timestamp: 2000, direction: 'request', decision: 'block', score: 0.9, findings: '[]' });
    store.insert({ timestamp: 3000, direction: 'request', decision: 'warn', score: 0.6, findings: '[]' });

    expect(store.query({ decision: 'block' })).toHaveLength(1);
    expect(store.query({ decision: 'allow' })).toHaveLength(1);
  });

  it('should filter by timestamp range', () => {
    store.insert({ timestamp: 1000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });
    store.insert({ timestamp: 2000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });
    store.insert({ timestamp: 3000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });

    expect(store.query({ since: 1500 })).toHaveLength(2);
    expect(store.query({ since: 1500, until: 2500 })).toHaveLength(1);
  });

  it('should filter by direction', () => {
    store.insert({ timestamp: 1000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });
    store.insert({ timestamp: 2000, direction: 'response', decision: 'allow', score: 0, findings: '[]' });

    expect(store.query({ direction: 'request' })).toHaveLength(1);
    expect(store.query({ direction: 'response' })).toHaveLength(1);
  });

  it('should filter by minimum score', () => {
    store.insert({ timestamp: 1000, direction: 'request', decision: 'allow', score: 0.1, findings: '[]' });
    store.insert({ timestamp: 2000, direction: 'request', decision: 'warn', score: 0.6, findings: '[]' });
    store.insert({ timestamp: 3000, direction: 'request', decision: 'block', score: 0.9, findings: '[]' });

    expect(store.query({ minScore: 0.5 })).toHaveLength(2);
  });

  it('should support limit and offset', () => {
    for (let i = 0; i < 10; i++) {
      store.insert({ timestamp: i * 1000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });
    }

    expect(store.query({ limit: 3 })).toHaveLength(3);
    expect(store.query({ limit: 3, offset: 8 })).toHaveLength(2);
  });

  it('should count events', () => {
    store.insert({ timestamp: 1000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });
    store.insert({ timestamp: 2000, direction: 'request', decision: 'block', score: 0.9, findings: '[]' });

    expect(store.count()).toBe(2);
    expect(store.count({ decision: 'block' })).toBe(1);
  });

  it('should order by timestamp descending', () => {
    store.insert({ timestamp: 1000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });
    store.insert({ timestamp: 3000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });
    store.insert({ timestamp: 2000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });

    const events = store.query();
    expect(events[0]!.timestamp).toBe(3000);
    expect(events[2]!.timestamp).toBe(1000);
  });

  it('should store and retrieve findings JSON', () => {
    const findings: Finding[] = [
      { ruleId: 'INJ-001', message: 'test', severity: 'critical', category: 'injection', confidence: 0.9 },
    ];
    store.insert({
      timestamp: 1000,
      direction: 'request',
      decision: 'block',
      score: 0.9,
      findings: JSON.stringify(findings),
    });

    const events = store.query();
    const parsed = JSON.parse(events[0]!.findings) as Finding[];
    expect(parsed[0]!.ruleId).toBe('INJ-001');
  });
});

describe('AuditLoggerImpl', () => {
  let store: SqliteAuditStore;
  let dir: string;
  let logger: AuditLoggerImpl;

  beforeEach(() => {
    ({ store, dir } = tempDb());
    logger = new AuditLoggerImpl(store);
  });

  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('should log a message with scan result', async () => {
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'read_file' },
    };

    const result: ScanResult = {
      decision: 'warn',
      findings: [
        { ruleId: 'INJ-001', message: 'Injection', severity: 'critical', category: 'injection', confidence: 0.9 },
      ],
      score: 0.9,
      direction: 'request',
      timestamp: Date.now(),
    };

    await logger.log(message, result);

    const events = store.query();
    expect(events).toHaveLength(1);
    expect(events[0]!.method).toBe('tools/call');
    expect(events[0]!.tool_name).toBe('read_file');
    expect(events[0]!.decision).toBe('warn');
  });

  it('should handle response messages', async () => {
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { content: [{ type: 'text', text: 'hello' }] },
    };

    const result: ScanResult = {
      decision: 'allow',
      findings: [],
      score: 0,
      direction: 'response',
      timestamp: Date.now(),
    };

    await logger.log(message, result);

    const events = store.query();
    expect(events).toHaveLength(1);
    expect(events[0]!.direction).toBe('response');
    expect(events[0]!.method).toBeNull();
  });

  it('should expose store via getStore()', () => {
    expect(logger.getStore()).toBe(store);
  });
});

describe('SARIF output', () => {
  it('should produce valid SARIF 2.1.0 structure', () => {
    const events = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'request',
        method: 'tools/call',
        tool_name: 'exec_cmd',
        decision: 'block',
        score: 0.95,
        findings: JSON.stringify([
          { ruleId: 'INJ-001', message: 'Injection detected', severity: 'critical', category: 'injection', confidence: 0.95 },
        ]),
        message: null,
      },
    ];

    const sarif = toSarif(events);

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]!.tool.driver.name).toBe('mcp-fence');
    expect(sarif.runs[0]!.results).toHaveLength(1);
    expect(sarif.runs[0]!.results[0]!.ruleId).toBe('INJ-001');
    expect(sarif.runs[0]!.results[0]!.level).toBe('error');
  });

  it('should skip allow events', () => {
    const events = [
      {
        id: 1,
        timestamp: Date.now(),
        direction: 'request',
        method: 'tools/list',
        tool_name: null,
        decision: 'allow',
        score: 0,
        findings: '[]',
        message: null,
      },
    ];

    const sarif = toSarif(events);
    expect(sarif.runs[0]!.results).toHaveLength(0);
  });

  it('should map severity levels correctly', () => {
    const findings = [
      { ruleId: 'A', message: 'critical', severity: 'critical', category: 'injection', confidence: 1 },
      { ruleId: 'B', message: 'high', severity: 'high', category: 'injection', confidence: 1 },
      { ruleId: 'C', message: 'medium', severity: 'medium', category: 'injection', confidence: 1 },
      { ruleId: 'D', message: 'low', severity: 'low', category: 'injection', confidence: 1 },
    ];

    const events = [
      {
        id: 1, timestamp: Date.now(), direction: 'request', method: null, tool_name: null,
        decision: 'block', score: 1, findings: JSON.stringify(findings), message: null,
      },
    ];

    const sarif = toSarif(events);
    const levels = sarif.runs[0]!.results.map((r) => r.level);
    expect(levels).toEqual(['error', 'error', 'warning', 'note']);
  });

  it('should include multiple events with different rules', () => {
    const events = [
      {
        id: 1, timestamp: 1000, direction: 'request', method: 'tools/call', tool_name: 'cmd',
        decision: 'block', score: 0.9,
        findings: JSON.stringify([{ ruleId: 'CMD-001', message: 'Command injection', severity: 'critical', category: 'command-injection', confidence: 0.9 }]),
        message: null,
      },
      {
        id: 2, timestamp: 2000, direction: 'response', method: null, tool_name: 'read_file',
        decision: 'warn', score: 0.6,
        findings: JSON.stringify([{ ruleId: 'SEC-001', message: 'AWS key detected', severity: 'critical', category: 'secret', confidence: 0.95 }]),
        message: null,
      },
    ];

    const sarif = toSarif(events);
    expect(sarif.runs[0]!.results).toHaveLength(2);
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(2);
  });

  it('should produce valid JSON string', () => {
    const sarif = toSarif([]);
    const json = sarifToJson(sarif);
    const parsed = JSON.parse(json);
    expect(parsed.version).toBe('2.1.0');
  });

  it('should handle malformed findings JSON gracefully', () => {
    const events = [
      {
        id: 1, timestamp: 1000, direction: 'request', method: null, tool_name: null,
        decision: 'block', score: 0.9, findings: 'not valid json', message: null,
      },
    ];

    const sarif = toSarif(events);
    expect(sarif.runs[0]!.results).toHaveLength(0);
  });
});

// ─── Extended SqliteAuditStore Tests ───

describe('SqliteAuditStore — extended', () => {
  let store: SqliteAuditStore;
  let dir: string;

  beforeEach(() => {
    ({ store, dir } = tempDb());
  });

  afterEach(() => {
    try { store.close(); } catch { /* may already be closed by test */ }
    rmSync(dir, { recursive: true, force: true });
  });

  it('should handle concurrent batch inserts (100 events)', () => {
    for (let i = 0; i < 100; i++) {
      store.insert({
        timestamp: i,
        direction: i % 2 === 0 ? 'request' : 'response',
        method: `method_${i}`,
        toolName: `tool_${i}`,
        decision: 'allow',
        score: 0,
        findings: '[]',
      });
    }

    expect(store.count()).toBe(100);
    const events = store.query({ limit: 100 });
    expect(events).toHaveLength(100);
  });

  it('should store large messages (10KB+ JSON)', () => {
    const largePayload = { data: 'x'.repeat(10_000), nested: { arr: Array(100).fill('test') } };
    const largeMessage = JSON.stringify(largePayload);

    store.insert({
      timestamp: 1000,
      direction: 'request',
      method: 'tools/call',
      decision: 'allow',
      score: 0,
      findings: '[]',
      message: largeMessage,
    });

    const events = store.query();
    expect(events).toHaveLength(1);
    expect(events[0]!.message).toBe(largeMessage);
    const parsed = JSON.parse(events[0]!.message!);
    expect(parsed.data.length).toBe(10_000);
  });

  it('should handle unicode characters in method and toolName', () => {
    store.insert({
      timestamp: 1000,
      direction: 'request',
      method: 'tools/call_\u{1F525}\u{1F680}',
      toolName: '\u{C548}\u{B155}_tool_\u{2603}',
      decision: 'allow',
      score: 0,
      findings: '[]',
    });

    const events = store.query();
    expect(events[0]!.method).toBe('tools/call_\u{1F525}\u{1F680}');
    expect(events[0]!.tool_name).toBe('\u{C548}\u{B155}_tool_\u{2603}');
  });

  it('should handle single quotes in method and toolName', () => {
    store.insert({
      timestamp: 1000,
      direction: 'request',
      method: "tools/call'test",
      toolName: "O'Brien's tool",
      decision: 'allow',
      score: 0,
      findings: '[]',
    });

    const events = store.query();
    expect(events[0]!.method).toBe("tools/call'test");
    expect(events[0]!.tool_name).toBe("O'Brien's tool");
  });

  it('should handle SQL-injection-like values in string fields', () => {
    const maliciousMethod = "'; DROP TABLE events; --";
    const maliciousToolName = "tool\" OR 1=1 --";

    store.insert({
      timestamp: 1000,
      direction: 'request',
      method: maliciousMethod,
      toolName: maliciousToolName,
      decision: 'allow',
      score: 0,
      findings: '[]',
    });

    // Table should still exist and the event should be stored verbatim
    const events = store.query();
    expect(events).toHaveLength(1);
    expect(events[0]!.method).toBe(maliciousMethod);
    expect(events[0]!.tool_name).toBe(maliciousToolName);
    expect(store.count()).toBe(1);
  });

  it('should store empty string for method and toolName (not null)', () => {
    store.insert({
      timestamp: 1000,
      direction: 'request',
      method: '',
      toolName: '',
      decision: 'allow',
      score: 0,
      findings: '[]',
    });

    const events = store.query();
    expect(events[0]!.method).toBe('');
    expect(events[0]!.tool_name).toBe('');
  });

  it('should store null when method and toolName are omitted', () => {
    store.insert({
      timestamp: 1000,
      direction: 'request',
      decision: 'allow',
      score: 0,
      findings: '[]',
    });

    const events = store.query();
    expect(events[0]!.method).toBeNull();
    expect(events[0]!.tool_name).toBeNull();
  });

  it('should return empty array when query matches no results', () => {
    store.insert({
      timestamp: 1000,
      direction: 'request',
      decision: 'allow',
      score: 0,
      findings: '[]',
    });

    const events = store.query({ decision: 'block', direction: 'response', minScore: 0.99 });
    expect(events).toEqual([]);
  });

  it('should handle query with all filters combined', () => {
    for (let i = 0; i < 20; i++) {
      store.insert({
        timestamp: 1000 + i * 100,
        direction: i % 2 === 0 ? 'request' : 'response',
        decision: i % 3 === 0 ? 'block' : i % 3 === 1 ? 'warn' : 'allow',
        score: i / 20,
        findings: '[]',
      });
    }

    const events = store.query({
      since: 1000,
      until: 2500,
      direction: 'request',
      minScore: 0.2,
      limit: 5,
      offset: 0,
    });

    // All returned events should match all filters
    for (const e of events) {
      expect(e.timestamp).toBeGreaterThanOrEqual(1000);
      expect(e.timestamp).toBeLessThanOrEqual(2500);
      expect(e.direction).toBe('request');
      expect(e.score).toBeGreaterThanOrEqual(0.2);
    }
    expect(events.length).toBeLessThanOrEqual(5);
  });

  it('should not throw on multiple close() calls', () => {
    store.close();
    // better-sqlite3 silently allows double close without throwing.
    // This is safe behavior, but SqliteAuditStore does not add its own guard
    // (e.g., a `closed` flag). If better-sqlite3 ever changes this behavior,
    // mcp-fence would need its own protection.
    expect(() => store.close()).not.toThrow();
  });

  it('should throw or fail gracefully on insert after close', () => {
    store.close();
    expect(() => store.insert({
      timestamp: 1000,
      direction: 'request',
      decision: 'allow',
      score: 0,
      findings: '[]',
    })).toThrow();
  });

  it('should use WAL journal mode', () => {
    // Access the underlying db to verify pragma
    const dbPath = join(dir, 'test.db');
    const checkDb = new Database(dbPath);
    const result = checkDb.pragma('journal_mode') as Array<{ journal_mode: string }>;
    expect(result[0]!.journal_mode).toBe('wal');
    checkDb.close();
  });

  it('should create database file on construction', () => {
    const dbPath = join(dir, 'test.db');
    expect(existsSync(dbPath)).toBe(true);
  });

  it('should handle schema idempotency (create store twice on same db file)', () => {
    const dbPath = join(dir, 'test.db');

    // Insert via first store
    store.insert({
      timestamp: 1000,
      direction: 'request',
      decision: 'allow',
      score: 0,
      findings: '[]',
    });
    store.close();

    // Open a second store on the same file — should not fail or lose data
    const store2 = new SqliteAuditStore(dbPath);
    expect(store2.count()).toBe(1);

    store2.insert({
      timestamp: 2000,
      direction: 'response',
      decision: 'block',
      score: 0.9,
      findings: '[]',
    });
    expect(store2.count()).toBe(2);
    store2.close();

    // Reassign store so afterEach cleanup doesn't fail
    store = new SqliteAuditStore(dbPath);
  });
});

// ─── Extended AuditLoggerImpl Tests ───

describe('AuditLoggerImpl — extended', () => {
  let store: SqliteAuditStore;
  let dir: string;
  let logger: AuditLoggerImpl;

  beforeEach(() => {
    ({ store, dir } = tempDb());
    logger = new AuditLoggerImpl(store);
  });

  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('should log notification messages (no id, no params)', async () => {
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    };

    const result: ScanResult = {
      decision: 'allow',
      findings: [],
      score: 0,
      direction: 'request',
      timestamp: Date.now(),
    };

    await logger.log(message, result);

    const events = store.query();
    expect(events).toHaveLength(1);
    expect(events[0]!.method).toBe('notifications/initialized');
    expect(events[0]!.tool_name).toBeNull();
  });

  it('should log error responses', async () => {
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 42,
      error: { code: -32600, message: 'Invalid request' },
    };

    const result: ScanResult = {
      decision: 'allow',
      findings: [],
      score: 0,
      direction: 'response',
      timestamp: Date.now(),
    };

    await logger.log(message, result);

    const events = store.query();
    expect(events).toHaveLength(1);
    expect(events[0]!.direction).toBe('response');
    // Error response has no method
    expect(events[0]!.method).toBeNull();
    // Full message JSON should contain the error
    const storedMsg = JSON.parse(events[0]!.message!);
    expect(storedMsg.error.code).toBe(-32600);
  });

  it('should log tools/call with nested params and extract tool name', async () => {
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: {
        name: 'execute_command',
        arguments: {
          command: 'ls',
          args: ['-la', '/tmp'],
          options: { cwd: '/home', env: { PATH: '/usr/bin' } },
        },
      },
    };

    const result: ScanResult = {
      decision: 'warn',
      findings: [
        { ruleId: 'CMD-001', message: 'Command execution', severity: 'high', category: 'command-injection', confidence: 0.8 },
      ],
      score: 0.7,
      direction: 'request',
      timestamp: Date.now(),
    };

    await logger.log(message, result);

    const events = store.query();
    expect(events[0]!.method).toBe('tools/call');
    expect(events[0]!.tool_name).toBe('execute_command');
    // Nested params should be preserved in stored message
    const storedMsg = JSON.parse(events[0]!.message!);
    expect(storedMsg.params.arguments.options.cwd).toBe('/home');
  });

  it('should log tools/list response', async () => {
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 3,
      result: {
        tools: [
          { name: 'read_file', description: 'Read a file' },
          { name: 'write_file', description: 'Write a file' },
        ],
      },
    };

    const result: ScanResult = {
      decision: 'allow',
      findings: [],
      score: 0,
      direction: 'response',
      timestamp: Date.now(),
    };

    await logger.log(message, result);

    const events = store.query();
    expect(events).toHaveLength(1);
    const storedMsg = JSON.parse(events[0]!.message!);
    expect(storedMsg.result.tools).toHaveLength(2);
    expect(storedMsg.result.tools[0].name).toBe('read_file');
  });

  it('should store full message JSON and allow retrieval', async () => {
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 99,
      method: 'tools/call',
      params: { name: 'test_tool', arguments: { key: 'value', num: 42, bool: true, arr: [1, 2, 3] } },
    };

    const result: ScanResult = {
      decision: 'allow',
      findings: [],
      score: 0,
      direction: 'request',
      timestamp: 1234567890,
    };

    await logger.log(message, result);

    const events = store.query();
    const storedMsg = JSON.parse(events[0]!.message!);
    expect(storedMsg).toEqual(message);
  });

  it('should roundtrip complex findings with metadata', async () => {
    const findings: Finding[] = [
      {
        ruleId: 'INJ-001',
        message: 'Prompt injection detected',
        severity: 'critical',
        category: 'injection',
        confidence: 0.95,
        metadata: {
          pattern: 'ignore previous instructions',
          offset: 42,
          context: 'deeply nested "quotes" and \'escapes\'',
          tags: ['ai-security', 'prompt-injection'],
        },
      },
      {
        ruleId: 'SEC-003',
        message: 'AWS key in output',
        severity: 'high',
        category: 'secret',
        confidence: 0.99,
        metadata: {
          redacted: 'AKIA***',
          positions: [{ start: 10, end: 30 }],
        },
      },
    ];

    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'test' },
    };

    const result: ScanResult = {
      decision: 'block',
      findings,
      score: 0.97,
      direction: 'request',
      timestamp: Date.now(),
    };

    await logger.log(message, result);

    const events = store.query();
    const parsedFindings = JSON.parse(events[0]!.findings) as Finding[];
    expect(parsedFindings).toEqual(findings);
    expect(parsedFindings[0]!.metadata!['tags']).toEqual(['ai-security', 'prompt-injection']);
    expect(parsedFindings[1]!.metadata!['positions']).toEqual([{ start: 10, end: 30 }]);
  });

  it('should handle high-frequency logging (100 events rapidly)', async () => {
    const promises: Promise<void>[] = [];

    for (let i = 0; i < 100; i++) {
      const message: JsonRpcMessage = {
        jsonrpc: '2.0',
        id: i,
        method: 'tools/call',
        params: { name: `tool_${i}` },
      };

      const result: ScanResult = {
        decision: 'allow',
        findings: [],
        score: 0,
        direction: 'request',
        timestamp: Date.now(),
      };

      promises.push(logger.log(message, result));
    }

    await Promise.all(promises);
    expect(store.count()).toBe(100);
  });
});

// ─── Extended SARIF Output Tests ───

describe('SARIF output — extended', () => {
  it('should produce multiple SARIF results from a single event with multiple findings', () => {
    const findings: Finding[] = [
      { ruleId: 'INJ-001', message: 'Injection A', severity: 'critical', category: 'injection', confidence: 0.9 },
      { ruleId: 'SEC-001', message: 'Secret leak', severity: 'high', category: 'secret', confidence: 0.95 },
      { ruleId: 'CMD-001', message: 'Command injection', severity: 'medium', category: 'command-injection', confidence: 0.7 },
    ];

    const events = [{
      id: 1, timestamp: 1000, direction: 'request', method: 'tools/call', tool_name: 'exec',
      decision: 'block', score: 0.95, findings: JSON.stringify(findings), message: null,
    }];

    const sarif = toSarif(events);
    expect(sarif.runs[0]!.results).toHaveLength(3);
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(3);
  });

  it('should deduplicate rules when same ruleId appears across events', () => {
    const events = [
      {
        id: 1, timestamp: 1000, direction: 'request', method: 'tools/call', tool_name: 'a',
        decision: 'block', score: 0.9,
        findings: JSON.stringify([
          { ruleId: 'INJ-001', message: 'Injection', severity: 'critical', category: 'injection', confidence: 0.9 },
        ]),
        message: null,
      },
      {
        id: 2, timestamp: 2000, direction: 'request', method: 'tools/call', tool_name: 'b',
        decision: 'block', score: 0.85,
        findings: JSON.stringify([
          { ruleId: 'INJ-001', message: 'Injection', severity: 'critical', category: 'injection', confidence: 0.88 },
        ]),
        message: null,
      },
    ];

    const sarif = toSarif(events);
    // Two results but only one rule definition
    expect(sarif.runs[0]!.results).toHaveLength(2);
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0]!.tool.driver.rules[0]!.id).toBe('INJ-001');
  });

  it('should map all severity levels including info', () => {
    const findings = [
      { ruleId: 'A', message: 'critical', severity: 'critical', category: 'injection', confidence: 1 },
      { ruleId: 'B', message: 'high', severity: 'high', category: 'injection', confidence: 1 },
      { ruleId: 'C', message: 'medium', severity: 'medium', category: 'injection', confidence: 1 },
      { ruleId: 'D', message: 'low', severity: 'low', category: 'injection', confidence: 1 },
      { ruleId: 'E', message: 'info', severity: 'info', category: 'injection', confidence: 1 },
    ];

    const events = [{
      id: 1, timestamp: 1000, direction: 'request', method: null, tool_name: null,
      decision: 'warn', score: 0.5, findings: JSON.stringify(findings), message: null,
    }];

    const sarif = toSarif(events);
    const levels = sarif.runs[0]!.results.map((r) => r.level);
    expect(levels).toEqual(['error', 'error', 'warning', 'note', 'note']);
  });

  it('should handle warn decision with empty findings array', () => {
    const events = [{
      id: 1, timestamp: 1000, direction: 'request', method: 'tools/call', tool_name: 'test',
      decision: 'warn', score: 0.5, findings: '[]', message: null,
    }];

    const sarif = toSarif(events);
    // warn decision but no findings means no SARIF results
    expect(sarif.runs[0]!.results).toHaveLength(0);
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(0);
  });

  it('should handle very long messages in SARIF output', () => {
    const longMessage = 'A'.repeat(50_000);
    const findings = [
      { ruleId: 'INJ-001', message: longMessage, severity: 'critical', category: 'injection', confidence: 0.9 },
    ];

    const events = [{
      id: 1, timestamp: 1000, direction: 'request', method: 'tools/call', tool_name: 'test',
      decision: 'block', score: 0.95, findings: JSON.stringify(findings), message: null,
    }];

    const sarif = toSarif(events);
    expect(sarif.runs[0]!.results).toHaveLength(1);
    expect(sarif.runs[0]!.results[0]!.message.text).toContain(longMessage);

    // Should still produce valid JSON
    const json = sarifToJson(sarif);
    const parsed = JSON.parse(json);
    expect(parsed.version).toBe('2.1.0');
  });

  it('should produce valid SARIF with 0 events (empty runs)', () => {
    const sarif = toSarif([]);

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]!.results).toHaveLength(0);
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(0);
    expect(sarif.runs[0]!.tool.driver.name).toBe('mcp-fence');
  });

  it('should verify SARIF JSON is valid and parseable with complete structure', () => {
    const events = [{
      id: 1, timestamp: 1710000000000, direction: 'response', method: 'tools/call', tool_name: 'read_file',
      decision: 'block', score: 0.92,
      findings: JSON.stringify([
        { ruleId: 'SEC-002', message: 'Private key in output', severity: 'critical', category: 'secret', confidence: 0.98 },
      ]),
      message: null,
    }];

    const sarif = toSarif(events);
    const json = sarifToJson(sarif);
    const parsed = JSON.parse(json);

    // Structural validation
    expect(parsed).toHaveProperty('version');
    expect(parsed).toHaveProperty('$schema');
    expect(parsed).toHaveProperty('runs');
    expect(Array.isArray(parsed.runs)).toBe(true);
    expect(parsed.runs[0]).toHaveProperty('tool');
    expect(parsed.runs[0]).toHaveProperty('results');
    expect(parsed.runs[0].tool).toHaveProperty('driver');
    expect(parsed.runs[0].tool.driver).toHaveProperty('name');
    expect(parsed.runs[0].tool.driver).toHaveProperty('version');
    expect(parsed.runs[0].tool.driver).toHaveProperty('informationUri');
    expect(parsed.runs[0].tool.driver).toHaveProperty('rules');
  });

  it('should include all expected fields in properties', () => {
    const events = [{
      id: 1, timestamp: 1710000000000, direction: 'request', method: 'tools/call', tool_name: 'exec_cmd',
      decision: 'block', score: 0.95,
      findings: JSON.stringify([
        { ruleId: 'CMD-001', message: 'Dangerous command', severity: 'critical', category: 'command-injection', confidence: 0.93 },
      ]),
      message: null,
    }];

    const sarif = toSarif(events);
    const properties = sarif.runs[0]!.results[0]!.properties;

    expect(properties).toHaveProperty('direction', 'request');
    expect(properties).toHaveProperty('method', 'tools/call');
    expect(properties).toHaveProperty('toolName', 'exec_cmd');
    expect(properties).toHaveProperty('decision', 'block');
    expect(properties).toHaveProperty('score', 0.95);
    expect(properties).toHaveProperty('confidence', 0.93);
    expect(properties).toHaveProperty('category', 'command-injection');
    expect(properties).toHaveProperty('timestamp');
    // Timestamp should be valid ISO string
    expect(new Date(properties['timestamp'] as string).getTime()).toBe(1710000000000);
  });

  it('should handle events with null tool_name and null method in properties', () => {
    const events = [{
      id: 1, timestamp: 1000, direction: 'response', method: null, tool_name: null,
      decision: 'warn', score: 0.6,
      findings: JSON.stringify([
        { ruleId: 'SEC-001', message: 'Secret detected', severity: 'high', category: 'secret', confidence: 0.9 },
      ]),
      message: null,
    }];

    const sarif = toSarif(events);
    const result = sarif.runs[0]!.results[0]!;

    expect(result.properties['method']).toBeNull();
    expect(result.properties['toolName']).toBeNull();
    // Message text should not contain "(tool: null)" or "[null]"
    expect(result.message.text).not.toContain('null');
    expect(result.message.text).toBe('[RESPONSE] Secret detected');
  });
});

// ─── CLI parseDuration and printTable Tests ───

describe('CLI helpers — parseDuration', () => {
  // parseDuration is not exported, so we test it indirectly through behavior.
  // We replicate the logic here for unit testing since it's a private function.
  function parseDurationLocal(duration: string): number {
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error(`Invalid duration format: ${duration}`);
    }

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

  it('should parse "1h" as ~1 hour ago', () => {
    const before = Date.now() - 60 * 60 * 1000;
    const result = parseDurationLocal('1h');
    const after = Date.now() - 60 * 60 * 1000;
    // Result should be between before and after (accounting for execution time)
    expect(result).toBeGreaterThanOrEqual(before - 10);
    expect(result).toBeLessThanOrEqual(after + 10);
  });

  it('should parse "30m" as ~30 minutes ago', () => {
    const expected = Date.now() - 30 * 60 * 1000;
    const result = parseDurationLocal('30m');
    expect(Math.abs(result - expected)).toBeLessThan(100);
  });

  it('should parse "1d" as ~1 day ago', () => {
    const expected = Date.now() - 24 * 60 * 60 * 1000;
    const result = parseDurationLocal('1d');
    expect(Math.abs(result - expected)).toBeLessThan(100);
  });

  it('should parse "10s" as ~10 seconds ago', () => {
    const expected = Date.now() - 10 * 1000;
    const result = parseDurationLocal('10s');
    expect(Math.abs(result - expected)).toBeLessThan(100);
  });

  it('should parse "0h" as current time (0 hours ago)', () => {
    const result = parseDurationLocal('0h');
    expect(Math.abs(result - Date.now())).toBeLessThan(100);
  });

  it('should parse "999d" as ~999 days ago', () => {
    const expected = Date.now() - 999 * 24 * 60 * 60 * 1000;
    const result = parseDurationLocal('999d');
    expect(Math.abs(result - expected)).toBeLessThan(100);
  });

  it('should throw on invalid format', () => {
    expect(() => parseDurationLocal('1x')).toThrow();
    expect(() => parseDurationLocal('abc')).toThrow();
    expect(() => parseDurationLocal('')).toThrow();
    expect(() => parseDurationLocal('1.5h')).toThrow();
  });
});

describe('CLI helpers — printTable', () => {
  // Replicate printTable logic to test output formatting
  function printTableLocal(events: Array<{
    timestamp: number;
    direction: string;
    method: string | null;
    tool_name: string | null;
    decision: string;
    score: number;
  }>): string {
    const lines: string[] = [];

    if (events.length === 0) {
      return 'No events found.\n';
    }

    const header = `${'Timestamp'.padEnd(24)} ${'Direction'.padEnd(10)} ${'Method'.padEnd(20)} ${'Decision'.padEnd(10)} ${'Score'.padEnd(7)} Tool`;
    lines.push(header);
    lines.push('\u2500'.repeat(header.length));

    for (const e of events) {
      const ts = new Date(e.timestamp).toISOString().replace('T', ' ').slice(0, 23);
      const dir = (e.direction ?? '').padEnd(10);
      const method = (e.method ?? '-').padEnd(20);
      const decision = (e.decision ?? '').padEnd(10);
      const score = e.score.toFixed(2).padEnd(7);
      const tool = e.tool_name ?? '-';
      lines.push(`${ts} ${dir} ${method} ${decision} ${score} ${tool}`);
    }

    lines.push('');
    lines.push(`${events.length} event(s)`);
    return lines.join('\n') + '\n';
  }

  it('should print "No events found." for empty array', () => {
    const output = printTableLocal([]);
    expect(output).toBe('No events found.\n');
  });

  it('should format a single event with all fields', () => {
    const output = printTableLocal([{
      timestamp: 1710000000000,
      direction: 'request',
      method: 'tools/call',
      tool_name: 'read_file',
      decision: 'block',
      score: 0.95,
    }]);

    expect(output).toContain('Timestamp');
    expect(output).toContain('Direction');
    expect(output).toContain('request');
    expect(output).toContain('tools/call');
    expect(output).toContain('read_file');
    expect(output).toContain('block');
    expect(output).toContain('0.95');
    expect(output).toContain('1 event(s)');
  });

  it('should show "-" for null method and tool_name', () => {
    const output = printTableLocal([{
      timestamp: 1000,
      direction: 'response',
      method: null,
      tool_name: null,
      decision: 'allow',
      score: 0,
    }]);

    // method and tool columns should show "-"
    const lines = output.split('\n');
    const dataLine = lines[2]!; // header, separator, first data line
    // Count dashes in the appropriate columns
    expect(dataLine).toContain('-');
  });

  it('should format multiple events and show correct count', () => {
    const events = [
      { timestamp: 1000, direction: 'request', method: 'a', tool_name: 'b', decision: 'allow', score: 0 },
      { timestamp: 2000, direction: 'response', method: 'c', tool_name: null, decision: 'warn', score: 0.5 },
      { timestamp: 3000, direction: 'request', method: null, tool_name: 'd', decision: 'block', score: 0.9 },
    ];

    const output = printTableLocal(events);
    expect(output).toContain('3 event(s)');
  });

  it('should handle score of exactly 0.00', () => {
    const output = printTableLocal([{
      timestamp: 1000,
      direction: 'request',
      method: 'test',
      tool_name: null,
      decision: 'allow',
      score: 0,
    }]);

    expect(output).toContain('0.00');
  });
});

// ─── HMAC Hash Chain Tests ───

describe('HMAC hash chain', () => {
  let store: SqliteAuditStore;
  let dir: string;
  let hmacKey: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-fence-hmac-test-'));
    hmacKey = getOrCreateHmacKey(dir);
    store = new SqliteAuditStore(join(dir, 'test.db'), { hmacKey });
  });

  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('should create and verify a valid chain of 5 events', () => {
    for (let i = 0; i < 5; i++) {
      store.insert({
        timestamp: 1000 + i * 100,
        direction: 'request',
        decision: i % 2 === 0 ? 'allow' : 'warn',
        score: i * 0.1,
        findings: '[]',
        message: `msg-${i}`,
      });
    }

    const result = store.verifyChain(hmacKey);
    expect(result.valid).toBe(true);
    expect(result.brokenAt).toBeUndefined();
  });

  it('should detect tampering with a single event', () => {
    for (let i = 0; i < 5; i++) {
      store.insert({
        timestamp: 1000 + i * 100,
        direction: 'request',
        decision: 'allow',
        score: 0,
        findings: '[]',
      });
    }

    // Tamper with the third event's findings
    const dbPath = join(dir, 'test.db');
    const rawDb = new Database(dbPath);
    rawDb.prepare("UPDATE events SET findings = '[{\"tampered\":true}]' WHERE id = 3").run();
    rawDb.close();

    const result = store.verifyChain(hmacKey);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(3);
  });

  it('should detect chain break when prev_hmac is altered', () => {
    for (let i = 0; i < 3; i++) {
      store.insert({
        timestamp: 1000 + i,
        direction: 'request',
        decision: 'allow',
        score: 0,
        findings: '[]',
      });
    }

    const dbPath = join(dir, 'test.db');
    const rawDb = new Database(dbPath);
    rawDb.prepare("UPDATE events SET prev_hmac = 'forged' WHERE id = 2").run();
    rawDb.close();

    const result = store.verifyChain(hmacKey);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(2);
  });

  it('should return valid for empty database', () => {
    const result = store.verifyChain(hmacKey);
    expect(result.valid).toBe(true);
  });

  it('should store hmac and prev_hmac columns', () => {
    store.insert({
      timestamp: 1000,
      direction: 'request',
      decision: 'allow',
      score: 0,
      findings: '[]',
    });

    const events = store.query();
    expect(events[0]!.hmac).toBeTruthy();
    expect(events[0]!.prev_hmac).toBe('genesis');
  });

  it('should chain prev_hmac to previous hmac', () => {
    store.insert({ timestamp: 1000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });
    store.insert({ timestamp: 2000, direction: 'request', decision: 'allow', score: 0, findings: '[]' });

    // Query in ASC order via raw DB
    const dbPath = join(dir, 'test.db');
    const rawDb = new Database(dbPath);
    const rows = rawDb.prepare('SELECT hmac, prev_hmac FROM events ORDER BY id ASC').all() as Array<{ hmac: string; prev_hmac: string }>;
    rawDb.close();

    expect(rows[0]!.prev_hmac).toBe('genesis');
    expect(rows[1]!.prev_hmac).toBe(rows[0]!.hmac);
  });
});

// ─── HMAC Key Management Tests ───

describe('getOrCreateHmacKey', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-fence-key-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('should create a key file on first call', () => {
    const key = getOrCreateHmacKey(dir);
    expect(key).toHaveLength(64); // 32 bytes in hex
    expect(existsSync(join(dir, 'hmac.key'))).toBe(true);
  });

  it('should return the same key on subsequent calls', () => {
    const key1 = getOrCreateHmacKey(dir);
    const key2 = getOrCreateHmacKey(dir);
    expect(key1).toBe(key2);
  });

  it('should create nested directories if needed', () => {
    const nested = join(dir, 'nested', 'path');
    const key = getOrCreateHmacKey(nested);
    expect(key).toHaveLength(64);
  });
});

// ─── DB Size Limit Tests ───

describe('DB size limit and pruning', () => {
  let store: SqliteAuditStore;
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-fence-prune-test-'));
    dbPath = join(dir, 'test.db');
  });

  afterEach(() => {
    try { store.close(); } catch { /* may already be closed */ }
    rmSync(dir, { recursive: true, force: true });
  });

  it('should prune when DB exceeds size limit', () => {
    // Set a very small size limit to trigger pruning
    store = new SqliteAuditStore(dbPath, { maxDbSizeMb: 0.01 }); // ~10KB limit

    // Insert enough data to exceed the tiny limit
    const bigFindings = JSON.stringify([{
      ruleId: 'TEST',
      message: 'x'.repeat(500),
      severity: 'low',
      category: 'injection',
      confidence: 0.5,
    }]);

    // Insert 200 events (prune check happens every 100)
    for (let i = 0; i < 200; i++) {
      store.insert({
        timestamp: 1000 + i,
        direction: 'request',
        decision: 'allow',
        score: 0,
        findings: bigFindings,
        message: 'x'.repeat(200),
      });
    }

    // After pruning, count should be less than 200
    const count = store.count();
    expect(count).toBeLessThan(200);
    expect(count).toBeGreaterThan(0);
  });

  it('should not prune when under size limit', () => {
    store = new SqliteAuditStore(dbPath, { maxDbSizeMb: 100 });

    for (let i = 0; i < 200; i++) {
      store.insert({
        timestamp: 1000 + i,
        direction: 'request',
        decision: 'allow',
        score: 0,
        findings: '[]',
      });
    }

    expect(store.count()).toBe(200);
  });
});
