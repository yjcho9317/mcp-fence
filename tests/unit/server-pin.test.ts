import { describe, it, expect, beforeEach } from 'vitest';
import { HashPinChecker } from '../../src/integrity/hash-pin.js';
import { MemoryHashStore } from '../../src/integrity/store.js';
import type { JsonRpcMessage } from '../../src/types.js';

interface ToolDef {
  name: string;
  description: string;
  inputSchema?: Record<string, unknown>;
}

function toolsListResponse(tools: ToolDef[]): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: 1,
    result: { tools },
  };
}

describe('Server schema pinning — TOFU', () => {
  let store: MemoryHashStore;
  let checker: HashPinChecker;

  beforeEach(() => {
    store = new MemoryHashStore();
    checker = new HashPinChecker(store);
  });

  it('should pin server schema on first tools/list response', () => {
    const msg = toolsListResponse([
      { name: 'read_file', description: 'Reads a file', inputSchema: { type: 'object' } },
      { name: 'write_file', description: 'Writes a file', inputSchema: { type: 'object' } },
    ]);

    const findings = checker.checkServerSchema(msg);
    expect(findings).toHaveLength(0);

    const pin = checker.getServerPin();
    expect(pin).not.toBeNull();
    expect(pin!.toolNames).toEqual(['read_file', 'write_file']);
    expect(pin!.schemaHash).toBeTruthy();
  });

  it('should not alert on identical schema', () => {
    const msg = toolsListResponse([
      { name: 'tool_a', description: 'Does A', inputSchema: { type: 'object' } },
      { name: 'tool_b', description: 'Does B', inputSchema: { type: 'string' } },
    ]);

    checker.checkServerSchema(msg); // Pin
    const findings = checker.checkServerSchema(msg); // Same schema
    expect(findings).toHaveLength(0);
  });

  it('should detect a tool being added (SRV-001 + SRV-002)', () => {
    const original = toolsListResponse([
      { name: 'tool_a', description: 'Does A' },
    ]);
    checker.checkServerSchema(original);

    const modified = toolsListResponse([
      { name: 'tool_a', description: 'Does A' },
      { name: 'tool_b', description: 'Does B' },
    ]);
    const findings = checker.checkServerSchema(modified);

    const ruleIds = findings.map((f) => f.ruleId).sort();
    expect(ruleIds).toContain('SRV-001');
    expect(ruleIds).toContain('SRV-002');

    const srv002 = findings.find((f) => f.ruleId === 'SRV-002')!;
    expect(srv002.metadata?.['toolName']).toBe('tool_b');
    expect(srv002.severity).toBe('high');
    expect(srv002.category).toBe('rug-pull');
  });

  it('should detect a tool being removed (SRV-001 + SRV-003)', () => {
    const original = toolsListResponse([
      { name: 'tool_a', description: 'Does A' },
      { name: 'tool_b', description: 'Does B' },
    ]);
    checker.checkServerSchema(original);

    const modified = toolsListResponse([
      { name: 'tool_a', description: 'Does A' },
    ]);
    const findings = checker.checkServerSchema(modified);

    const ruleIds = findings.map((f) => f.ruleId).sort();
    expect(ruleIds).toContain('SRV-001');
    expect(ruleIds).toContain('SRV-003');

    const srv003 = findings.find((f) => f.ruleId === 'SRV-003')!;
    expect(srv003.metadata?.['toolName']).toBe('tool_b');
  });

  it('should detect inputSchema change (SRV-001)', () => {
    const original = toolsListResponse([
      {
        name: 'tool_a',
        description: 'Does A',
        inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
      },
    ]);
    checker.checkServerSchema(original);

    const modified = toolsListResponse([
      {
        name: 'tool_a',
        description: 'Does A',
        inputSchema: { type: 'object', properties: { path: { type: 'string' }, url: { type: 'string' } } },
      },
    ]);
    const findings = checker.checkServerSchema(modified);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('SRV-001');
    expect(findings[0]!.message).toContain('description or inputSchema');
  });

  it('should detect description change via server schema (SRV-001)', () => {
    const original = toolsListResponse([
      { name: 'tool_a', description: 'Original description' },
    ]);
    checker.checkServerSchema(original);

    const modified = toolsListResponse([
      { name: 'tool_a', description: 'Changed description with exfiltration' },
    ]);
    const findings = checker.checkServerSchema(modified);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('SRV-001');
  });

  it('should fire both SRV-001 and RUG-001 for description change when both checks run', () => {
    const original = toolsListResponse([
      { name: 'tool_a', description: 'Safe tool' },
    ]);
    // Run both checks for pinning
    checker.check(original);
    checker.checkServerSchema(original);

    const modified = toolsListResponse([
      { name: 'tool_a', description: 'Malicious tool that steals data' },
    ]);
    const rugFindings = checker.check(modified);
    const serverFindings = checker.checkServerSchema(modified);

    expect(rugFindings.some((f) => f.ruleId === 'RUG-001')).toBe(true);
    expect(serverFindings.some((f) => f.ruleId === 'SRV-001')).toBe(true);
  });

  it('should produce the same hash regardless of tool order', () => {
    const msgAB = toolsListResponse([
      { name: 'tool_a', description: 'Does A', inputSchema: { type: 'object' } },
      { name: 'tool_b', description: 'Does B', inputSchema: { type: 'string' } },
    ]);

    const msgBA = toolsListResponse([
      { name: 'tool_b', description: 'Does B', inputSchema: { type: 'string' } },
      { name: 'tool_a', description: 'Does A', inputSchema: { type: 'object' } },
    ]);

    checker.checkServerSchema(msgAB); // Pin with A,B order
    const findings = checker.checkServerSchema(msgBA); // Check with B,A order
    expect(findings).toHaveLength(0); // Same schema, different order
  });

  it('should ignore non-tools/list messages', () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { content: [{ type: 'text', text: 'hello' }] },
    };
    const findings = checker.checkServerSchema(msg);
    expect(findings).toHaveLength(0);
    expect(checker.getServerPin()).toBeNull();
  });

  it('should update the server pin after detecting a change', () => {
    const original = toolsListResponse([
      { name: 'tool_a', description: 'Does A' },
    ]);
    checker.checkServerSchema(original);
    const firstPin = checker.getServerPin()!;

    const modified = toolsListResponse([
      { name: 'tool_a', description: 'Does A' },
      { name: 'tool_b', description: 'Does B' },
    ]);
    checker.checkServerSchema(modified);
    const secondPin = checker.getServerPin()!;

    expect(secondPin.schemaHash).not.toBe(firstPin.schemaHash);
    expect(secondPin.toolNames).toEqual(['tool_a', 'tool_b']);
  });

  it('should not re-alert on same changed schema after update', () => {
    const original = toolsListResponse([{ name: 'tool_a', description: 'A' }]);
    checker.checkServerSchema(original);

    const changed = toolsListResponse([{ name: 'tool_b', description: 'B' }]);
    const first = checker.checkServerSchema(changed);
    expect(first.length).toBeGreaterThan(0);

    // Same changed schema again should not fire
    const second = checker.checkServerSchema(changed);
    expect(second).toHaveLength(0);
  });
});

describe('MemoryHashStore — server pin', () => {
  let store: MemoryHashStore;

  beforeEach(() => {
    store = new MemoryHashStore();
  });

  it('should return null when no server pin set', () => {
    expect(store.getServerPin()).toBeNull();
  });

  it('should store and return server pin', () => {
    const pin = { schemaHash: 'abc123', toolNames: ['tool_a'], pinnedAt: 1000 };
    const ok = store.setServerPin(pin);
    expect(ok).toBe(true);
    expect(store.getServerPin()).toEqual(pin);
  });

  it('should return true when setting same hash again', () => {
    const pin = { schemaHash: 'abc123', toolNames: ['tool_a'], pinnedAt: 1000 };
    store.setServerPin(pin);
    const ok = store.setServerPin(pin);
    expect(ok).toBe(true);
  });

  it('should return false when hash changes', () => {
    store.setServerPin({ schemaHash: 'abc123', toolNames: ['tool_a'], pinnedAt: 1000 });
    const ok = store.setServerPin({ schemaHash: 'different', toolNames: ['tool_a', 'tool_b'], pinnedAt: 2000 });
    expect(ok).toBe(false);
  });

  it('should clear server pin along with tool pins', () => {
    store.setServerPin({ schemaHash: 'abc123', toolNames: ['tool_a'], pinnedAt: 1000 });
    store.pin('tool_a', 'hash_a', 'desc a');
    store.clear();
    expect(store.getServerPin()).toBeNull();
    expect(store.has('tool_a')).toBe(false);
  });
});
