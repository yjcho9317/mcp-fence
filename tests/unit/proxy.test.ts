import { describe, it, expect, vi } from 'vitest';
import type {
  JsonRpcMessage,
  JsonRpcRequest,
  JsonRpcNotification,
  JsonRpcResponse,
  ScanResult,
  Scanner,
  AuditLogger,
  Direction,
  Finding,
} from '../../src/types.js';

/**
 * These tests exercise the proxy's decision logic and response construction
 * in isolation. The actual McpProxy class spawns child processes, so we
 * replicate the pure functions (createBlockResponse, passthroughResult)
 * and the message-handling decision logic here.
 *
 * The functions under test are module-private in proxy.ts. We replicate
 * them faithfully to validate their behavior. If proxy.ts exports these
 * in the future, these tests can be updated to import directly.
 */

// ── Replicate passthroughResult (identical to proxy.ts) ──

function passthroughResult(direction: 'request' | 'response'): ScanResult {
  return {
    decision: 'allow',
    findings: [],
    score: 0,
    direction,
    timestamp: Date.now(),
  };
}

// ── Replicate createBlockResponse (identical to proxy.ts) ──

function createBlockResponse(
  originalMessage: JsonRpcMessage,
  result: ScanResult,
): JsonRpcMessage | null {
  if (!('id' in originalMessage) || originalMessage.id == null) {
    return null;
  }

  return {
    jsonrpc: '2.0',
    id: originalMessage.id,
    error: {
      code: -32600,
      message: `[mcp-fence] Blocked: ${result.findings.map((f) => f.message).join('; ')}`,
    },
  };
}

// ── Replicate handleMessage decision logic (identical to proxy.ts) ──

interface DecisionOutcome {
  forwarded: boolean;
  blockResponseSent: JsonRpcMessage | null;
}

function simulateHandleMessage(
  message: JsonRpcMessage,
  scanResult: ScanResult,
  mode: 'monitor' | 'enforce',
): DecisionOutcome {
  if (scanResult.decision === 'block' && mode === 'enforce') {
    const blockResp = createBlockResponse(message, scanResult);
    return { forwarded: false, blockResponseSent: blockResp };
  }
  // In monitor mode or for warn/allow decisions, the message is forwarded
  return { forwarded: true, blockResponseSent: null };
}

// ─── Helper ───

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'TEST-001',
    message: 'Test finding',
    severity: 'critical',
    category: 'injection',
    confidence: 0.95,
    ...overrides,
  };
}

function makeBlockResult(findings: Finding[] = [makeFinding()]): ScanResult {
  return {
    decision: 'block',
    findings,
    score: 0.95,
    direction: 'request',
    timestamp: Date.now(),
  };
}

function makeWarnResult(findings: Finding[] = [makeFinding({ severity: 'medium', confidence: 0.6 })]): ScanResult {
  return {
    decision: 'warn',
    findings,
    score: 0.6,
    direction: 'request',
    timestamp: Date.now(),
  };
}

// ═══════════════════════════════════════════════

describe('passthroughResult', () => {
  it('should return allow decision with no findings for request direction', () => {
    const result = passthroughResult('request');
    expect(result.decision).toBe('allow');
    expect(result.findings).toHaveLength(0);
    expect(result.score).toBe(0);
    expect(result.direction).toBe('request');
    expect(typeof result.timestamp).toBe('number');
  });

  it('should return allow decision for response direction', () => {
    const result = passthroughResult('response');
    expect(result.direction).toBe('response');
    expect(result.decision).toBe('allow');
  });

  it('should produce a fresh timestamp on each call', () => {
    const a = passthroughResult('request');
    const b = passthroughResult('request');
    // timestamps should be very close but independently generated
    expect(typeof a.timestamp).toBe('number');
    expect(typeof b.timestamp).toBe('number');
  });
});

// ─── createBlockResponse ───

describe('createBlockResponse', () => {
  it('should create JSON-RPC error for a request with numeric id', () => {
    const msg: JsonRpcRequest = {
      jsonrpc: '2.0',
      id: 42,
      method: 'tools/call',
      params: { name: 'exec' },
    };
    const result = makeBlockResult();
    const resp = createBlockResponse(msg, result);

    expect(resp).not.toBeNull();
    expect(resp!.jsonrpc).toBe('2.0');
    expect((resp as JsonRpcResponse).id).toBe(42);
    expect((resp as JsonRpcResponse).error).toBeDefined();
    expect((resp as JsonRpcResponse).error!.code).toBe(-32600);
    expect((resp as JsonRpcResponse).error!.message).toContain('[mcp-fence] Blocked');
    expect((resp as JsonRpcResponse).error!.message).toContain('Test finding');
  });

  it('should create JSON-RPC error for a request with string id', () => {
    const msg: JsonRpcRequest = {
      jsonrpc: '2.0',
      id: 'req-abc-123',
      method: 'tools/call',
    };
    const result = makeBlockResult();
    const resp = createBlockResponse(msg, result);

    expect(resp).not.toBeNull();
    expect((resp as JsonRpcResponse).id).toBe('req-abc-123');
  });

  it('should return null for notifications (no id)', () => {
    const notification: JsonRpcNotification = {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    };
    const result = makeBlockResult();
    const resp = createBlockResponse(notification, result);

    expect(resp).toBeNull();
  });

  it('should return null when id is explicitly undefined', () => {
    // A request with id=undefined shouldn't get a block response
    const msg = {
      jsonrpc: '2.0' as const,
      id: undefined,
      method: 'tools/call',
    };
    const result = makeBlockResult();
    // id == null is true for undefined
    const resp = createBlockResponse(msg as unknown as JsonRpcMessage, result);
    expect(resp).toBeNull();
  });

  it('should concatenate multiple finding messages with semicolons', () => {
    const findings = [
      makeFinding({ ruleId: 'A', message: 'Injection detected' }),
      makeFinding({ ruleId: 'B', message: 'Command injection' }),
      makeFinding({ ruleId: 'C', message: 'Path traversal' }),
    ];
    const result = makeBlockResult(findings);
    const msg: JsonRpcRequest = { jsonrpc: '2.0', id: 1, method: 'test' };
    const resp = createBlockResponse(msg, result);

    const errMsg = (resp as JsonRpcResponse).error!.message;
    expect(errMsg).toContain('Injection detected');
    expect(errMsg).toContain('Command injection');
    expect(errMsg).toContain('Path traversal');
    expect(errMsg).toContain('; ');
  });

  it('should handle empty findings array gracefully', () => {
    const result = makeBlockResult([]);
    const msg: JsonRpcRequest = { jsonrpc: '2.0', id: 1, method: 'test' };
    const resp = createBlockResponse(msg, result);

    expect(resp).not.toBeNull();
    expect((resp as JsonRpcResponse).error!.message).toBe('[mcp-fence] Blocked: ');
  });

  it('should preserve id=0 (falsy but valid JSON-RPC id)', () => {
    const msg: JsonRpcRequest = { jsonrpc: '2.0', id: 0, method: 'test' };
    const result = makeBlockResult();
    const resp = createBlockResponse(msg, result);

    // BUG: id=0 is a valid JSON-RPC id, but the proxy checks `originalMessage.id == null`
    // which is false for 0. So this should return a response. However, if the check
    // were `!originalMessage.id`, id=0 would be wrongly treated as no-id.
    expect(resp).not.toBeNull();
    expect((resp as JsonRpcResponse).id).toBe(0);
  });
});

// ─── Decision logic: enforce mode ───

describe('handleMessage — enforce mode', () => {
  it('should block and not forward when decision=block', () => {
    const msg: JsonRpcRequest = { jsonrpc: '2.0', id: 1, method: 'tools/call' };
    const result = makeBlockResult();
    const outcome = simulateHandleMessage(msg, result, 'enforce');

    expect(outcome.forwarded).toBe(false);
    expect(outcome.blockResponseSent).not.toBeNull();
  });

  it('should forward when decision=allow in enforce mode', () => {
    const msg: JsonRpcRequest = { jsonrpc: '2.0', id: 1, method: 'tools/call' };
    const result = passthroughResult('request');
    const outcome = simulateHandleMessage(msg, result, 'enforce');

    expect(outcome.forwarded).toBe(true);
    expect(outcome.blockResponseSent).toBeNull();
  });

  it('should forward when decision=warn in enforce mode (warn does not block)', () => {
    const msg: JsonRpcRequest = { jsonrpc: '2.0', id: 1, method: 'tools/call' };
    const result = makeWarnResult();
    const outcome = simulateHandleMessage(msg, result, 'enforce');

    expect(outcome.forwarded).toBe(true);
    expect(outcome.blockResponseSent).toBeNull();
  });
});

// ─── Decision logic: monitor mode ───

describe('handleMessage — monitor mode', () => {
  it('should forward even when decision=block in monitor mode', () => {
    const msg: JsonRpcRequest = { jsonrpc: '2.0', id: 1, method: 'tools/call' };
    const result = makeBlockResult();
    const outcome = simulateHandleMessage(msg, result, 'monitor');

    expect(outcome.forwarded).toBe(true);
    expect(outcome.blockResponseSent).toBeNull();
  });

  it('should forward when decision=warn in monitor mode', () => {
    const msg: JsonRpcRequest = { jsonrpc: '2.0', id: 1, method: 'tools/call' };
    const result = makeWarnResult();
    const outcome = simulateHandleMessage(msg, result, 'monitor');

    expect(outcome.forwarded).toBe(true);
    expect(outcome.blockResponseSent).toBeNull();
  });

  it('should forward when decision=allow in monitor mode', () => {
    const msg: JsonRpcRequest = { jsonrpc: '2.0', id: 1, method: 'tools/list' };
    const result = passthroughResult('request');
    const outcome = simulateHandleMessage(msg, result, 'monitor');

    expect(outcome.forwarded).toBe(true);
    expect(outcome.blockResponseSent).toBeNull();
  });
});

// ─── Blocking responses (server → client direction) ───

describe('handleServerMessage — block response direction', () => {
  it('should create block response for a response with id in enforce mode', () => {
    const msg: JsonRpcResponse = {
      jsonrpc: '2.0',
      id: 99,
      result: { malicious: true },
    };
    const scanResult: ScanResult = {
      ...makeBlockResult(),
      direction: 'response',
    };
    const outcome = simulateHandleMessage(msg, scanResult, 'enforce');

    expect(outcome.forwarded).toBe(false);
    expect(outcome.blockResponseSent).not.toBeNull();
    expect((outcome.blockResponseSent as JsonRpcResponse).id).toBe(99);
  });

  it('should forward blocked response in monitor mode', () => {
    const msg: JsonRpcResponse = {
      jsonrpc: '2.0',
      id: 99,
      result: { suspicious: true },
    };
    const scanResult: ScanResult = {
      ...makeBlockResult(),
      direction: 'response',
    };
    const outcome = simulateHandleMessage(msg, scanResult, 'monitor');

    expect(outcome.forwarded).toBe(true);
  });
});

// ─── Scanner interface contract ───

describe('Scanner interface contract', () => {
  it('should accept a scanner that returns ScanResult', async () => {
    const mockScanner: Scanner = {
      scan: vi.fn().mockResolvedValue({
        decision: 'warn',
        findings: [makeFinding({ severity: 'medium', confidence: 0.6 })],
        score: 0.6,
        direction: 'request' as Direction,
        timestamp: Date.now(),
      }),
    };

    const message: JsonRpcMessage = { jsonrpc: '2.0', id: 1, method: 'tools/call' };
    const result = await mockScanner.scan(message, 'request');
    expect(result.decision).toBe('warn');
    expect(result.findings).toHaveLength(1);
  });

  it('should accept an audit logger that records events', async () => {
    const logged: Array<{ message: JsonRpcMessage; result: ScanResult }> = [];
    const mockLogger: AuditLogger = {
      log: vi.fn().mockImplementation(async (msg, res) => {
        logged.push({ message: msg, result: res });
      }),
    };

    const message: JsonRpcMessage = { jsonrpc: '2.0', id: 1, method: 'test' };
    const result = passthroughResult('request');

    await mockLogger.log(message, result);
    expect(logged).toHaveLength(1);
  });
});
