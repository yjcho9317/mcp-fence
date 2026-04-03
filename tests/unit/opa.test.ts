/**
 * Tests for OPA (Open Policy Agent) client integration.
 *
 * Spins up a local HTTP server to mock OPA responses, validating:
 * - Successful allow/deny decisions
 * - Timeout handling
 * - failOpen behavior (OPA unreachable -> allow)
 * - failClosed behavior (OPA unreachable -> deny)
 * - OPA overriding local policy decisions
 * - Various OPA response formats
 */

import { describe, it, expect, afterEach } from 'vitest';
import * as http from 'node:http';
import { queryOpa, type OpaConfig } from '../../src/policy/opa-client.js';
import { PolicyEngine } from '../../src/policy/engine.js';
import type { JsonRpcMessage, PolicyConfig } from '../../src/types.js';

// ─── Test HTTP server helpers ───

interface MockOpaServer {
  server: http.Server;
  url: string;
  close: () => Promise<void>;
}

function createMockOpaServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<MockOpaServer> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      const url = `http://127.0.0.1:${addr.port}/v1/data/mcp/allow`;
      resolve({
        server,
        url,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

function toolsCall(name: string, args?: Record<string, unknown>): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name, arguments: args },
  };
}

// ─── queryOpa ───

let mockServer: MockOpaServer | null = null;

afterEach(async () => {
  if (mockServer) {
    await mockServer.close();
    mockServer = null;
  }
});

describe('queryOpa — successful responses', () => {
  it('should return allow when OPA result is true', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result: true }));
    });

    const config: OpaConfig = { enabled: true, url: mockServer.url, allowPrivateNetwork: true };
    const decision = await queryOpa(config, { tool: 'read_file', direction: 'request' });
    expect(decision.allow).toBe(true);
  });

  it('should return deny when OPA result is false', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result: false }));
    });

    const config: OpaConfig = { enabled: true, url: mockServer.url, allowPrivateNetwork: true };
    const decision = await queryOpa(config, { tool: 'exec_cmd', direction: 'request' });
    expect(decision.allow).toBe(false);
  });

  it('should return allow with reason from object response', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result: { allow: true, reason: 'whitelisted tool' } }));
    });

    const config: OpaConfig = { enabled: true, url: mockServer.url, allowPrivateNetwork: true };
    const decision = await queryOpa(config, { tool: 'read_file', direction: 'request' });
    expect(decision.allow).toBe(true);
    expect(decision.reason).toBe('whitelisted tool');
  });

  it('should return deny with reason from object response', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result: { allow: false, reason: 'unauthorized tool' } }));
    });

    const config: OpaConfig = { enabled: true, url: mockServer.url, allowPrivateNetwork: true };
    const decision = await queryOpa(config, { tool: 'exec_cmd', direction: 'request' });
    expect(decision.allow).toBe(false);
    expect(decision.reason).toBe('unauthorized tool');
  });

  it('should send correct input payload to OPA', async () => {
    let receivedBody = '';
    mockServer = await createMockOpaServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        receivedBody = Buffer.concat(chunks).toString('utf-8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ result: true }));
      });
    });

    const config: OpaConfig = { enabled: true, url: mockServer.url, allowPrivateNetwork: true };
    await queryOpa(config, { tool: 'read_file', args: { path: '/tmp' }, direction: 'request' });

    const parsed = JSON.parse(receivedBody);
    expect(parsed.input.tool).toBe('read_file');
    expect(parsed.input.args).toEqual({ path: '/tmp' });
    expect(parsed.input.direction).toBe('request');
  });
});

describe('queryOpa — error handling', () => {
  it('should fail-open on timeout (default behavior)', async () => {
    mockServer = await createMockOpaServer((_req, _res) => {
      // Never respond — trigger timeout
    });

    const config: OpaConfig = {
      enabled: true,
      url: mockServer.url,
      timeoutMs: 100,
      failOpen: true,
      allowPrivateNetwork: true,
    };
    const decision = await queryOpa(config, { tool: 'exec_cmd', direction: 'request' });
    expect(decision.allow).toBe(true);
    expect(decision.reason).toContain('timed out');
  });

  it('should fail-closed on timeout when failOpen is false', async () => {
    mockServer = await createMockOpaServer((_req, _res) => {
      // Never respond
    });

    const config: OpaConfig = {
      enabled: true,
      url: mockServer.url,
      timeoutMs: 100,
      failOpen: false,
      allowPrivateNetwork: true,
    };
    const decision = await queryOpa(config, { tool: 'exec_cmd', direction: 'request' });
    expect(decision.allow).toBe(false);
    expect(decision.reason).toContain('timed out');
  });

  it('should fail-open on connection refused', async () => {
    const config: OpaConfig = {
      enabled: true,
      url: 'http://127.0.0.1:19999/v1/data/mcp/allow',
      timeoutMs: 500,
      failOpen: true,
      allowPrivateNetwork: true,
    };
    const decision = await queryOpa(config, { tool: 'exec_cmd', direction: 'request' });
    expect(decision.allow).toBe(true);
    expect(decision.reason).toContain('connection error');
  });

  it('should fail-closed on connection refused when failOpen is false', async () => {
    const config: OpaConfig = {
      enabled: true,
      url: 'http://127.0.0.1:19999/v1/data/mcp/allow',
      timeoutMs: 500,
      failOpen: false,
      allowPrivateNetwork: true,
    };
    const decision = await queryOpa(config, { tool: 'exec_cmd', direction: 'request' });
    expect(decision.allow).toBe(false);
    expect(decision.reason).toContain('connection error');
  });

  it('should fail-open on non-200 status', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(500);
      res.end('Internal Server Error');
    });

    const config: OpaConfig = { enabled: true, url: mockServer.url, failOpen: true, allowPrivateNetwork: true };
    const decision = await queryOpa(config, { tool: 'exec_cmd', direction: 'request' });
    expect(decision.allow).toBe(true);
    expect(decision.reason).toContain('status 500');
  });

  it('should fail-closed on non-200 status when failOpen is false', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(404);
      res.end('Not Found');
    });

    const config: OpaConfig = { enabled: true, url: mockServer.url, failOpen: false, allowPrivateNetwork: true };
    const decision = await queryOpa(config, { tool: 'exec_cmd', direction: 'request' });
    expect(decision.allow).toBe(false);
    expect(decision.reason).toContain('status 404');
  });

  it('should fail-open on invalid JSON response', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('not json at all');
    });

    const config: OpaConfig = { enabled: true, url: mockServer.url, failOpen: true, allowPrivateNetwork: true };
    const decision = await queryOpa(config, { tool: 'exec_cmd', direction: 'request' });
    expect(decision.allow).toBe(true);
    expect(decision.reason).toContain('parse');
  });

  it('should deny when OPA result is undefined (policy path missing)', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({}));
    });

    const config: OpaConfig = { enabled: true, url: mockServer.url, allowPrivateNetwork: true };
    const decision = await queryOpa(config, { tool: 'exec_cmd', direction: 'request' });
    expect(decision.allow).toBe(false);
    expect(decision.reason).toContain('no decision');
  });
});

// ─── PolicyEngine + OPA integration ───

describe('PolicyEngine with OPA integration', () => {
  it('OPA allow overrides local deny', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result: true }));
    });

    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'exec_cmd', action: 'deny' }],
      opa: { enabled: true, url: mockServer.url, allowPrivateNetwork: true },
    };
    const engine = new PolicyEngine(config);
    const findings = await engine.evaluate(toolsCall('exec_cmd'));
    expect(findings).toHaveLength(0);
  });

  it('OPA deny overrides local allow', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result: { allow: false, reason: 'OPA says no' } }));
    });

    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'read_file', action: 'allow' }],
      opa: { enabled: true, url: mockServer.url, allowPrivateNetwork: true },
    };
    const engine = new PolicyEngine(config);
    const findings = await engine.evaluate(toolsCall('read_file'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('OPA-001');
    expect(findings[0]!.metadata?.['source']).toBe('opa');
    expect(findings[0]!.metadata?.['opaReason']).toBe('OPA says no');
  });

  it('OPA deny with default OPA message when no reason provided', async () => {
    mockServer = await createMockOpaServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result: false }));
    });

    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [],
      opa: { enabled: true, url: mockServer.url, allowPrivateNetwork: true },
    };
    const engine = new PolicyEngine(config);
    const findings = await engine.evaluate(toolsCall('any_tool'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('denied by OPA');
  });

  it('OPA unreachable with failOpen allows through', async () => {
    const config: PolicyConfig = {
      defaultAction: 'deny',
      rules: [],
      opa: {
        enabled: true,
        url: 'http://127.0.0.1:19999/v1/data/mcp/allow',
        timeoutMs: 100,
        failOpen: true,
        allowPrivateNetwork: true,
      },
    };
    const engine = new PolicyEngine(config);
    const findings = await engine.evaluate(toolsCall('any_tool'));
    // failOpen + OPA unreachable -> OPA returns allow -> no findings
    expect(findings).toHaveLength(0);
  });

  it('OPA unreachable with failClosed denies', async () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'read_file', action: 'allow' }],
      opa: {
        enabled: true,
        url: 'http://127.0.0.1:19999/v1/data/mcp/allow',
        timeoutMs: 100,
        failOpen: false,
        allowPrivateNetwork: true,
      },
    };
    const engine = new PolicyEngine(config);
    const findings = await engine.evaluate(toolsCall('read_file'));
    // failClosed + OPA unreachable -> OPA returns deny -> findings
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('OPA-001');
  });

  it('non-tools/call messages bypass OPA entirely', async () => {
    let opaQueried = false;
    mockServer = await createMockOpaServer((_req, res) => {
      opaQueried = true;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result: false }));
    });

    const config: PolicyConfig = {
      defaultAction: 'deny',
      rules: [],
      opa: { enabled: true, url: mockServer.url, allowPrivateNetwork: true },
    };
    const engine = new PolicyEngine(config);
    const listMsg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
    };
    const findings = await engine.evaluate(listMsg);
    expect(findings).toHaveLength(0);
    expect(opaQueried).toBe(false);
  });
});
