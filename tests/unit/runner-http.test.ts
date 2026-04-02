import { describe, it, expect, afterEach, vi } from 'vitest';
import { HttpRunner, type HttpRunnerOptions } from '../../src/server/runner-http.js';
import type { FenceConfig } from '../../src/types.js';
import * as jose from 'jose';

const TEST_CONFIG: FenceConfig = {
  mode: 'monitor',
  log: { level: 'error', maxDbSizeMb: 100 },
  detection: { warnThreshold: 0.5, blockThreshold: 0.8, maxInputSize: 10240 },
  policy: { defaultAction: 'allow', rules: [] },
};

/**
 * Create a minimal mock upstream MCP SSE server for testing.
 * Returns the server and its URL.
 */
async function createMockUpstream(): Promise<{
  server: import('node:http').Server;
  url: string;
  close: () => Promise<void>;
}> {
  const http = await import('node:http');

  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/sse') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        });
        // Send endpoint event
        res.write('event: endpoint\ndata: /message\n\n');
        // Keep connection open
        return;
      }

      if (req.method === 'POST' && req.url?.startsWith('/message')) {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', () => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok' }));
        });
        return;
      }

      if (req.method === 'POST' && req.url === '/') {
        // Streamable HTTP: echo back a response
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', () => {
          const body = JSON.parse(Buffer.concat(chunks).toString()) as { id?: number; method?: string };
          if (body.id != null) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { echo: true } }));
          } else {
            res.writeHead(202);
            res.end();
          }
        });
        return;
      }

      res.writeHead(404);
      res.end();
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as import('node:net').AddressInfo;
      const url = `http://127.0.0.1:${addr.port}`;
      resolve({
        server,
        url,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

describe('HttpRunner', () => {
  let runner: HttpRunner | null = null;
  let mockUpstream: Awaited<ReturnType<typeof createMockUpstream>> | null = null;

  afterEach(async () => {
    runner?.shutdown();
    runner = null;
    // Allow pending abort rejections to settle before closing upstream
    await new Promise((r) => setTimeout(r, 50));
    await mockUpstream?.close();
    mockUpstream = null;
  });

  it('should start an HTTP server and respond to health check', async () => {
    mockUpstream = await createMockUpstream();

    const options: HttpRunnerOptions = {
      transportMode: 'http',
      port: 0, // random port
      upstreamUrl: mockUpstream.url,
      config: TEST_CONFIG,
    };

    runner = new HttpRunner(options);

    // Use a random available port
    const actualOptions = { ...options, port: 0 };
    runner = new HttpRunner(actualOptions);

    // Listen on random port
    const httpModule = await import('node:http');
    // Patch: use the runner with port 0 trick
    await runner.start();

    const server = runner.httpServer!;
    const addr = server.address() as import('node:net').AddressInfo;
    const port = addr.port;

    const res = await fetch(`http://127.0.0.1:${port}/health`);
    expect(res.ok).toBe(true);
    const body = await res.json();
    expect(body.status).toBe('ok');
    expect(body.mode).toBe('http');
  });

  it('should return 404 for unknown routes', async () => {
    mockUpstream = await createMockUpstream();

    runner = new HttpRunner({
      transportMode: 'http',
      port: 0,
      upstreamUrl: mockUpstream.url,
      config: TEST_CONFIG,
    });

    await runner.start();
    const addr = runner.httpServer!.address() as import('node:net').AddressInfo;

    const res = await fetch(`http://127.0.0.1:${addr.port}/unknown`);
    expect(res.status).toBe(404);
  });

  it('should reject requests without JWT when jwt is enabled', async () => {
    mockUpstream = await createMockUpstream();

    const secret = 'test-jwt-secret-long-enough-for-hs256';
    runner = new HttpRunner({
      transportMode: 'http',
      port: 0,
      upstreamUrl: mockUpstream.url,
      config: TEST_CONFIG,
      jwtConfig: { enabled: true, secret },
    });

    await runner.start();
    const addr = runner.httpServer!.address() as import('node:net').AddressInfo;

    // POST without token
    const res = await fetch(`http://127.0.0.1:${addr.port}/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe('missing_token');
  });

  it('should allow requests with valid JWT', async () => {
    mockUpstream = await createMockUpstream();

    const secret = 'test-jwt-secret-long-enough-for-hs256';
    runner = new HttpRunner({
      transportMode: 'http',
      port: 0,
      upstreamUrl: mockUpstream.url,
      config: TEST_CONFIG,
      jwtConfig: { enabled: true, secret },
    });

    await runner.start();
    const addr = runner.httpServer!.address() as import('node:net').AddressInfo;

    // Create a valid token
    const key = new TextEncoder().encode(secret);
    const token = await new jose.SignJWT({ sub: 'test-user' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(key);

    const res = await fetch(`http://127.0.0.1:${addr.port}/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });

    // The request should be accepted (200 from upstream echo or 202/timeout)
    // At minimum, it should not be 401
    expect(res.status).not.toBe(401);
  });

  it('should allow health check without JWT', async () => {
    mockUpstream = await createMockUpstream();

    runner = new HttpRunner({
      transportMode: 'http',
      port: 0,
      upstreamUrl: mockUpstream.url,
      config: TEST_CONFIG,
      jwtConfig: { enabled: true, secret: 'test-jwt-secret-long-enough-for-hs256' },
    });

    await runner.start();
    const addr = runner.httpServer!.address() as import('node:net').AddressInfo;

    const res = await fetch(`http://127.0.0.1:${addr.port}/health`);
    expect(res.status).toBe(200);
  });

  it('should start SSE mode server and accept GET /sse', async () => {
    mockUpstream = await createMockUpstream();

    runner = new HttpRunner({
      transportMode: 'sse',
      port: 0,
      upstreamUrl: mockUpstream.url,
      config: TEST_CONFIG,
    });

    await runner.start();
    const addr = runner.httpServer!.address() as import('node:net').AddressInfo;

    // Connect to SSE endpoint
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    try {
      const res = await fetch(`http://127.0.0.1:${addr.port}/sse`, {
        headers: { 'Accept': 'text/event-stream' },
        signal: controller.signal,
      });

      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toBe('text/event-stream');

      // Read the first chunk which should contain the endpoint event
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      const { value } = await reader.read();
      const text = decoder.decode(value);

      expect(text).toContain('event: endpoint');
      expect(text).toContain('sessionId=');

      reader.cancel();
    } finally {
      clearTimeout(timeout);
    }
  });

  it('should return 400 for POST /message without sessionId', async () => {
    mockUpstream = await createMockUpstream();

    runner = new HttpRunner({
      transportMode: 'sse',
      port: 0,
      upstreamUrl: mockUpstream.url,
      config: TEST_CONFIG,
    });

    await runner.start();
    const addr = runner.httpServer!.address() as import('node:net').AddressInfo;

    const res = await fetch(`http://127.0.0.1:${addr.port}/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'test' }),
    });

    expect(res.status).toBe(400);
  });

  it('should return 404 for POST /message with unknown sessionId', async () => {
    mockUpstream = await createMockUpstream();

    runner = new HttpRunner({
      transportMode: 'sse',
      port: 0,
      upstreamUrl: mockUpstream.url,
      config: TEST_CONFIG,
    });

    await runner.start();
    const addr = runner.httpServer!.address() as import('node:net').AddressInfo;

    const res = await fetch(`http://127.0.0.1:${addr.port}/message?sessionId=nonexistent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'test' }),
    });

    expect(res.status).toBe(404);
  });
});
