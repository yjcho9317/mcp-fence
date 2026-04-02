import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PassThrough } from 'node:stream';
import { SseParser, formatSseEvent, type SseEvent } from '../../src/transport/sse-parser.js';
import { SseServerTransport } from '../../src/transport/sse-transport.js';
import { HttpServerTransport } from '../../src/transport/http-transport.js';
import { extractBearerToken, authenticateRequest, sendUnauthorized, jwtGuard } from '../../src/auth/middleware.js';
import { verifyToken } from '../../src/auth/jwt.js';
import type { JwtConfig } from '../../src/auth/jwt.js';
import * as jose from 'jose';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { JsonRpcMessage } from '../../src/types.js';

// ─── SSE Parser ───

describe('SseParser', () => {
  it('should parse a single SSE event', async () => {
    const stream = new PassThrough();
    const parser = new SseParser(stream);
    const events: SseEvent[] = [];

    parser.on('event', (e: SseEvent) => events.push(e));

    stream.write('data: hello world\n\n');
    await new Promise((r) => setTimeout(r, 10));

    expect(events).toHaveLength(1);
    expect(events[0]!.data).toBe('hello world');
    expect(events[0]!.type).toBe('message');

    stream.end();
  });

  it('should parse events with custom type', async () => {
    const stream = new PassThrough();
    const parser = new SseParser(stream);
    const events: SseEvent[] = [];

    parser.on('event', (e: SseEvent) => events.push(e));

    stream.write('event: endpoint\ndata: /message?sessionId=abc\n\n');
    await new Promise((r) => setTimeout(r, 10));

    expect(events).toHaveLength(1);
    expect(events[0]!.type).toBe('endpoint');
    expect(events[0]!.data).toBe('/message?sessionId=abc');

    stream.end();
  });

  it('should parse events with id field', async () => {
    const stream = new PassThrough();
    const parser = new SseParser(stream);
    const events: SseEvent[] = [];

    parser.on('event', (e: SseEvent) => events.push(e));

    stream.write('id: 42\ndata: test\n\n');
    await new Promise((r) => setTimeout(r, 10));

    expect(events).toHaveLength(1);
    expect(events[0]!.id).toBe('42');

    stream.end();
  });

  it('should handle multi-line data fields', async () => {
    const stream = new PassThrough();
    const parser = new SseParser(stream);
    const events: SseEvent[] = [];

    parser.on('event', (e: SseEvent) => events.push(e));

    stream.write('data: line 1\ndata: line 2\ndata: line 3\n\n');
    await new Promise((r) => setTimeout(r, 10));

    expect(events).toHaveLength(1);
    expect(events[0]!.data).toBe('line 1\nline 2\nline 3');

    stream.end();
  });

  it('should ignore comment lines', async () => {
    const stream = new PassThrough();
    const parser = new SseParser(stream);
    const events: SseEvent[] = [];

    parser.on('event', (e: SseEvent) => events.push(e));

    stream.write(': this is a comment\ndata: actual data\n\n');
    await new Promise((r) => setTimeout(r, 10));

    expect(events).toHaveLength(1);
    expect(events[0]!.data).toBe('actual data');

    stream.end();
  });

  it('should parse multiple events in sequence', async () => {
    const stream = new PassThrough();
    const parser = new SseParser(stream);
    const events: SseEvent[] = [];

    parser.on('event', (e: SseEvent) => events.push(e));

    stream.write('data: first\n\ndata: second\n\ndata: third\n\n');
    await new Promise((r) => setTimeout(r, 10));

    expect(events).toHaveLength(3);
    expect(events[0]!.data).toBe('first');
    expect(events[1]!.data).toBe('second');
    expect(events[2]!.data).toBe('third');

    stream.end();
  });

  it('should handle chunked data across writes', async () => {
    const stream = new PassThrough();
    const parser = new SseParser(stream);
    const events: SseEvent[] = [];

    parser.on('event', (e: SseEvent) => events.push(e));

    stream.write('dat');
    stream.write('a: split across\n');
    stream.write('\n');
    await new Promise((r) => setTimeout(r, 10));

    expect(events).toHaveLength(1);
    expect(events[0]!.data).toBe('split across');

    stream.end();
  });

  it('should emit close when stream ends', async () => {
    const stream = new PassThrough();
    const parser = new SseParser(stream);

    let closed = false;
    parser.on('close', () => { closed = true; });

    stream.end();
    await new Promise((r) => setTimeout(r, 10));

    expect(closed).toBe(true);
  });

  it('should parse JSON-RPC message from SSE data', async () => {
    const stream = new PassThrough();
    const parser = new SseParser(stream);
    const events: SseEvent[] = [];

    parser.on('event', (e: SseEvent) => events.push(e));

    const jsonRpc = JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: [] } });
    stream.write(`event: message\ndata: ${jsonRpc}\n\n`);
    await new Promise((r) => setTimeout(r, 10));

    expect(events).toHaveLength(1);
    const parsed = JSON.parse(events[0]!.data);
    expect(parsed.jsonrpc).toBe('2.0');
    expect(parsed.id).toBe(1);

    stream.end();
  });

  it('should strip leading space after colon per SSE spec', async () => {
    const stream = new PassThrough();
    const parser = new SseParser(stream);
    const events: SseEvent[] = [];

    parser.on('event', (e: SseEvent) => events.push(e));

    // "data: value" -> value is "value" (space after colon stripped)
    // "data:value" -> value is "value" (no space to strip)
    stream.write('data: with space\n\n');
    stream.write('data:without space\n\n');
    await new Promise((r) => setTimeout(r, 10));

    expect(events).toHaveLength(2);
    expect(events[0]!.data).toBe('with space');
    expect(events[1]!.data).toBe('without space');

    stream.end();
  });
});

// ─── formatSseEvent ───

describe('formatSseEvent', () => {
  it('should format a basic data event', () => {
    const result = formatSseEvent('hello');
    expect(result).toBe('data: hello\n\n');
  });

  it('should format an event with type', () => {
    const result = formatSseEvent('endpoint-url', 'endpoint');
    expect(result).toBe('event: endpoint\ndata: endpoint-url\n\n');
  });

  it('should format an event with id', () => {
    const result = formatSseEvent('data', 'message', '42');
    expect(result).toBe('id: 42\nevent: message\ndata: data\n\n');
  });

  it('should split multi-line data across data: fields', () => {
    const result = formatSseEvent('line1\nline2');
    expect(result).toBe('data: line1\ndata: line2\n\n');
  });
});

// ─── JWT Verification ───

describe('JWT verification', () => {
  const HS256_SECRET = 'test-secret-that-is-long-enough-for-hs256';

  async function createHs256Token(
    payload: Record<string, unknown>,
    secret: string = HS256_SECRET,
  ): Promise<string> {
    const key = new TextEncoder().encode(secret);
    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(key);
  }

  it('should verify a valid HS256 token', async () => {
    const token = await createHs256Token({ sub: 'user-1' });
    const config: JwtConfig = { enabled: true, secret: HS256_SECRET };

    const payload = await verifyToken(token, config);
    expect(payload.sub).toBe('user-1');
  });

  it('should reject an expired token', async () => {
    const key = new TextEncoder().encode(HS256_SECRET);
    const token = await new jose.SignJWT({ sub: 'user-1' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
      .sign(key);

    const config: JwtConfig = { enabled: true, secret: HS256_SECRET };

    await expect(verifyToken(token, config)).rejects.toThrow();
  });

  it('should reject a token with wrong signature', async () => {
    const token = await createHs256Token({ sub: 'user-1' });
    const config: JwtConfig = { enabled: true, secret: 'different-secret-entirely-wrong' };

    await expect(verifyToken(token, config)).rejects.toThrow();
  });

  it('should verify audience claim', async () => {
    const key = new TextEncoder().encode(HS256_SECRET);
    const token = await new jose.SignJWT({ sub: 'user-1' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .setAudience('mcp-fence')
      .sign(key);

    const config: JwtConfig = { enabled: true, secret: HS256_SECRET, audience: 'mcp-fence' };
    const payload = await verifyToken(token, config);
    expect(payload.sub).toBe('user-1');
  });

  it('should reject token with wrong audience', async () => {
    const key = new TextEncoder().encode(HS256_SECRET);
    const token = await new jose.SignJWT({ sub: 'user-1' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .setAudience('other-service')
      .sign(key);

    const config: JwtConfig = { enabled: true, secret: HS256_SECRET, audience: 'mcp-fence' };
    await expect(verifyToken(token, config)).rejects.toThrow();
  });

  it('should verify issuer claim', async () => {
    const key = new TextEncoder().encode(HS256_SECRET);
    const token = await new jose.SignJWT({ sub: 'user-1' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .setIssuer('https://auth.example.com')
      .sign(key);

    const config: JwtConfig = { enabled: true, secret: HS256_SECRET, issuer: 'https://auth.example.com' };
    const payload = await verifyToken(token, config);
    expect(payload.sub).toBe('user-1');
  });

  it('should throw when neither secret nor jwksUrl is provided', async () => {
    const config: JwtConfig = { enabled: true };
    await expect(verifyToken('any-token', config)).rejects.toThrow('must specify either');
  });
});

// ─── Auth Middleware ───

describe('extractBearerToken', () => {
  it('should extract token from valid Bearer header', () => {
    expect(extractBearerToken('Bearer abc123')).toBe('abc123');
  });

  it('should return null for missing header', () => {
    expect(extractBearerToken(undefined)).toBeNull();
  });

  it('should return null for non-Bearer auth scheme', () => {
    expect(extractBearerToken('Basic abc123')).toBeNull();
  });

  it('should return null for malformed Bearer header', () => {
    expect(extractBearerToken('Bearer')).toBeNull();
    expect(extractBearerToken('Bearer a b c')).toBeNull();
  });
});

describe('authenticateRequest', () => {
  const SECRET = 'test-secret-that-is-long-enough-for-hs256';

  async function makeToken(payload: Record<string, unknown> = { sub: 'u1' }): Promise<string> {
    const key = new TextEncoder().encode(SECRET);
    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(key);
  }

  function mockRequest(headers: Record<string, string> = {}): IncomingMessage {
    return { headers } as unknown as IncomingMessage;
  }

  it('should return missing_token when no Authorization header', async () => {
    const req = mockRequest();
    const config: JwtConfig = { enabled: true, secret: SECRET };
    const result = await authenticateRequest(req, config);
    expect(result.authenticated).toBe(false);
    expect(result.error).toBe('missing_token');
  });

  it('should return authenticated for valid token', async () => {
    const token = await makeToken();
    const req = mockRequest({ authorization: `Bearer ${token}` });
    const config: JwtConfig = { enabled: true, secret: SECRET };
    const result = await authenticateRequest(req, config);
    expect(result.authenticated).toBe(true);
    expect(result.payload).toBeDefined();
  });

  it('should return invalid_token for garbage token', async () => {
    const req = mockRequest({ authorization: 'Bearer not.a.real.token' });
    const config: JwtConfig = { enabled: true, secret: SECRET };
    const result = await authenticateRequest(req, config);
    expect(result.authenticated).toBe(false);
  });
});

describe('sendUnauthorized', () => {
  it('should send 401 with error JSON', () => {
    const writeHead = vi.fn();
    const end = vi.fn();
    const res = { writeHead, end } as unknown as ServerResponse;

    sendUnauthorized(res, 'missing_token');

    expect(writeHead).toHaveBeenCalledWith(401, { 'Content-Type': 'application/json' });
    expect(end).toHaveBeenCalledWith(JSON.stringify({ error: 'missing_token' }));
  });
});

describe('jwtGuard', () => {
  it('should return true when JWT is disabled', async () => {
    const req = {} as IncomingMessage;
    const res = {} as ServerResponse;
    expect(await jwtGuard(req, res, undefined)).toBe(true);
    expect(await jwtGuard(req, res, { enabled: false })).toBe(true);
  });
});

// ─── SseServerTransport ───

describe('SseServerTransport', () => {
  it('should generate a unique session ID', () => {
    const t1 = new SseServerTransport();
    const t2 = new SseServerTransport();
    expect(t1.sessionId).not.toBe(t2.sessionId);
    expect(t1.sessionId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('should send SSE endpoint event when attached', () => {
    const transport = new SseServerTransport();
    const written: string[] = [];
    const res = {
      writeHead: vi.fn(),
      write: vi.fn((data: string) => written.push(data)),
      on: vi.fn(),
      writableEnded: false,
      end: vi.fn(),
    } as unknown as ServerResponse;

    transport.attachSseResponse(res);

    expect(res.writeHead).toHaveBeenCalledWith(200, expect.objectContaining({
      'Content-Type': 'text/event-stream',
    }));
    expect(written.length).toBe(1);
    expect(written[0]).toContain('event: endpoint');
    expect(written[0]).toContain(transport.sessionId);
  });

  it('should send messages as SSE events', () => {
    const transport = new SseServerTransport();
    const written: string[] = [];
    const res = {
      writeHead: vi.fn(),
      write: vi.fn((data: string) => written.push(data)),
      on: vi.fn(),
      writableEnded: false,
      end: vi.fn(),
    } as unknown as ServerResponse;

    transport.attachSseResponse(res);
    written.length = 0; // Clear the endpoint event

    const msg: JsonRpcMessage = { jsonrpc: '2.0', id: 1, result: { tools: [] } };
    transport.send(msg);

    expect(written.length).toBe(1);
    expect(written[0]).toContain('event: message');
    expect(written[0]).toContain('"jsonrpc"');
  });
});

// ─── HttpServerTransport ───

describe('HttpServerTransport', () => {
  function createMockRequest(body: string): IncomingMessage {
    const stream = new PassThrough();
    stream.push(Buffer.from(body));
    stream.push(null);
    (stream as unknown as IncomingMessage).headers = {};
    return stream as unknown as IncomingMessage;
  }

  it('should parse POST body and call message handler', async () => {
    const transport = new HttpServerTransport();
    const messages: JsonRpcMessage[] = [];
    transport.onMessage((msg) => messages.push(msg));

    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const req = createMockRequest(body);
    const writeHead = vi.fn();
    const end = vi.fn();
    const res = { writeHead, end, headersSent: false, on: vi.fn() } as unknown as ServerResponse;

    transport.handleRequest(req, res);
    await new Promise((r) => setTimeout(r, 20));

    expect(messages).toHaveLength(1);
    expect((messages[0] as { method: string }).method).toBe('tools/list');
  });

  it('should return 400 for invalid POST body', async () => {
    const transport = new HttpServerTransport();
    const errors: Error[] = [];
    transport.onError((err) => errors.push(err));

    const req = createMockRequest('not json');
    const writeHead = vi.fn();
    const end = vi.fn();
    const res = { writeHead, end, headersSent: false, on: vi.fn() } as unknown as ServerResponse;

    transport.handleRequest(req, res);
    await new Promise((r) => setTimeout(r, 20));

    expect(writeHead).toHaveBeenCalledWith(400, expect.anything());
    expect(errors).toHaveLength(1);
  });

  it('should send response via matching pending response', async () => {
    const transport = new HttpServerTransport();
    transport.onMessage(() => {}); // register handler

    const body = JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'tools/list' });
    const req = createMockRequest(body);
    const writeHead = vi.fn();
    const end = vi.fn();
    const on = vi.fn();
    const res = { writeHead, end, headersSent: false, on } as unknown as ServerResponse;

    transport.handleRequest(req, res);
    await new Promise((r) => setTimeout(r, 20));

    // Send a response back
    const responseMsg: JsonRpcMessage = { jsonrpc: '2.0', id: 42, result: { tools: [] } };
    transport.send(responseMsg);

    expect(writeHead).toHaveBeenCalledWith(200, { 'Content-Type': 'application/json' });
    expect(end).toHaveBeenCalledWith(JSON.stringify(responseMsg));
  });

  it('should send 202 for notifications (no id)', async () => {
    const transport = new HttpServerTransport();
    transport.onMessage(() => {});

    const body = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const req = createMockRequest(body);
    const writeHead = vi.fn();
    const end = vi.fn();
    const res = { writeHead, end, headersSent: false, on: vi.fn() } as unknown as ServerResponse;

    transport.handleRequest(req, res);
    await new Promise((r) => setTimeout(r, 20));

    expect(writeHead).toHaveBeenCalledWith(202, expect.anything());
  });
});
