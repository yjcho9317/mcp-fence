/**
 * HTTP mode runner for SSE and Streamable HTTP transports.
 *
 * Creates an HTTP server that routes:
 * - GET /sse         -> SSE stream (server-to-client events)
 * - POST /message    -> client-to-server messages (SSE mode)
 * - POST /           -> bidirectional JSON-RPC (Streamable HTTP mode)
 * - GET /health      -> health check endpoint
 *
 * Connects to an upstream MCP server and wires transports through McpProxy.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { SseClientTransport, SseServerTransport } from '../transport/sse-transport.js';
import { HttpClientTransport, HttpServerTransport } from '../transport/http-transport.js';
import { McpProxy, type ProxyOptions } from '../proxy.js';
import { jwtGuard } from '../auth/middleware.js';
import type { JwtConfig } from '../auth/jwt.js';
import { createLogger } from '../logger.js';
import type { FenceConfig, Scanner, AuditLogger } from '../types.js';
import type { HashPinChecker } from '../integrity/hash-pin.js';
import type { PolicyEngine } from '../policy/engine.js';

const log = createLogger('runner-http');

export type HttpTransportMode = 'sse' | 'http';

export interface HttpRunnerOptions {
  /** Transport mode */
  transportMode: HttpTransportMode;
  /** Port to listen on */
  port: number;
  /** Upstream MCP server URL */
  upstreamUrl: string;
  /** mcp-fence configuration */
  config: FenceConfig;
  /** JWT authentication config */
  jwtConfig?: JwtConfig;
  /** Optional content scanner */
  scanner?: Scanner;
  /** Optional hash pin checker */
  hashPinChecker?: HashPinChecker;
  /** Optional policy engine */
  policyEngine?: PolicyEngine;
  /** Optional audit logger */
  auditLogger?: AuditLogger;
}

export class HttpRunner {
  private server: Server | null = null;
  private proxies: Map<string, McpProxy> = new Map();
  private sseSessions: Map<string, SseServerTransport> = new Map();
  private httpServerTransport: HttpServerTransport | null = null;
  private httpClientTransport: HttpClientTransport | null = null;
  private httpProxy: McpProxy | null = null;

  constructor(private readonly options: HttpRunnerOptions) {}

  async start(): Promise<void> {
    const { port, transportMode, upstreamUrl } = this.options;

    this.server = createServer((req, res) => {
      this.handleRequest(req, res).catch((err) => {
        log.error('Unhandled request error', err);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'internal_error' }));
        }
      });
    });

    // Pre-create the Streamable HTTP transport if in http mode
    if (transportMode === 'http') {
      this.httpClientTransport = new HttpClientTransport(upstreamUrl);
      this.httpServerTransport = new HttpServerTransport();

      const proxyOpts: ProxyOptions = {
        clientTransport: this.httpServerTransport,
        serverTransport: this.httpClientTransport,
        config: this.options.config,
        scanner: this.options.scanner,
        hashPinChecker: this.options.hashPinChecker,
        policyEngine: this.options.policyEngine,
        auditLogger: this.options.auditLogger,
      };

      this.httpProxy = new McpProxy(proxyOpts);
      await this.httpProxy.start();
    }

    return new Promise<void>((resolve, reject) => {
      this.server!.on('error', reject);
      this.server!.listen(port, () => {
        log.info(`mcp-fence HTTP server listening on port ${port} (${transportMode} mode)`);
        log.info(`Upstream: ${upstreamUrl}`);
        resolve();
      });
    });
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers['host'] ?? 'localhost'}`);
    const method = req.method ?? 'GET';
    const pathname = url.pathname;

    // Health check (no auth required)
    if (method === 'GET' && pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', mode: this.options.transportMode }));
      return;
    }

    // JWT guard for all other endpoints
    const authenticated = await jwtGuard(req, res, this.options.jwtConfig);
    if (!authenticated) return;

    if (this.options.transportMode === 'sse') {
      await this.handleSseMode(method, pathname, url, req, res);
    } else {
      await this.handleHttpMode(method, pathname, req, res);
    }
  }

  /**
   * SSE mode routes:
   * - GET /sse           -> establish SSE stream
   * - POST /message      -> send message to server (requires sessionId query param)
   */
  private async handleSseMode(
    method: string,
    pathname: string,
    url: URL,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    if (method === 'GET' && pathname === '/sse') {
      await this.handleSseConnect(res);
      return;
    }

    if (method === 'POST' && pathname === '/message') {
      const sessionId = url.searchParams.get('sessionId');
      if (!sessionId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'missing_session_id' }));
        return;
      }

      const session = this.sseSessions.get(sessionId);
      if (!session) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'session_not_found' }));
        return;
      }

      session.handlePostMessage(req, res);
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  }

  /**
   * Streamable HTTP mode routes:
   * - POST / -> JSON-RPC request/response
   */
  private async handleHttpMode(
    method: string,
    pathname: string,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    if (method === 'POST' && pathname === '/') {
      if (!this.httpServerTransport) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'transport_not_ready' }));
        return;
      }

      this.httpServerTransport.handleRequest(req, res);
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  }

  /**
   * Handle a new SSE client connection.
   * Creates a session-specific upstream connection and wires through proxy.
   */
  private async handleSseConnect(res: ServerResponse): Promise<void> {
    const serverTransport = new SseServerTransport();
    const sessionId = serverTransport.sessionId;

    log.info(`New SSE session: ${sessionId}`);

    const clientTransport = new SseClientTransport(this.options.upstreamUrl);

    try {
      await clientTransport.connect();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      log.error(`Failed to connect to upstream: ${message}`);
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'upstream_connection_failed', message }));
      return;
    }

    // Attach the SSE response (starts streaming to client)
    serverTransport.attachSseResponse(res);

    // Wire through proxy
    const proxyOpts: ProxyOptions = {
      clientTransport: serverTransport,
      serverTransport: clientTransport,
      config: this.options.config,
      scanner: this.options.scanner,
      hashPinChecker: this.options.hashPinChecker,
      policyEngine: this.options.policyEngine,
      auditLogger: this.options.auditLogger,
    };

    const proxy = new McpProxy(proxyOpts);
    await proxy.start();

    this.sseSessions.set(sessionId, serverTransport);
    this.proxies.set(sessionId, proxy);

    // Clean up on disconnect
    serverTransport.onClose(() => {
      log.info(`SSE session closed: ${sessionId}`);
      proxy.shutdown();
      clientTransport.close();
      this.sseSessions.delete(sessionId);
      this.proxies.delete(sessionId);
    });
  }

  /**
   * Gracefully shut down the HTTP server and all active sessions.
   */
  shutdown(): void {
    log.info('Shutting down HTTP runner...');

    for (const [sessionId, proxy] of this.proxies) {
      proxy.shutdown();
      this.proxies.delete(sessionId);
    }
    this.sseSessions.clear();

    this.httpProxy?.shutdown();
    this.httpClientTransport?.close();

    if (this.server) {
      this.server.close();
      this.server = null;
    }

    log.info('HTTP runner shut down');
  }

  /** The underlying HTTP server instance (for testing). */
  get httpServer(): Server | null {
    return this.server;
  }
}
