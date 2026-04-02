/**
 * Streamable HTTP transport for MCP.
 *
 * MCP Streamable HTTP protocol uses a single POST endpoint:
 * - Client sends JSON-RPC in POST body
 * - Server responds with either application/json or text/event-stream
 *
 * HttpClientTransport: sends POST to upstream, reads response.
 * HttpServerTransport: accepts POST from client, queues responses.
 */

import { EventEmitter } from 'node:events';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { JsonRpcMessage } from '../types.js';
import type { Transport } from './types.js';
import { SseParser } from './sse-parser.js';
import { parseJsonRpcMessage } from './stdio.js';
import { createLogger } from '../logger.js';
import { TransportError } from '../errors.js';

const log = createLogger('transport:http');

/**
 * Sends JSON-RPC messages to an upstream MCP server via POST.
 * Responses come back in the POST response body (JSON or SSE).
 */
export class HttpClientTransport implements Transport {
  private messageHandler: ((msg: JsonRpcMessage) => void) | null = null;
  private errorHandler: ((err: Error) => void) | null = null;
  private closeHandler: (() => void) | null = null;
  private closed = false;
  private abortController = new AbortController();

  constructor(private readonly upstreamUrl: string) {}

  onMessage(handler: (msg: JsonRpcMessage) => void): void {
    this.messageHandler = handler;
  }

  onError(handler: (err: Error) => void): void {
    this.errorHandler = handler;
  }

  onClose(handler: () => void): void {
    this.closeHandler = handler;
  }

  /**
   * Send a JSON-RPC message via POST to the upstream server.
   * The response may be a single JSON body or an SSE stream.
   */
  send(msg: JsonRpcMessage): void {
    if (this.closed) return;

    const body = JSON.stringify(msg);

    fetch(this.upstreamUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
      },
      body,
      signal: this.abortController.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          this.errorHandler?.(
            new TransportError(`Upstream HTTP error: ${response.status} ${response.statusText}`),
          );
          return;
        }

        const contentType = response.headers.get('content-type') ?? '';

        if (contentType.includes('text/event-stream') && response.body) {
          // SSE streaming response
          await this.handleSseResponse(response.body);
        } else {
          // Single JSON response
          const text = await response.text();
          if (text.trim().length === 0) return;
          try {
            const responseMsg = parseJsonRpcMessage(text);
            this.messageHandler?.(responseMsg);
          } catch (err) {
            this.errorHandler?.(
              err instanceof Error ? err : new Error(String(err)),
            );
          }
        }
      })
      .catch((err: unknown) => {
        if (this.closed) return;
        const message = err instanceof Error ? err.message : String(err);
        this.errorHandler?.(new TransportError(`Failed to POST to upstream: ${message}`));
      });
  }

  close(): void {
    this.closed = true;
    this.abortController.abort();
    this.closeHandler?.();
  }

  private async handleSseResponse(webStream: ReadableStream<Uint8Array>): Promise<void> {
    const { Readable } = await import('node:stream');
    const nodeStream = Readable.fromWeb(webStream as import('stream/web').ReadableStream);
    const parser = new SseParser(nodeStream);

    parser.on('event', (event: { type: string; data: string }) => {
      if (event.type === 'message') {
        try {
          const msg = parseJsonRpcMessage(event.data);
          this.messageHandler?.(msg);
        } catch (err) {
          this.errorHandler?.(err instanceof Error ? err : new Error(String(err)));
        }
      }
    });

    parser.on('error', (err: Error) => {
      this.errorHandler?.(new TransportError(`SSE response stream error: ${err.message}`));
    });
  }
}

/**
 * Accepts Streamable HTTP requests from MCP clients.
 * Each POST request receives a JSON-RPC message; responses are sent
 * back via the pending HTTP response or queued for the next request.
 */
export class HttpServerTransport implements Transport {
  private messageHandler: ((msg: JsonRpcMessage) => void) | null = null;
  private errorHandler: ((err: Error) => void) | null = null;
  private closeHandler: (() => void) | null = null;
  private pendingResponses: Map<string | number, ServerResponse> = new Map();
  private closed = false;

  onMessage(handler: (msg: JsonRpcMessage) => void): void {
    this.messageHandler = handler;
  }

  onError(handler: (err: Error) => void): void {
    this.errorHandler = handler;
  }

  onClose(handler: () => void): void {
    this.closeHandler = handler;
  }

  /**
   * Handle an incoming POST request with a JSON-RPC message.
   */
  handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const chunks: Buffer[] = [];

    req.on('data', (chunk: Buffer) => chunks.push(chunk));

    req.on('end', () => {
      try {
        const body = Buffer.concat(chunks).toString('utf-8');
        const msg = parseJsonRpcMessage(body);

        // Track the response for requests that expect a reply
        if ('id' in msg && msg.id != null) {
          this.pendingResponses.set(msg.id, res);

          // Timeout: if no response within 30s, send 504
          const timeoutId = setTimeout(() => {
            if (this.pendingResponses.has(msg.id!)) {
              this.pendingResponses.delete(msg.id!);
              if (!res.headersSent) {
                res.writeHead(504, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'gateway_timeout' }));
              }
            }
          }, 30_000);

          // Clear timeout if response is sent before that
          res.on('close', () => {
            clearTimeout(timeoutId);
            this.pendingResponses.delete(msg.id!);
          });
        } else {
          // Notifications don't expect a response
          res.writeHead(202, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'accepted' }));
        }

        this.messageHandler?.(msg);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        this.errorHandler?.(new TransportError(`Invalid POST body: ${message}`));
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_request', message }));
      }
    });

    req.on('error', (err: Error) => {
      this.errorHandler?.(new TransportError(`POST request error: ${err.message}`));
    });
  }

  /**
   * Send a JSON-RPC message back to the client.
   * If the message is a response (has id), sends it via the pending HTTP response.
   * If it's a notification, it cannot be pushed (Streamable HTTP is request-response).
   */
  send(msg: JsonRpcMessage): void {
    if (this.closed) return;

    // Responses and errors have an 'id'
    if ('id' in msg && msg.id != null) {
      const pendingRes = this.pendingResponses.get(msg.id);
      if (pendingRes && !pendingRes.headersSent) {
        pendingRes.writeHead(200, { 'Content-Type': 'application/json' });
        pendingRes.end(JSON.stringify(msg));
        this.pendingResponses.delete(msg.id);
        return;
      }
    }

    // For notifications from server, we cannot push over Streamable HTTP
    // without an open response. Log and drop.
    log.debug('Dropping server notification (no pending response for Streamable HTTP)');
  }

  close(): void {
    this.closed = true;

    for (const [id, res] of this.pendingResponses) {
      if (!res.headersSent) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'server_closing' }));
      }
      this.pendingResponses.delete(id);
    }

    this.closeHandler?.();
  }
}
