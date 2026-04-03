/**
 * SSE transport implementation for MCP.
 *
 * MCP SSE protocol uses two channels:
 * - GET /sse: Server-to-client event stream
 * - POST /message: Client-to-server JSON-RPC messages
 *
 * SseClientTransport: connects to an upstream MCP SSE server (outbound).
 * SseServerTransport: accepts SSE connections from MCP clients (inbound).
 */

import { EventEmitter } from 'node:events';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { JsonRpcMessage } from '../types.js';
import type { Transport } from './types.js';
import { SseParser, formatSseEvent } from './sse-parser.js';
import { parseJsonRpcMessage } from './stdio.js';
import { createLogger } from '../logger.js';
import { TransportError } from '../errors.js';

const log = createLogger('transport:sse');

/** Maximum allowed request body size in bytes (1 MB). */
const MAX_REQUEST_BODY_BYTES = 1_048_576;

/**
 * Connects to an upstream MCP server via SSE.
 * Opens a GET request to receive events and sends messages via POST.
 */
export class SseClientTransport implements Transport {
  private messageHandler: ((msg: JsonRpcMessage) => void) | null = null;
  private errorHandler: ((err: Error) => void) | null = null;
  private closeHandler: (() => void) | null = null;
  private parser: SseParser | null = null;
  private abortController: AbortController | null = null;
  private messageEndpoint: string | null = null;
  private closed = false;

  constructor(private readonly upstreamUrl: string) {}

  /**
   * Open the SSE connection to the upstream server.
   * Must be called before the transport can receive messages.
   */
  async connect(): Promise<void> {
    this.abortController = new AbortController();

    const sseUrl = this.upstreamUrl.replace(/\/$/, '') + '/sse';
    log.info(`Connecting to upstream SSE: ${sseUrl}`);

    const response = await fetch(sseUrl, {
      headers: { 'Accept': 'text/event-stream' },
      signal: this.abortController.signal,
    });

    if (!response.ok) {
      throw new TransportError(`Upstream SSE connection failed: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      throw new TransportError('Upstream SSE response has no body');
    }

    const stream = this.readableStreamToNodeReadable(response.body);
    // Suppress errors on the underlying stream during abort
    stream.on('error', (err: Error) => {
      if (!this.closed) {
        this.errorHandler?.(new TransportError(`SSE stream error: ${err.message}`));
      }
    });
    this.parser = new SseParser(stream);

    this.parser.on('event', (event: { type: string; data: string }) => {
      if (event.type === 'endpoint') {
        // The server sends the POST endpoint URL via an "endpoint" event
        this.messageEndpoint = this.resolveEndpoint(event.data);
        log.debug(`Upstream message endpoint: ${this.messageEndpoint}`);
        return;
      }

      if (event.type === 'message') {
        try {
          const msg = parseJsonRpcMessage(event.data);
          this.messageHandler?.(msg);
        } catch (err) {
          this.errorHandler?.(err instanceof Error ? err : new Error(String(err)));
        }
      }
    });

    this.parser.on('error', (err: Error) => {
      if (!this.closed) {
        this.errorHandler?.(new TransportError(`SSE stream error: ${err.message}`));
      }
    });

    this.parser.on('close', () => {
      if (!this.closed) {
        this.closeHandler?.();
      }
    });
  }

  onMessage(handler: (msg: JsonRpcMessage) => void): void {
    this.messageHandler = handler;
  }

  onError(handler: (err: Error) => void): void {
    this.errorHandler = handler;
  }

  onClose(handler: () => void): void {
    this.closeHandler = handler;
  }

  send(msg: JsonRpcMessage): void {
    if (!this.messageEndpoint) {
      this.errorHandler?.(new TransportError('No message endpoint available from upstream'));
      return;
    }

    const body = JSON.stringify(msg);

    fetch(this.messageEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: this.abortController?.signal,
    }).catch((err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      if (!this.closed) {
        this.errorHandler?.(new TransportError(`Failed to POST message to upstream: ${message}`));
      }
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.parser?.removeAllListeners();
    try {
      this.abortController?.abort();
    } catch {
      // Abort may throw if the signal is already aborted
    }
  }

  private resolveEndpoint(path: string): string {
    // If the path is absolute, combine with the upstream origin
    if (path.startsWith('/')) {
      const url = new URL(this.upstreamUrl);
      return `${url.origin}${path}`;
    }
    // If it's already a full URL, use as-is
    if (path.startsWith('http://') || path.startsWith('https://')) {
      return path;
    }
    return `${this.upstreamUrl.replace(/\/$/, '')}/${path}`;
  }

  /**
   * Convert a web ReadableStream to a Node.js Readable.
   * Uses manual piping to properly handle abort signals without unhandled rejections.
   */
  private readableStreamToNodeReadable(webStream: ReadableStream<Uint8Array>): import('node:stream').Readable {
    const { PassThrough } = require('node:stream') as typeof import('node:stream');
    const passthrough = new PassThrough();
    const reader = webStream.getReader();

    const pump = (): void => {
      reader.read().then(
        ({ done, value }) => {
          if (done) {
            passthrough.end();
            return;
          }
          passthrough.write(value);
          pump();
        },
        (err: unknown) => {
          // Suppress AbortError during intentional close
          if (this.closed) {
            passthrough.end();
            return;
          }
          const message = err instanceof Error ? err.message : String(err);
          passthrough.destroy(new Error(message));
        },
      );
    };

    pump();
    return passthrough;
  }
}

/**
 * Accepts SSE connections from MCP clients.
 * Holds the SSE response stream and receives POST messages.
 */
export class SseServerTransport implements Transport {
  private messageHandler: ((msg: JsonRpcMessage) => void) | null = null;
  private errorHandler: ((err: Error) => void) | null = null;
  private closeHandler: (() => void) | null = null;
  private sseResponse: ServerResponse | null = null;
  private closed = false;
  private _sessionId: string;

  constructor() {
    this._sessionId = crypto.randomUUID();
  }

  get sessionId(): string {
    return this._sessionId;
  }

  /**
   * Attach the SSE response stream. Called when a client connects via GET /sse.
   */
  attachSseResponse(res: ServerResponse): void {
    this.sseResponse = res;

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });

    const endpointEvent = formatSseEvent(
      `/message?sessionId=${this._sessionId}`,
      'endpoint',
    );
    res.write(endpointEvent);

    res.on('close', () => {
      if (!this.closed) {
        this.closed = true;
        this.closeHandler?.();
      }
    });
  }

  /**
   * Handle an incoming POST /message request from the client.
   */
  handlePostMessage(req: IncomingMessage, res: ServerResponse): void {
    const chunks: Buffer[] = [];
    let bodySize = 0;
    let rejected = false;

    req.on('data', (chunk: Buffer) => {
      if (rejected) return;
      bodySize += chunk.length;
      if (bodySize > MAX_REQUEST_BODY_BYTES) {
        rejected = true;
        req.destroy();
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'payload_too_large' }));
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (rejected) return;
      try {
        const body = Buffer.concat(chunks).toString('utf-8');
        const msg = parseJsonRpcMessage(body);
        this.messageHandler?.(msg);
        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'accepted' }));
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

  onMessage(handler: (msg: JsonRpcMessage) => void): void {
    this.messageHandler = handler;
  }

  onError(handler: (err: Error) => void): void {
    this.errorHandler = handler;
  }

  onClose(handler: () => void): void {
    this.closeHandler = handler;
  }

  send(msg: JsonRpcMessage): void {
    if (!this.sseResponse || this.closed) {
      this.errorHandler?.(new TransportError('SSE response not attached or closed'));
      return;
    }

    const event = formatSseEvent(JSON.stringify(msg), 'message');
    this.sseResponse.write(event);
  }

  close(): void {
    this.closed = true;
    if (this.sseResponse && !this.sseResponse.writableEnded) {
      this.sseResponse.end();
    }
  }
}
