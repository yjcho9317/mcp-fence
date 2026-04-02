/**
 * stdio transport for MCP JSON-RPC messages.
 *
 * MCP stdio transport uses newline-delimited JSON (NDJSON):
 * - Each JSON-RPC message is a single line terminated by \n
 * - stdin/stdout carry MCP protocol messages
 * - stderr is used for logging (not protocol)
 *
 * This module provides a reader that parses incoming NDJSON streams
 * and a writer that serializes messages back to NDJSON.
 */

import { EventEmitter } from 'node:events';
import type { Readable, Writable } from 'node:stream';
import type { JsonRpcMessage } from '../types.js';
import { ParseError, TransportError } from '../errors.js';
import { createLogger } from '../logger.js';

const log = createLogger('transport');

/**
 * Parse a raw JSON string into a JsonRpcMessage.
 * Validates the basic JSON-RPC 2.0 structure.
 */
export function parseJsonRpcMessage(raw: string): JsonRpcMessage {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ParseError(`Invalid JSON: ${raw.slice(0, 100)}`);
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new ParseError('JSON-RPC message must be an object');
  }

  const msg = parsed as Record<string, unknown>;

  if (msg['jsonrpc'] !== '2.0') {
    throw new ParseError(`Invalid jsonrpc version: ${String(msg['jsonrpc'])}`);
  }

  return parsed as JsonRpcMessage;
}

/**
 * Serialize a JsonRpcMessage to a newline-terminated string.
 */
export function serializeMessage(message: JsonRpcMessage): string {
  return JSON.stringify(message) + '\n';
}

/**
 * Reads NDJSON messages from a readable stream.
 * Emits 'message' for each parsed JSON-RPC message.
 */
export class StdioReader extends EventEmitter {
  private buffer = '';

  constructor(private readonly input: Readable) {
    super();
    this.attach();
  }

  private attach(): void {
    this.input.setEncoding('utf-8');

    this.input.on('data', (chunk: string) => {
      this.buffer += chunk;
      this.processBuffer();
    });

    this.input.on('end', () => {
      // Process any remaining data in buffer
      if (this.buffer.trim().length > 0) {
        this.processLine(this.buffer.trim());
      }
      this.emit('close');
    });

    this.input.on('error', (err: Error) => {
      this.emit('error', new TransportError(`Input stream error: ${err.message}`));
    });
  }

  private processBuffer(): void {
    const lines = this.buffer.split('\n');
    // Keep the last (potentially incomplete) line in the buffer
    this.buffer = lines.pop() ?? '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.length > 0) {
        this.processLine(trimmed);
      }
    }
  }

  private processLine(line: string): void {
    try {
      const message = parseJsonRpcMessage(line);
      this.emit('message', message);
    } catch (err) {
      log.warn(`Failed to parse message: ${line.slice(0, 200)}`);
      this.emit('error', err instanceof Error ? err : new ParseError(String(err)));
    }
  }
}

/**
 * Writes NDJSON messages to a writable stream.
 */
export class StdioWriter {
  constructor(private readonly output: Writable) {}

  /** Write a JSON-RPC message to the output stream. */
  write(message: JsonRpcMessage): boolean {
    const data = serializeMessage(message);
    return this.output.write(data);
  }

  /** End the output stream. */
  end(): void {
    this.output.end();
  }
}
