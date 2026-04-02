import type { Readable, Writable } from 'node:stream';
import type { JsonRpcMessage } from '../types.js';
import type { Transport } from './types.js';
import { StdioReader, StdioWriter } from './stdio.js';

/**
 * Wraps StdioReader + StdioWriter into the Transport interface.
 * Used for both the client side (process.stdin/stdout) and
 * the server side (child process stdin/stdout).
 */
export class StdioTransport implements Transport {
  private readonly reader: StdioReader;
  private readonly writer: StdioWriter;

  constructor(input: Readable, output: Writable) {
    this.reader = new StdioReader(input);
    this.writer = new StdioWriter(output);
  }

  onMessage(handler: (msg: JsonRpcMessage) => void): void {
    this.reader.on('message', handler);
  }

  onError(handler: (err: Error) => void): void {
    this.reader.on('error', handler);
  }

  onClose(handler: () => void): void {
    this.reader.on('close', handler);
  }

  send(msg: JsonRpcMessage): void {
    this.writer.write(msg);
  }

  close(): void {
    this.writer.end();
  }
}
