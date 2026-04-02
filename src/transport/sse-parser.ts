/**
 * Server-Sent Events (SSE) stream parser.
 *
 * Parses an incoming byte/text stream following the SSE specification:
 * - Lines starting with "data:" contain event payload
 * - Lines starting with "event:" specify event type
 * - Lines starting with "id:" set the last event ID
 * - Empty lines dispatch the accumulated event
 * - Lines starting with ":" are comments (ignored)
 */

import { EventEmitter } from 'node:events';
import type { Readable } from 'node:stream';

export interface SseEvent {
  type: string;
  data: string;
  id?: string;
}

/**
 * Parses an SSE stream from a Readable (e.g., HTTP response body).
 * Emits 'event' for each complete SSE event and 'close' when the stream ends.
 */
export class SseParser extends EventEmitter {
  private buffer = '';
  private eventType = 'message';
  private dataLines: string[] = [];
  private lastId: string | undefined;

  constructor(stream: Readable) {
    super();
    this.attach(stream);
  }

  private attach(stream: Readable): void {
    stream.setEncoding('utf-8');

    stream.on('data', (chunk: string) => {
      this.buffer += chunk;
      this.processBuffer();
    });

    stream.on('end', () => {
      // Flush any remaining buffered event
      if (this.dataLines.length > 0) {
        this.dispatchEvent();
      }
      this.emit('close');
    });

    stream.on('error', (err: Error) => {
      this.emit('error', err);
    });
  }

  private processBuffer(): void {
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() ?? '';

    for (const rawLine of lines) {
      this.processLine(rawLine);
    }
  }

  private processLine(line: string): void {
    // Empty line dispatches the event
    if (line === '' || line === '\r') {
      if (this.dataLines.length > 0) {
        this.dispatchEvent();
      }
      return;
    }

    // Comment line
    if (line.startsWith(':')) {
      return;
    }

    const colonIndex = line.indexOf(':');
    let field: string;
    let value: string;

    if (colonIndex === -1) {
      field = line;
      value = '';
    } else {
      field = line.slice(0, colonIndex);
      // Strip single leading space after colon per spec
      value = line[colonIndex + 1] === ' '
        ? line.slice(colonIndex + 2)
        : line.slice(colonIndex + 1);
    }

    // Remove trailing \r if present
    if (value.endsWith('\r')) {
      value = value.slice(0, -1);
    }

    switch (field) {
      case 'event':
        this.eventType = value;
        break;
      case 'data':
        this.dataLines.push(value);
        break;
      case 'id':
        this.lastId = value;
        break;
      // 'retry' and unknown fields are ignored
    }
  }

  private dispatchEvent(): void {
    const event: SseEvent = {
      type: this.eventType,
      data: this.dataLines.join('\n'),
      id: this.lastId,
    };

    this.emit('event', event);

    // Reset for next event
    this.eventType = 'message';
    this.dataLines = [];
  }
}

/**
 * Format data as an SSE event string, ready to write to an HTTP response.
 */
export function formatSseEvent(data: string, event?: string, id?: string): string {
  let result = '';
  if (id) result += `id: ${id}\n`;
  if (event) result += `event: ${event}\n`;
  // Split data across multiple "data:" lines if it contains newlines
  const lines = data.split('\n');
  for (const line of lines) {
    result += `data: ${line}\n`;
  }
  result += '\n'; // empty line to dispatch
  return result;
}
