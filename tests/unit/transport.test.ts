import { describe, it, expect } from 'vitest';
import { PassThrough } from 'node:stream';
import {
  parseJsonRpcMessage,
  serializeMessage,
  StdioReader,
  StdioWriter,
} from '../../src/transport/stdio.js';
import type { JsonRpcMessage } from '../../src/types.js';

// ─── parseJsonRpcMessage ───

describe('parseJsonRpcMessage', () => {
  it('should parse a valid JSON-RPC request', () => {
    const raw = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}';
    const msg = parseJsonRpcMessage(raw);
    expect(msg).toEqual({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: {},
    });
  });

  it('should parse a valid JSON-RPC response', () => {
    const raw = '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}';
    const msg = parseJsonRpcMessage(raw);
    expect(msg).toEqual({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [] },
    });
  });

  it('should parse a JSON-RPC notification (no id)', () => {
    const raw = '{"jsonrpc":"2.0","method":"notifications/initialized"}';
    const msg = parseJsonRpcMessage(raw);
    expect(msg).toEqual({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });
  });

  it('should throw on invalid JSON', () => {
    expect(() => parseJsonRpcMessage('not json')).toThrow('Invalid JSON');
  });

  it('should throw on non-object JSON', () => {
    expect(() => parseJsonRpcMessage('"just a string"')).toThrow('must be an object');
  });

  it('should throw on wrong jsonrpc version', () => {
    expect(() => parseJsonRpcMessage('{"jsonrpc":"1.0","id":1,"method":"test"}')).toThrow(
      'Invalid jsonrpc version',
    );
  });

  it('should throw on null JSON value', () => {
    expect(() => parseJsonRpcMessage('null')).toThrow('must be an object');
  });

  it('should throw on array JSON value', () => {
    expect(() => parseJsonRpcMessage('[1,2,3]')).toThrow();
  });

  it('should throw when jsonrpc field is missing entirely', () => {
    expect(() => parseJsonRpcMessage('{"id":1,"method":"test"}')).toThrow('Invalid jsonrpc version');
  });

  it('should parse messages with unicode content in params', () => {
    const raw = '{"jsonrpc":"2.0","id":1,"method":"test","params":{"text":"\\u4f60\\u597d\\u4e16\\u754c"}}';
    const msg = parseJsonRpcMessage(raw);
    expect((msg as { params: { text: string } }).params.text).toBe('\u4f60\u597d\u4e16\u754c');
  });

  it('should parse messages with emoji content', () => {
    const raw = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'test', params: { text: 'hello \ud83d\ude00\ud83c\udf1f' } });
    const msg = parseJsonRpcMessage(raw);
    expect(msg).toBeDefined();
  });

  it('should parse an error response', () => {
    const raw = '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}';
    const msg = parseJsonRpcMessage(raw);
    expect((msg as { error: { code: number } }).error.code).toBe(-32601);
  });

  it('should parse a response with null id', () => {
    const raw = '{"jsonrpc":"2.0","id":null,"result":true}';
    const msg = parseJsonRpcMessage(raw);
    expect((msg as { id: null }).id).toBeNull();
  });

  it('should parse a response with string id', () => {
    const raw = '{"jsonrpc":"2.0","id":"abc-123","method":"test"}';
    const msg = parseJsonRpcMessage(raw);
    expect((msg as { id: string }).id).toBe('abc-123');
  });
});

// ─── serializeMessage ───

describe('serializeMessage', () => {
  it('should serialize a message with trailing newline', () => {
    const msg: JsonRpcMessage = { jsonrpc: '2.0', id: 1, method: 'test', params: {} };
    const result = serializeMessage(msg);
    expect(result).toBe('{"jsonrpc":"2.0","id":1,"method":"test","params":{}}\n');
    expect(result.endsWith('\n')).toBe(true);
  });

  it('should serialize a response message', () => {
    const msg: JsonRpcMessage = { jsonrpc: '2.0', id: 1, result: { tools: [] } };
    const result = serializeMessage(msg);
    expect(result).toContain('"result"');
    expect(result.endsWith('\n')).toBe(true);
  });

  it('should serialize messages with unicode content correctly', () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'test',
      params: { text: '\u6d4b\u8bd5\u4e2d\u6587' },
    };
    const result = serializeMessage(msg);
    const parsed = JSON.parse(result);
    expect(parsed.params.text).toBe('\u6d4b\u8bd5\u4e2d\u6587');
  });
});

// ─── StdioReader ───

describe('StdioReader', () => {
  it('should emit messages from newline-delimited JSON', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    const messages: JsonRpcMessage[] = [];
    reader.on('message', (msg: JsonRpcMessage) => messages.push(msg));

    input.write('{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n');
    input.write('{"jsonrpc":"2.0","id":2,"method":"tools/call"}\n');

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(messages).toHaveLength(2);
    expect((messages[0] as { method: string }).method).toBe('tools/list');
    expect((messages[1] as { method: string }).method).toBe('tools/call');

    input.end();
  });

  it('should handle chunked input correctly', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    const messages: JsonRpcMessage[] = [];
    reader.on('message', (msg: JsonRpcMessage) => messages.push(msg));

    // Send a message split across two chunks
    input.write('{"jsonrpc":"2.0","id":1,');
    input.write('"method":"test"}\n');

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(messages).toHaveLength(1);
    expect((messages[0] as { method: string }).method).toBe('test');

    input.end();
  });

  it('should emit error on invalid JSON and continue', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    const messages: JsonRpcMessage[] = [];
    const errors: Error[] = [];
    reader.on('message', (msg: JsonRpcMessage) => messages.push(msg));
    reader.on('error', (err: Error) => errors.push(err));

    input.write('not valid json\n');
    input.write('{"jsonrpc":"2.0","id":1,"method":"valid"}\n');

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(errors).toHaveLength(1);
    expect(messages).toHaveLength(1);

    input.end();
  });

  it('should emit close when input ends', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    let closed = false;
    reader.on('close', () => {
      closed = true;
    });

    input.end();

    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(closed).toBe(true);
  });

  // ─── New: Batch JSON-RPC messages ───

  it('should parse batch messages (multiple messages in a single chunk)', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    const messages: JsonRpcMessage[] = [];
    reader.on('message', (msg: JsonRpcMessage) => messages.push(msg));

    // Three messages in a single write
    const batch =
      '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' +
      '{"jsonrpc":"2.0","id":2,"method":"tools/call"}\n' +
      '{"jsonrpc":"2.0","id":3,"method":"resources/list"}\n';
    input.write(batch);

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(messages).toHaveLength(3);
    expect((messages[0] as { id: number }).id).toBe(1);
    expect((messages[1] as { id: number }).id).toBe(2);
    expect((messages[2] as { id: number }).id).toBe(3);

    input.end();
  });

  // ─── New: Unicode / multibyte ───

  it('should handle messages with unicode/multibyte characters', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    const messages: JsonRpcMessage[] = [];
    reader.on('message', (msg: JsonRpcMessage) => messages.push(msg));

    const msg = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { text: '\u4f60\u597d\u4e16\u754c \ud83d\ude80 \uc548\ub155\ud558\uc138\uc694' },
    });
    input.write(msg + '\n');

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(messages).toHaveLength(1);
    const params = (messages[0] as { params: { text: string } }).params;
    expect(params.text).toContain('\u4f60\u597d');
    expect(params.text).toContain('\uc548\ub155');

    input.end();
  });

  // ─── New: Large message ───

  it('should handle a large message', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    const messages: JsonRpcMessage[] = [];
    reader.on('message', (msg: JsonRpcMessage) => messages.push(msg));

    // ~100KB payload
    const bigPayload = 'x'.repeat(100_000);
    const msg = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { data: bigPayload },
    });
    input.write(msg + '\n');

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(messages).toHaveLength(1);
    expect(
      (messages[0] as { params: { data: string } }).params.data.length,
    ).toBe(100_000);

    input.end();
  });

  // ─── New: Empty lines between messages ───

  it('should skip empty lines between messages', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    const messages: JsonRpcMessage[] = [];
    const errors: Error[] = [];
    reader.on('message', (msg: JsonRpcMessage) => messages.push(msg));
    reader.on('error', (err: Error) => errors.push(err));

    input.write('{"jsonrpc":"2.0","id":1,"method":"a"}\n');
    input.write('\n');
    input.write('  \n');
    input.write('\n');
    input.write('{"jsonrpc":"2.0","id":2,"method":"b"}\n');

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(messages).toHaveLength(2);
    // Empty lines should not cause parse errors
    expect(errors).toHaveLength(0);

    input.end();
  });

  // ─── New: Partial JSON across multiple chunks ───

  it('should reassemble a message split across three chunks', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    const messages: JsonRpcMessage[] = [];
    reader.on('message', (msg: JsonRpcMessage) => messages.push(msg));

    input.write('{"jsonrpc":');
    input.write('"2.0","id":1,');
    input.write('"method":"split_test"}\n');

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(messages).toHaveLength(1);
    expect((messages[0] as { method: string }).method).toBe('split_test');

    input.end();
  });

  it('should handle partial JSON at stream end (remaining buffer)', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    const messages: JsonRpcMessage[] = [];
    const errors: Error[] = [];
    reader.on('message', (msg: JsonRpcMessage) => messages.push(msg));
    reader.on('error', (err: Error) => errors.push(err));

    // Write a complete message followed by an incomplete one, then end the stream
    input.write('{"jsonrpc":"2.0","id":1,"method":"first"}\n');
    // This message has no newline and the stream ends -- the reader should
    // attempt to process the leftover buffer on 'end'
    input.write('{"jsonrpc":"2.0","id":2,"method":"second"}');
    input.end();

    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(messages).toHaveLength(2);
    expect((messages[1] as { method: string }).method).toBe('second');
  });

  // ─── New: Stream error forwarding ───

  it('should emit TransportError when the input stream errors', async () => {
    const input = new PassThrough();
    const reader = new StdioReader(input);

    const errors: Error[] = [];
    reader.on('error', (err: Error) => errors.push(err));

    input.emit('error', new Error('stream broken'));

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(errors).toHaveLength(1);
    expect(errors[0]!.message).toContain('stream broken');
  });
});

// ─── StdioWriter ───

describe('StdioWriter', () => {
  it('should write serialized messages to output', () => {
    const output = new PassThrough();
    const writer = new StdioWriter(output);

    const chunks: string[] = [];
    output.on('data', (chunk: Buffer) => chunks.push(chunk.toString()));

    const msg: JsonRpcMessage = { jsonrpc: '2.0', id: 1, method: 'test' };
    writer.write(msg);

    expect(chunks.join('')).toBe('{"jsonrpc":"2.0","id":1,"method":"test"}\n');
  });

  it('should write multiple messages sequentially', () => {
    const output = new PassThrough();
    const writer = new StdioWriter(output);

    const chunks: string[] = [];
    output.on('data', (chunk: Buffer) => chunks.push(chunk.toString()));

    writer.write({ jsonrpc: '2.0', id: 1, method: 'a' });
    writer.write({ jsonrpc: '2.0', id: 2, method: 'b' });

    const combined = chunks.join('');
    const lines = combined.split('\n').filter((l) => l.length > 0);
    expect(lines).toHaveLength(2);
  });

  it('should end the output stream', async () => {
    const output = new PassThrough();
    const writer = new StdioWriter(output);

    const finishPromise = new Promise<void>((resolve) => {
      output.on('finish', () => resolve());
    });

    writer.end();
    await finishPromise;
    expect(output.writableEnded).toBe(true);
  });
});
