import type { JsonRpcMessage } from '../types.js';

export interface Transport {
  onMessage(handler: (msg: JsonRpcMessage) => void): void;
  onError(handler: (err: Error) => void): void;
  onClose(handler: () => void): void;
  send(msg: JsonRpcMessage): void;
  close(): void;
}
