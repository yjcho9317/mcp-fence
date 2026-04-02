export class McpFenceError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = 'McpFenceError';
  }
}

export class ConfigError extends McpFenceError {
  constructor(message: string) {
    super(message, 'CONFIG_ERROR');
    this.name = 'ConfigError';
  }
}

export class TransportError extends McpFenceError {
  constructor(message: string) {
    super(message, 'TRANSPORT_ERROR');
    this.name = 'TransportError';
  }
}

export class ProxyError extends McpFenceError {
  constructor(message: string) {
    super(message, 'PROXY_ERROR');
    this.name = 'ProxyError';
  }
}

export class ParseError extends McpFenceError {
  constructor(message: string) {
    super(message, 'PARSE_ERROR');
    this.name = 'ParseError';
  }
}

export class AuthError extends McpFenceError {
  constructor(message: string) {
    super(message, 'AUTH_ERROR');
    this.name = 'AuthError';
  }
}
