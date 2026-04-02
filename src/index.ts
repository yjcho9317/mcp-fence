/**
 * mcp-fence public API.
 *
 * This module exports types and classes for programmatic usage.
 * CLI usage goes through cli.ts.
 */

export { McpProxy } from './proxy.js';
export type { ProxyOptions } from './proxy.js';
export type { Transport } from './transport/types.js';
export { StdioTransport } from './transport/stdio-transport.js';
export { SseClientTransport, SseServerTransport } from './transport/sse-transport.js';
export { HttpClientTransport, HttpServerTransport } from './transport/http-transport.js';
export { SseParser, formatSseEvent } from './transport/sse-parser.js';
export type { SseEvent } from './transport/sse-parser.js';
export { StdioRunner } from './server/runner-stdio.js';
export type { StdioRunnerOptions } from './server/runner-stdio.js';
export { HttpRunner } from './server/runner-http.js';
export type { HttpRunnerOptions, HttpTransportMode } from './server/runner-http.js';
export { verifyToken, resetJwksCache } from './auth/jwt.js';
export type { JwtConfig, JwtPayload } from './auth/jwt.js';
export { authenticateRequest, extractBearerToken, jwtGuard, sendUnauthorized } from './auth/middleware.js';
export type { AuthResult } from './auth/middleware.js';
export { loadConfig, generateDefaultConfigYaml, DEFAULT_CONFIG } from './config.js';
export { createLogger, setLogLevel } from './logger.js';
export { DetectionEngine } from './detection/engine.js';
export { HashPinChecker } from './integrity/hash-pin.js';
export { MemoryHashStore } from './integrity/store.js';
export type { HashStore, PinnedTool } from './integrity/store.js';
export { PolicyEngine } from './policy/engine.js';
export { evaluatePolicy } from './policy/local.js';
export { AuditLoggerImpl } from './audit/logger.js';
export { SqliteAuditStore } from './audit/storage.js';
export type { AuditStore, AuditEvent, QueryFilters } from './audit/storage.js';
export { toSarif, sarifToJson } from './audit/sarif.js';
export { McpFenceError, ConfigError, TransportError, ProxyError, ParseError, AuthError } from './errors.js';

export type {
  JsonRpcMessage,
  JsonRpcRequest,
  JsonRpcResponse,
  JsonRpcNotification,
  JsonRpcError,
  Direction,
  Finding,
  FindingCategory,
  ScanResult,
  Scanner,
  AuditLogger,
  McpToolInfo,
  FenceConfig,
  OperationMode,
  LogConfig,
  DetectionConfig,
  PolicyConfig,
  PolicyRule,
  ArgConstraint,
  JwtConfig as JwtConfigType,
} from './types.js';
