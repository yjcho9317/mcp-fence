/**
 * mcp-fence public API.
 *
 * This module exports types and classes for programmatic usage.
 * CLI usage goes through cli.ts.
 */

export { McpProxy } from './proxy.js';
export type { ProxyOptions } from './proxy.js';
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
export { McpFenceError, ConfigError, TransportError, ProxyError, ParseError } from './errors.js';

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
} from './types.js';
