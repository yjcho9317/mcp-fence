/**
 * mcp-fence core type definitions.
 *
 * These types define the contracts between modules.
 * Changes to these types must be backward-compatible or coordinated across all consumers.
 */

// ─── JSON-RPC 2.0 Types ───

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number;
  method: string;
  params?: Record<string, unknown> | unknown[];
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: JsonRpcError;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: '2.0';
  method: string;
  params?: Record<string, unknown> | unknown[];
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcResponse | JsonRpcNotification;

// ─── Message Direction ───

export type Direction = 'request' | 'response';

// ─── Scan Pipeline Types (심장부) ───

/**
 * Individual finding from a detection rule.
 */
export interface Finding {
  /** Unique rule identifier (e.g., INJ-001, SEC-003) */
  ruleId: string;
  /** Human-readable description of the finding */
  message: string;
  /** Severity level */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Category of the finding */
  category: FindingCategory;
  /** Confidence score 0.0 ~ 1.0 */
  confidence: number;
  /** Guidance on how to fix the issue */
  remediation?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

export type FindingCategory =
  | 'injection'
  | 'secret'
  | 'rug-pull'
  | 'policy-violation'
  | 'command-injection'
  | 'data-exfiltration';

/**
 * Result of the scan pipeline.
 * This is the core data contract between proxy, detection, and audit modules.
 *
 * DO NOT change this interface without updating:
 * - proxy.ts (produces ScanResult)
 * - audit/logger.ts (consumes ScanResult)
 * - All detection modules (produce Finding[])
 */
export interface ScanResult {
  /** Final decision */
  decision: 'allow' | 'block' | 'warn';
  /** All findings from detection modules */
  findings: Finding[];
  /** Aggregate risk score 0.0 ~ 1.0 */
  score: number;
  /** Which direction was scanned */
  direction: Direction;
  /** Timestamp of the scan */
  timestamp: number;
}

// ─── MCP-Specific Types ───

export interface McpToolInfo {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

// ─── Configuration Types ───

export type OperationMode = 'monitor' | 'enforce';

export interface JwtConfig {
  /** Whether JWT authentication is enabled */
  enabled: boolean;
  /** Shared secret for HS256 */
  secret?: string;
  /** JWKS endpoint URL for RS256 key rotation */
  jwksUrl?: string;
  /** Expected audience claim */
  audience?: string;
  /** Expected issuer claim */
  issuer?: string;
}

export interface ContextBudgetConfig {
  /** Whether context budget checking is enabled */
  enabled: boolean;
  /** Maximum response size in estimated tokens (default: 10000) */
  maxResponseTokens?: number;
  /** Maximum response size in bytes (default: 102400 = 100KB) */
  maxResponseBytes?: number;
  /** Action when budget is exceeded */
  truncateAction: 'warn' | 'truncate' | 'block';
}

export interface FenceConfig {
  /** Operation mode: monitor (log only) or enforce (block) */
  mode: OperationMode;
  /** Logging configuration */
  log: LogConfig;
  /** Detection thresholds */
  detection: DetectionConfig;
  /** Policy rules for tool access control */
  policy: PolicyConfig;
  /** JWT authentication (HTTP transports only) */
  jwt?: JwtConfig;
  /** Cross-server data flow policies */
  dataFlow?: DataFlowConfig;
  /** Context budget limits for server responses */
  contextBudget?: ContextBudgetConfig;
}

export interface OpaConfig {
  /** Whether OPA integration is enabled */
  enabled: boolean;
  /** OPA query endpoint (e.g., "http://localhost:8181/v1/data/mcp/allow") */
  url: string;
  /** Request timeout in milliseconds (default: 5000) */
  timeoutMs?: number;
  /** If OPA is unreachable, allow or deny? (default: false = deny) */
  failOpen?: boolean;
  /** Allow OPA URLs pointing to private/loopback addresses. Defaults to false. */
  allowPrivateNetwork?: boolean;
}

export interface DataFlowRule {
  /** Source tool name or glob pattern */
  from: string;
  /** Destination tool name or glob pattern */
  to: string;
  /** Action: allow or deny */
  action: 'allow' | 'deny';
}

export interface DataFlowConfig {
  /** Whether data flow policy checks are enabled */
  enabled: boolean;
  /** Ordered list of data flow rules */
  rules: DataFlowRule[];
}

export interface PolicyConfig {
  /** Default action when no rule matches */
  defaultAction: 'allow' | 'deny';
  /** Ordered list of policy rules */
  rules: PolicyRule[];
  /** OPA integration for external policy decisions */
  opa?: OpaConfig;
}

export interface PolicyRule {
  /** Tool name or glob pattern (e.g., "read_*", "exec_cmd") */
  tool: string;
  /** Action to take */
  action: 'allow' | 'deny';
  /** Optional argument constraints */
  args?: ArgConstraint[];
}

export interface ArgConstraint {
  /** Argument name to validate */
  name: string;
  /** Deny if argument value matches this pattern */
  denyPattern?: string;
  /** Allow only if argument value matches this pattern */
  allowPattern?: string;
  /** Case-insensitive pattern matching (default: false) */
  caseInsensitive?: boolean;
}

export interface LogConfig {
  level: 'debug' | 'info' | 'warn' | 'error';
  /** Log file path (optional, defaults to stderr) */
  file?: string;
  /** Maximum audit DB size in megabytes (default: 100) */
  maxDbSizeMb?: number;
}

export interface DetectionConfig {
  /** Score threshold to trigger a warning (0.0 ~ 1.0) */
  warnThreshold: number;
  /** Score threshold to trigger a block in enforce mode (0.0 ~ 1.0) */
  blockThreshold: number;
  /** Maximum input size in bytes before truncation */
  maxInputSize: number;
}

// ─── Proxy Types ───

/**
 * Scanner interface — proxy calls this to scan messages.
 * Detection engine, policy engine, and integrity checker all implement this.
 */
export interface Scanner {
  scan(message: JsonRpcMessage, direction: Direction): Promise<ScanResult>;
}

/**
 * Audit logger interface — proxy calls this to record events.
 */
export interface AuditLogger {
  log(message: JsonRpcMessage, result: ScanResult): Promise<void>;
}
