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

export interface FenceConfig {
  /** Operation mode: monitor (log only) or enforce (block) */
  mode: OperationMode;
  /** Logging configuration */
  log: LogConfig;
  /** Detection thresholds */
  detection: DetectionConfig;
  /** Policy rules for tool access control */
  policy: PolicyConfig;
}

export interface PolicyConfig {
  /** Default action when no rule matches */
  defaultAction: 'allow' | 'deny';
  /** Ordered list of policy rules */
  rules: PolicyRule[];
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
