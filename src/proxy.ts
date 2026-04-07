/**
 * MCP Bidirectional Proxy.
 *
 * This is the core of mcp-fence. It sits between MCP client and server,
 * intercepting all messages in both directions.
 *
 * Data flow:
 *   MCP Client → Transport → [scan] → Transport → MCP Server
 *   MCP Server → Transport → [scan] → Transport → MCP Client
 *
 * The proxy is transport-agnostic — it works with any Transport implementation
 * (stdio, SSE, HTTP). Transport creation and process lifecycle are handled
 * by Runner classes (e.g., StdioRunner).
 */

import type { Transport } from './transport/types.js';
import type { JsonRpcMessage, Scanner, AuditLogger, ScanResult, FenceConfig, Finding, DataFlowConfig } from './types.js';
import { HashPinChecker } from './integrity/hash-pin.js';
import { PolicyEngine } from './policy/engine.js';
import { SessionTracker } from './policy/session.js';
import { evaluateDataFlow } from './policy/data-flow.js';
import { checkContextBudget } from './detection/context-budget.js';
import { ProxyError } from './errors.js';
import { createLogger } from './logger.js';

const log = createLogger('proxy');

export interface ProxyOptions {
  /** Transport connected to the MCP client */
  clientTransport: Transport;
  /** Transport connected to the MCP server */
  serverTransport: Transport;
  /** Configuration */
  config: FenceConfig;
  /** Optional content scanner */
  scanner?: Scanner;
  /** Optional hash pin checker for rug-pull detection */
  hashPinChecker?: HashPinChecker;
  /** Optional policy engine for tool access control */
  policyEngine?: PolicyEngine;
  /** Optional audit logger */
  auditLogger?: AuditLogger;
}

/**
 * The passthrough scan result used when no scanner is configured.
 */
function passthroughResult(direction: 'request' | 'response'): ScanResult {
  return {
    decision: 'allow',
    findings: [],
    score: 0,
    direction,
    timestamp: Date.now(),
  };
}

/**
 * Create a JSON-RPC error response for blocked messages.
 */
function createBlockResponse(
  originalMessage: JsonRpcMessage,
  result: ScanResult,
): JsonRpcMessage | null {
  // Only block request messages that have an id (need a response)
  if (!('id' in originalMessage) || originalMessage.id == null) {
    return null;
  }

  return {
    jsonrpc: '2.0',
    id: originalMessage.id,
    error: {
      code: -32600,
      message: `[mcp-fence] Blocked: ${result.findings.map((f) => f.message).join('; ')}`,
    },
  };
}

export class McpProxy {
  private readonly clientTransport: Transport;
  private readonly serverTransport: Transport;
  private readonly sessionTracker = new SessionTracker();
  private running = false;

  constructor(private readonly options: ProxyOptions) {
    this.clientTransport = options.clientTransport;
    this.serverTransport = options.serverTransport;
  }

  /**
   * Start the proxy: wire up transports and begin relaying messages.
   */
  async start(): Promise<void> {
    if (this.running) {
      throw new ProxyError('Proxy is already running');
    }

    const { config } = this.options;

    log.info(`Starting proxy in ${config.mode} mode`);

    this.clientTransport.onMessage((message: JsonRpcMessage) => {
      void this.handleClientMessage(message);
    });

    this.clientTransport.onError((err: Error) => {
      log.warn(`Client transport error: ${err.message}`);
    });

    this.serverTransport.onMessage((message: JsonRpcMessage) => {
      void this.handleServerMessage(message);
    });

    this.serverTransport.onError((err: Error) => {
      log.warn(`Server transport error: ${err.message}`);
    });

    this.clientTransport.onClose(() => {
      log.info('Client disconnected');
      this.sessionTracker.reset();
      this.shutdown();
    });

    this.running = true;
    log.info('Proxy is running — bidirectional relay active');
  }

  /**
   * Handle a message from the MCP client (request direction).
   */
  private async handleClientMessage(message: JsonRpcMessage): Promise<void> {
    const method = 'method' in message ? message.method : undefined;
    log.debug(`→ Client message: ${method ?? 'response'}`);

    // Scan the request (content-based detection)
    const result = this.options.scanner
      ? await this.options.scanner.scan(message, 'request')
      : passthroughResult('request');

    // Policy check (tool access control)
    if (this.options.policyEngine) {
      const policyFindings = await this.options.policyEngine.evaluate(message);
      if (policyFindings.length > 0) {
        result.findings.push(...policyFindings);
        result.decision = 'block';
        result.score = Math.max(result.score, 0.9);
      }
    }

    // Data flow check (cross-tool data flow policy)
    const toolName = this.extractToolName(message);
    if (toolName) {
      const dataFlowConfig = this.options.config.dataFlow;
      if (dataFlowConfig?.enabled) {
        const dfFindings = evaluateDataFlow(
          toolName,
          this.sessionTracker.getPreviousTools(),
          dataFlowConfig,
        );
        if (dfFindings.length > 0) {
          result.findings.push(...dfFindings);
          result.decision = 'block';
          result.score = Math.max(result.score, 0.95);
        }
      }
    }

    // Audit log
    if (this.options.auditLogger) {
      await this.options.auditLogger.log(message, result);
    }

    // Decision
    if (result.decision === 'block' && this.options.config.mode === 'enforce') {
      log.warn(`BLOCKED request: ${result.findings.map((f) => f.ruleId).join(', ')}`);
      const blockResp = createBlockResponse(message, result);
      if (blockResp) {
        this.clientTransport.send(blockResp);
      }
      return;
    }

    if (result.decision === 'warn') {
      log.warn(`WARNING in request: ${result.findings.map((f) => f.ruleId).join(', ')}`);
    }

    // Record tool call AFTER forward decision — blocked calls don't enter history
    if (toolName) {
      this.sessionTracker.recordToolCall(toolName);
    }

    this.serverTransport.send(message);
  }

  /**
   * Handle a message from the MCP server (response direction).
   */
  private async handleServerMessage(originalMessage: JsonRpcMessage): Promise<void> {
    let message = originalMessage;
    const hasResult = 'result' in message;
    const hasError = 'error' in message;
    log.debug(`← Server message: ${hasResult ? 'result' : hasError ? 'error' : 'notification'}`);

    // Scan the response
    const result = this.options.scanner
      ? await this.options.scanner.scan(message, 'response')
      : passthroughResult('response');

    // Check for rug-pull (tool description hash changes)
    if (this.options.hashPinChecker) {
      const rugPullFindings = this.options.hashPinChecker.check(message);
      if (rugPullFindings.length > 0) {
        result.findings.push(...rugPullFindings);
        // Recalculate decision: rug-pull findings are always critical
        result.decision = 'block';
        result.score = Math.max(result.score, 0.98);
      }

      // Server-level schema pinning (TOFU)
      const serverSchemaFindings = this.options.hashPinChecker.checkServerSchema(message);
      if (serverSchemaFindings.length > 0) {
        result.findings.push(...serverSchemaFindings);
        result.decision = 'block';
        result.score = Math.max(result.score, 0.95);
      }
    }

    // Context budget check
    const budgetConfig = this.options.config.contextBudget;
    if (budgetConfig?.enabled) {
      const budgetResult = checkContextBudget(message, budgetConfig);
      if (budgetResult.exceeded && budgetResult.finding) {
        result.findings.push(budgetResult.finding);

        if (budgetConfig.truncateAction === 'block') {
          result.decision = 'block';
          result.score = Math.max(result.score, 0.9);
        } else if (budgetConfig.truncateAction === 'truncate' && budgetResult.truncatedMessage) {
          // Replace message with truncated version and forward
          message = budgetResult.truncatedMessage;
        }
        // 'warn' action: finding is added but message passes through unchanged
      }
    }

    // Audit log
    if (this.options.auditLogger) {
      await this.options.auditLogger.log(message, result);
    }

    // Decision
    if (result.decision === 'block' && this.options.config.mode === 'enforce') {
      log.warn(`BLOCKED response: ${result.findings.map((f) => f.ruleId).join(', ')}`);
      const blockResp = createBlockResponse(message, result);
      if (blockResp) {
        this.clientTransport.send(blockResp);
      }
      return;
    }

    if (result.decision === 'warn') {
      log.warn(`WARNING in response: ${result.findings.map((f) => f.ruleId).join(', ')}`);
    }

    this.clientTransport.send(message);
  }

  /**
   * Gracefully shut down the proxy.
   */
  shutdown(): void {
    if (!this.running) return;
    this.running = false;

    log.info('Shutting down proxy...');

    this.clientTransport.close();
    this.serverTransport.close();

    log.info('Proxy shut down');
  }

  /**
   * Extract tool name from a tools/call request message.
   */
  private extractToolName(message: JsonRpcMessage): string | null {
    if (!('method' in message)) return null;
    if (message.method !== 'tools/call') return null;
    if (!('params' in message) || message.params == null) return null;

    const params = message.params as Record<string, unknown>;
    const name = params['name'];
    return typeof name === 'string' ? name : null;
  }

  /** Whether the proxy is currently running. */
  get isRunning(): boolean {
    return this.running;
  }
}
