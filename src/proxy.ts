/**
 * MCP Bidirectional Proxy.
 *
 * This is the core of mcp-fence. It sits between MCP client and server,
 * intercepting all messages in both directions.
 *
 * Data flow:
 *   MCP Client (stdin) → proxy → [scan] → MCP Server (child stdin)
 *   MCP Server (child stdout) → proxy → [scan] → MCP Client (stdout)
 *
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { StdioReader, StdioWriter } from './transport/stdio.js';
import type { JsonRpcMessage, Scanner, AuditLogger, ScanResult, FenceConfig, Finding } from './types.js';
import { HashPinChecker } from './integrity/hash-pin.js';
import { PolicyEngine } from './policy/engine.js';
import { ProxyError } from './errors.js';
import { createLogger } from './logger.js';

const log = createLogger('proxy');

export interface ProxyOptions {
  /** Command to spawn the MCP server */
  serverCommand: string;
  /** Arguments for the server command */
  serverArgs: string[];
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
  private serverProcess: ChildProcess | null = null;
  private clientReader: StdioReader | null = null;
  private clientWriter: StdioWriter | null = null;
  private serverReader: StdioReader | null = null;
  private serverWriter: StdioWriter | null = null;
  private running = false;

  constructor(private readonly options: ProxyOptions) {}

  /**
   * Start the proxy: spawn the MCP server and begin relaying messages.
   */
  async start(): Promise<void> {
    if (this.running) {
      throw new ProxyError('Proxy is already running');
    }

    const { serverCommand, serverArgs, config } = this.options;

    log.info(`Starting proxy in ${config.mode} mode`);
    log.info(`Spawning MCP server: ${serverCommand} ${serverArgs.join(' ')}`);

    this.serverProcess = spawn(serverCommand, serverArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env },
    });

    if (!this.serverProcess.stdin || !this.serverProcess.stdout) {
      throw new ProxyError('Failed to get server process stdio streams');
    }

    this.serverProcess.stderr?.on('data', (chunk: Buffer) => {
      process.stderr.write(chunk);
    });

    this.clientReader = new StdioReader(process.stdin);
    this.serverWriter = new StdioWriter(this.serverProcess.stdin);

    this.serverReader = new StdioReader(this.serverProcess.stdout);
    this.clientWriter = new StdioWriter(process.stdout);

    this.clientReader.on('message', (message: JsonRpcMessage) => {
      void this.handleClientMessage(message);
    });

    this.clientReader.on('error', (err: Error) => {
      log.warn(`Client transport error: ${err.message}`);
    });

    this.serverReader.on('message', (message: JsonRpcMessage) => {
      void this.handleServerMessage(message);
    });

    this.serverReader.on('error', (err: Error) => {
      log.warn(`Server transport error: ${err.message}`);
    });

    this.serverProcess.on('exit', (code, signal) => {
      log.info(`MCP server exited (code: ${code}, signal: ${signal})`);
      this.shutdown();
    });

    this.serverProcess.on('error', (err: Error) => {
      log.error('MCP server process error', err);
      this.shutdown();
    });

    this.clientReader.on('close', () => {
      log.info('Client disconnected');
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
      const policyFindings = this.options.policyEngine.evaluate(message);
      if (policyFindings.length > 0) {
        result.findings.push(...policyFindings);
        result.decision = 'block';
        result.score = Math.max(result.score, 0.9);
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
        this.clientWriter?.write(blockResp);
      }
      return;
    }

    if (result.decision === 'warn') {
      log.warn(`WARNING in request: ${result.findings.map((f) => f.ruleId).join(', ')}`);
    }

    this.serverWriter?.write(message);
  }

  /**
   * Handle a message from the MCP server (response direction).
   */
  private async handleServerMessage(message: JsonRpcMessage): Promise<void> {
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
        this.clientWriter?.write(blockResp);
      }
      return;
    }

    if (result.decision === 'warn') {
      log.warn(`WARNING in response: ${result.findings.map((f) => f.ruleId).join(', ')}`);
    }

    this.clientWriter?.write(message);
  }

  /**
   * Gracefully shut down the proxy.
   */
  shutdown(): void {
    if (!this.running) return;
    this.running = false;

    log.info('Shutting down proxy...');

    if (this.serverProcess && !this.serverProcess.killed) {
      this.serverProcess.kill('SIGTERM');

      // Force kill after 5 seconds
      setTimeout(() => {
        if (this.serverProcess && !this.serverProcess.killed) {
          this.serverProcess.kill('SIGKILL');
        }
      }, 5000);
    }

    this.clientWriter?.end();
    log.info('Proxy shut down');
  }

  /** Whether the proxy is currently running. */
  get isRunning(): boolean {
    return this.running;
  }
}
