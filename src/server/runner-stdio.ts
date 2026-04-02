/**
 * Stdio mode runner.
 *
 * Handles child process spawning and lifecycle, creates StdioTransport
 * instances for client and server sides, and wires them into McpProxy.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { StdioTransport } from '../transport/stdio-transport.js';
import { McpProxy, type ProxyOptions } from '../proxy.js';
import { ProxyError } from '../errors.js';
import { createLogger } from '../logger.js';
import type { FenceConfig, Scanner, AuditLogger } from '../types.js';
import type { HashPinChecker } from '../integrity/hash-pin.js';
import type { PolicyEngine } from '../policy/engine.js';

const log = createLogger('runner-stdio');

export interface StdioRunnerOptions {
  serverCommand: string;
  serverArgs: string[];
  config: FenceConfig;
  scanner?: Scanner;
  hashPinChecker?: HashPinChecker;
  policyEngine?: PolicyEngine;
  auditLogger?: AuditLogger;
}

export class StdioRunner {
  private serverProcess: ChildProcess | null = null;
  private proxy: McpProxy | null = null;

  constructor(private readonly options: StdioRunnerOptions) {}

  /**
   * Spawn the MCP server, create transports, and start the proxy.
   */
  async start(): Promise<void> {
    const { serverCommand, serverArgs } = this.options;

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

    const clientTransport = new StdioTransport(process.stdin, process.stdout);
    const serverTransport = new StdioTransport(this.serverProcess.stdout, this.serverProcess.stdin);

    const proxyOptions: ProxyOptions = {
      clientTransport,
      serverTransport,
      config: this.options.config,
      scanner: this.options.scanner,
      hashPinChecker: this.options.hashPinChecker,
      policyEngine: this.options.policyEngine,
      auditLogger: this.options.auditLogger,
    };

    this.proxy = new McpProxy(proxyOptions);

    this.serverProcess.on('exit', (code, signal) => {
      log.info(`MCP server exited (code: ${code}, signal: ${signal})`);
      this.shutdown();
    });

    this.serverProcess.on('error', (err: Error) => {
      log.error('MCP server process error', err);
      this.shutdown();
    });

    await this.proxy.start();
  }

  /**
   * Gracefully shut down the runner: stop the proxy and kill the child process.
   */
  shutdown(): void {
    this.proxy?.shutdown();

    if (this.serverProcess && !this.serverProcess.killed) {
      this.serverProcess.kill('SIGTERM');

      setTimeout(() => {
        if (this.serverProcess && !this.serverProcess.killed) {
          this.serverProcess.kill('SIGKILL');
        }
      }, 5000);
    }
  }
}
