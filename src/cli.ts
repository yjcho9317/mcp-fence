/**
 * CLI entry point for mcp-fence.
 *
 * Usage:
 *   mcp-fence start -- npx mcp-server-filesystem /tmp
 *   mcp-fence start --config ./fence.config.yaml -- node server.js
 *   mcp-fence init
 *   mcp-fence scan <file>
 *   mcp-fence scan --text "suspicious content"
 *   mcp-fence logs --since 1h --level warn
 */

import { Command } from 'commander';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { McpProxy } from './proxy.js';
import { DetectionEngine } from './detection/engine.js';
import { HashPinChecker } from './integrity/hash-pin.js';
import { MemoryHashStore } from './integrity/store.js';
import { PolicyEngine } from './policy/engine.js';
import { AuditLoggerImpl } from './audit/logger.js';
import { SqliteAuditStore } from './audit/storage.js';
import { toSarif, sarifToJson } from './audit/sarif.js';
import { ALL_PATTERNS } from './detection/patterns.js';
import { ALL_SECRET_PATTERNS } from './detection/secrets.js';
import { loadConfig, generateDefaultConfigYaml } from './config.js';
import { setLogLevel, createLogger } from './logger.js';

const log = createLogger('cli');

const program = new Command();

program
  .name('mcp-fence')
  .description('The bidirectional firewall for MCP')
  .version('0.1.1');

// ─── start command ───

program
  .command('start')
  .description('Start the MCP security proxy')
  .option('-c, --config <path>', 'Path to config file')
  .option('-m, --mode <mode>', 'Operation mode: monitor or enforce', 'monitor')
  .option('--log-level <level>', 'Log level: debug, info, warn, error', 'info')
  .allowUnknownOption(false)
  .action(async (opts: { config?: string; mode?: string; logLevel?: string }, cmd: Command) => {
    // Everything after -- is the server command
    const serverArgs = cmd.args;
    if (serverArgs.length === 0) {
      log.error('No server command specified. Usage: mcp-fence start -- <server-command>');
      process.exit(1);
    }

    const serverCommand = serverArgs[0]!;
    const serverCommandArgs = serverArgs.slice(1);

    // Load config: CLI flags > env vars > YAML file > defaults
    const config = loadConfig(opts.config);

    // Environment variable overrides
    const envMode = process.env['MCP_FENCE_MODE'];
    if (envMode === 'monitor' || envMode === 'enforce') {
      config.mode = envMode;
    }
    const envLogLevel = process.env['MCP_FENCE_LOG_LEVEL'];
    if (envLogLevel === 'debug' || envLogLevel === 'info' || envLogLevel === 'warn' || envLogLevel === 'error') {
      config.log.level = envLogLevel;
    }

    // CLI flags override env vars and config
    if (opts.mode === 'monitor' || opts.mode === 'enforce') {
      config.mode = opts.mode;
    }

    if (opts.logLevel) {
      const level = opts.logLevel as 'debug' | 'info' | 'warn' | 'error';
      setLogLevel(level);
      config.log.level = level;
    }

    setLogLevel(config.log.level);

    log.info(`mcp-fence v0.1.1 — mode: ${config.mode}`);

    const scanner = new DetectionEngine(config.detection);
    const hashPinChecker = new HashPinChecker(new MemoryHashStore());
    const policyEngine = new PolicyEngine(config.policy);

    // Audit logging — SQLite database in ~/.mcp-fence/
    const homeDir = process.env['HOME'] ?? process.env['USERPROFILE'] ?? process.cwd();
    const dataDir = resolve(homeDir, '.mcp-fence');
    const { mkdirSync } = await import('node:fs');
    try { mkdirSync(dataDir, { recursive: true }); } catch {}
    const dbPath = resolve(dataDir, 'audit.db');
    const auditStore = new SqliteAuditStore(dbPath);
    const auditLogger = new AuditLoggerImpl(auditStore);

    const proxy = new McpProxy({
      serverCommand,
      serverArgs: serverCommandArgs,
      config,
      scanner,
      hashPinChecker,
      policyEngine,
      auditLogger,
    });

    // Graceful shutdown
    const handleShutdown = () => {
      proxy.shutdown();
      auditStore.close();
      process.exit(0);
    };

    process.on('SIGINT', handleShutdown);
    process.on('SIGTERM', handleShutdown);

    try {
      await proxy.start();
    } catch (err) {
      log.error('Failed to start proxy', err);
      process.exit(1);
    }
  });

// ─── status command ───

program
  .command('status')
  .description('Show current configuration and detection capabilities')
  .option('-c, --config <path>', 'Path to config file')
  .action((opts: { config?: string }) => {
    const config = loadConfig(opts.config);

    process.stdout.write('mcp-fence v0.1.1\n\n');
    process.stdout.write(`Mode:              ${config.mode}\n`);
    process.stdout.write(`Log level:         ${config.log.level}\n`);
    process.stdout.write(`Warn threshold:    ${config.detection.warnThreshold}\n`);
    process.stdout.write(`Block threshold:   ${config.detection.blockThreshold}\n`);
    process.stdout.write(`Max input size:    ${config.detection.maxInputSize} bytes\n`);
    process.stdout.write(`Policy default:    ${config.policy.defaultAction}\n`);
    process.stdout.write(`Policy rules:      ${config.policy.rules.length}\n`);

    if (config.policy.rules.length > 0) {
      process.stdout.write('\nPolicy rules:\n');
      for (const rule of config.policy.rules) {
        const argsInfo = rule.args?.length ? ` (${rule.args.length} arg constraint(s))` : '';
        process.stdout.write(`  ${rule.action.padEnd(6)} ${rule.tool}${argsInfo}\n`);
      }
    }

    process.stdout.write(`\nDetection patterns: ${ALL_PATTERNS.length} injection + ${ALL_SECRET_PATTERNS.length} secret\n`);
  });

// ─── init command ───

program
  .command('init')
  .description('Generate a default fence.config.yaml')
  .option('-o, --output <path>', 'Output path', 'fence.config.yaml')
  .action((opts: { output: string }) => {
    const outPath = resolve(process.cwd(), opts.output);

    if (existsSync(outPath)) {
      log.warn(`Config file already exists: ${outPath}`);
      process.exit(1);
    }

    writeFileSync(outPath, generateDefaultConfigYaml(), 'utf-8');
    log.info(`Config file created: ${outPath}`);
  });

// ─── scan command ───

program
  .command('scan [file]')
  .description('Scan a file or text for threats (standalone, no proxy needed)')
  .option('--text <content>', 'Scan a text string instead of a file')
  .option('-d, --direction <dir>', 'Scan direction: request or response', 'request')
  .option('-c, --config <path>', 'Path to config file')
  .option('--format <fmt>', 'Output format: text, json, sarif', 'text')
  .action(async (file: string | undefined, opts: {
    text?: string;
    direction: string;
    config?: string;
    format: string;
  }) => {
    let content: string;

    if (opts.text) {
      content = opts.text;
    } else if (file) {
      const filePath = resolve(process.cwd(), file);
      if (!existsSync(filePath)) {
        log.error(`File not found: ${filePath}`);
        process.exit(1);
      }
      content = readFileSync(filePath, 'utf-8');
    } else {
      // Read from stdin
      const chunks: Buffer[] = [];
      for await (const chunk of process.stdin) {
        chunks.push(chunk as Buffer);
      }
      content = Buffer.concat(chunks).toString('utf-8');
    }

    const config = loadConfig(opts.config);
    const direction = opts.direction === 'response' ? 'response' : 'request';
    const scanner = new DetectionEngine(config.detection);

    // Wrap content in a JSON-RPC message for the scanner
    const message: import('./types.js').JsonRpcMessage = direction === 'request'
      ? { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'scan_input', arguments: { content } } }
      : { jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: content }] } };

    const result = await scanner.scan(message, direction);

    if (opts.format === 'json') {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else if (opts.format === 'sarif') {
      const events = [{
        id: 1,
        timestamp: result.timestamp,
        direction: result.direction,
        method: direction === 'request' ? 'tools/call' : null,
        tool_name: null,
        decision: result.decision,
        score: result.score,
        findings: JSON.stringify(result.findings),
        message: null,
      }];
      process.stdout.write(sarifToJson(toSarif(events)) + '\n');
    } else {
      // Text format
      if (result.findings.length === 0) {
        process.stdout.write('No threats detected.\n');
      } else {
        process.stdout.write(`Decision: ${result.decision} (score: ${result.score.toFixed(2)})\n`);
        process.stdout.write(`Direction: ${result.direction}\n`);
        process.stdout.write(`Findings:\n`);
        for (const f of result.findings) {
          process.stdout.write(`  [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.message}\n`);
        }
      }
    }

    process.exit(result.decision === 'block' ? 1 : 0);
  });

// ─── logs command ───

program
  .command('logs')
  .description('Query audit logs')
  .option('--db <path>', 'Path to audit database')
  .option('--since <duration>', 'Show events since duration (e.g., 1h, 30m, 1d)')
  .option('--level <level>', 'Filter by minimum decision level: allow, warn, block')
  .option('--direction <dir>', 'Filter by direction: request, response')
  .option('--format <fmt>', 'Output format: table, json, sarif', 'table')
  .option('--limit <n>', 'Maximum number of results', '100')
  .action((opts: {
    db: string;
    since?: string;
    level?: string;
    direction?: string;
    format: string;
    limit: string;
  }) => {
    const homeDir = process.env['HOME'] ?? process.env['USERPROFILE'] ?? process.cwd();
    const defaultDb = resolve(homeDir, '.mcp-fence', 'audit.db');
    const dbPath = opts.db ? resolve(process.cwd(), opts.db) : defaultDb;

    if (!existsSync(dbPath)) {
      log.error(`Audit database not found: ${dbPath}`);
      process.exit(1);
    }

    const store = new SqliteAuditStore(dbPath);

    try {
      const filters: Record<string, unknown> = {
        limit: parseInt(opts.limit, 10),
      };

      if (opts.since) {
        filters['since'] = parseDuration(opts.since);
      }

      if (opts.level === 'warn') {
        filters['minScore'] = 0.01;
      } else if (opts.level === 'block') {
        filters['decision'] = 'block';
      }

      if (opts.direction === 'request' || opts.direction === 'response') {
        filters['direction'] = opts.direction;
      }

      const events = store.query(filters);

      if (opts.format === 'sarif') {
        const sarif = toSarif(events);
        process.stdout.write(sarifToJson(sarif) + '\n');
      } else if (opts.format === 'json') {
        process.stdout.write(JSON.stringify(events, null, 2) + '\n');
      } else {
        printTable(events);
      }
    } finally {
      store.close();
    }
  });

/**
 * Parse a duration string (e.g., "1h", "30m", "1d") into an epoch timestamp.
 */
function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)([smhd])$/);
  if (!match) {
    log.error(`Invalid duration format: ${duration}. Use e.g., 30m, 1h, 1d`);
    process.exit(1);
  }

  const value = parseInt(match[1]!, 10);
  const unit = match[2]!;
  const multipliers: Record<string, number> = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };

  return Date.now() - value * multipliers[unit]!;
}

/**
 * Print audit events as a formatted table.
 */
function printTable(events: Array<{ timestamp: number; direction: string; method: string | null; tool_name: string | null; decision: string; score: number }>): void {
  if (events.length === 0) {
    process.stdout.write('No events found.\n');
    return;
  }

  const header = `${'Timestamp'.padEnd(24)} ${'Direction'.padEnd(10)} ${'Method'.padEnd(20)} ${'Decision'.padEnd(10)} ${'Score'.padEnd(7)} Tool`;
  process.stdout.write(header + '\n');
  process.stdout.write('─'.repeat(header.length) + '\n');

  for (const e of events) {
    const ts = new Date(e.timestamp).toISOString().replace('T', ' ').slice(0, 23);
    const dir = (e.direction ?? '').padEnd(10);
    const method = (e.method ?? '-').padEnd(20);
    const decision = (e.decision ?? '').padEnd(10);
    const score = e.score.toFixed(2).padEnd(7);
    const tool = e.tool_name ?? '-';
    process.stdout.write(`${ts} ${dir} ${method} ${decision} ${score} ${tool}\n`);
  }

  process.stdout.write(`\n${events.length} event(s)\n`);
}

// ─── Parse ───

/**
 * Custom parsing to support `mcp-fence start -- <server-command>`.
 * Commander doesn't natively handle `--` well with subcommands,
 * so we manually split argv at `--`.
 */
function parseArgv(): void {
  const argv = process.argv;
  const dashDashIndex = argv.indexOf('--');

  if (dashDashIndex === -1) {
    // No --, parse normally
    program.parse(argv);
  } else {
    // Split at --: left side is mcp-fence args, right side is server command
    const fenceArgs = argv.slice(0, dashDashIndex);
    const serverCmd = argv.slice(dashDashIndex + 1);

    // Temporarily replace process.argv for commander parsing
    // Then append server command as positional args to the start subcommand
    program.parse([...fenceArgs, ...serverCmd]);
  }
}

parseArgv();
