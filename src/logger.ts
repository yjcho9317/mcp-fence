// Logs to stderr to avoid interfering with stdio MCP transport.

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

let currentLevel: LogLevel = 'info';

/** Set the global log level. */
export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

function shouldLog(level: LogLevel): boolean {
  return LOG_LEVELS[level] >= LOG_LEVELS[currentLevel];
}

function formatMessage(level: LogLevel, component: string, message: string): string {
  const timestamp = new Date().toISOString();
  return `[${timestamp}] [mcp-fence] [${level.toUpperCase()}] [${component}] ${message}`;
}

/**
 * Create a scoped logger for a specific component.
 *
 * @example
 * const log = createLogger('proxy');
 * log.info('Proxy started');
 * log.error('Connection failed', error);
 */
export function createLogger(component: string) {
  return {
    debug(message: string): void {
      if (shouldLog('debug')) {
        process.stderr.write(formatMessage('debug', component, message) + '\n');
      }
    },
    info(message: string): void {
      if (shouldLog('info')) {
        process.stderr.write(formatMessage('info', component, message) + '\n');
      }
    },
    warn(message: string): void {
      if (shouldLog('warn')) {
        process.stderr.write(formatMessage('warn', component, message) + '\n');
      }
    },
    error(message: string, err?: unknown): void {
      if (shouldLog('error')) {
        const errStr = err instanceof Error ? ` | ${err.message}` : '';
        process.stderr.write(formatMessage('error', component, message + errStr) + '\n');
      }
    },
  };
}
