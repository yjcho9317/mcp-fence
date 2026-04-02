/**
 * Audit logger for mcp-fence.
 *
 * Implements the AuditLogger interface defined in types.ts.
 * Receives (message, ScanResult) pairs from the proxy and persists them
 * via the AuditStore adapter.
 */

import type { JsonRpcMessage, ScanResult, AuditLogger as IAuditLogger } from '../types.js';
import type { AuditStore } from './storage.js';
import { createLogger } from '../logger.js';
import { maskSecrets } from './masker.js';
import { ALL_SECRET_PATTERNS } from '../detection/secrets.js';

const log = createLogger('audit');

/**
 * Extract the method name from a JSON-RPC message.
 */
function extractMethod(message: JsonRpcMessage): string | undefined {
  if ('method' in message) return message.method;
  return undefined;
}

/**
 * Extract the tool name from a tools/call request.
 */
function extractToolName(message: JsonRpcMessage): string | undefined {
  if (!('params' in message) || message.params == null) return undefined;
  const params = message.params as Record<string, unknown>;
  if (typeof params['name'] === 'string') return params['name'];
  return undefined;
}

export class AuditLoggerImpl implements IAuditLogger {
  constructor(private readonly store: AuditStore) {
    log.info('Audit logger initialized');
  }

  async log(message: JsonRpcMessage, result: ScanResult): Promise<void> {
    const method = extractMethod(message);
    const toolName = extractToolName(message);

    try {
      const rawMessage = JSON.stringify(message);
      const rawFindings = JSON.stringify(result.findings);
      const maskedMessage = maskSecrets(rawMessage, ALL_SECRET_PATTERNS);
      const maskedFindings = maskSecrets(rawFindings, ALL_SECRET_PATTERNS);

      this.store.insert({
        timestamp: result.timestamp,
        direction: result.direction,
        method,
        toolName,
        decision: result.decision,
        score: result.score,
        findings: maskedFindings,
        message: maskedMessage,
      });
    } catch (err) {
      // Audit failure must not crash the proxy
      log.error('Failed to write audit event', err);
    }
  }

  /** Get the underlying store for direct queries (used by CLI). */
  getStore(): AuditStore {
    return this.store;
  }
}
