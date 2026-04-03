/**
 * Context budget enforcement for server responses.
 *
 * Limits the size of MCP server responses to prevent context window
 * over-sharing. Measures response size in bytes (JSON.stringify length)
 * and applies the configured action: warn, truncate, or block.
 */

import type { JsonRpcMessage, Finding, ContextBudgetConfig } from '../types.js';
import { createLogger } from '../logger.js';

const log = createLogger('context-budget');

export interface BudgetResult {
  /** Whether the response exceeded the configured budget */
  exceeded: boolean;
  /** Actual size of the serialized response in bytes */
  actualBytes: number;
  /** Configured byte limit */
  limitBytes: number;
  /** Finding generated when budget is exceeded */
  finding?: Finding;
  /** Truncated message (only set when action='truncate' and budget exceeded) */
  truncatedMessage?: JsonRpcMessage;
}

/**
 * Truncate text content within a tools/call result to fit within the byte limit.
 *
 * Walks the result.content array looking for text entries and shortens
 * the longest one until the message fits. Appends a truncation marker.
 */
function truncateResponse(message: JsonRpcMessage, limitBytes: number): JsonRpcMessage {
  const serialized = JSON.stringify(message);
  if (serialized.length <= limitBytes) return message;

  // Deep clone to avoid mutating the original
  const cloned = JSON.parse(serialized) as JsonRpcMessage;

  if (!('result' in cloned) || cloned.result == null) {
    return cloned;
  }

  const result = cloned.result as Record<string, unknown>;
  const content = result['content'];

  if (Array.isArray(content)) {
    // Find the longest text entry and truncate it iteratively
    for (const item of content) {
      if (typeof item === 'object' && item !== null) {
        const entry = item as Record<string, unknown>;
        if (entry['type'] === 'text' && typeof entry['text'] === 'string') {
          const marker = '\n... [truncated by mcp-fence: response exceeded context budget]';
          const text = entry['text'] as string;

          // Binary search for the right cut point that keeps us within budget.
          // JSON.stringify may escape characters, so we can't just subtract byte counts.
          let lo = 0;
          let hi = text.length;
          let best = 0;
          while (lo <= hi) {
            const mid = (lo + hi) >>> 1;
            entry['text'] = text.slice(0, mid) + marker;
            if (JSON.stringify(cloned).length <= limitBytes) {
              best = mid;
              lo = mid + 1;
            } else {
              hi = mid - 1;
            }
          }
          entry['text'] = text.slice(0, best) + marker;
          break;
        }
      }
    }
  }

  return cloned;
}

/**
 * Check a server response against the configured context budget.
 */
export function checkContextBudget(
  message: JsonRpcMessage,
  config: ContextBudgetConfig,
): BudgetResult {
  if (!config.enabled) {
    return { exceeded: false, actualBytes: 0, limitBytes: 0 };
  }

  const limitBytes = config.maxResponseBytes ?? 102400;
  const serialized = JSON.stringify(message);
  const actualBytes = serialized.length;

  if (actualBytes <= limitBytes) {
    return { exceeded: false, actualBytes, limitBytes };
  }

  log.warn(`Response size ${actualBytes} bytes exceeds budget of ${limitBytes} bytes`);

  const baseFinding: Finding = {
    ruleId: 'CTX-001',
    message:
      `Response size (${actualBytes} bytes) exceeds context budget (${limitBytes} bytes).`,
    severity: config.truncateAction === 'block' ? 'high' : 'medium',
    category: 'policy-violation',
    confidence: 1.0,
    metadata: {
      actualBytes,
      limitBytes,
      action: config.truncateAction,
    },
  };

  const result: BudgetResult = {
    exceeded: true,
    actualBytes,
    limitBytes,
    finding: baseFinding,
  };

  if (config.truncateAction === 'truncate') {
    result.truncatedMessage = truncateResponse(message, limitBytes);
  }

  return result;
}
