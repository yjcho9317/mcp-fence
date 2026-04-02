/**
 * Cross-server data flow policy engine for mcp-fence.
 *
 * Tracks which tools have been called during a session and enforces
 * data flow rules that prevent data from one tool flowing to another.
 *
 * Example: if `read_file` was called and now `send_email` is called,
 * a deny rule for `read_file -> send_email` would block the second call.
 */

import type { Finding } from '../types.js';
import { createLogger } from '../logger.js';

const log = createLogger('data-flow');

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

/**
 * Convert a glob pattern to a RegExp.
 * Supports `*` (any chars) and `?` (single char).
 */
function globToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`);
}

/**
 * Check if a tool name matches a pattern (exact or glob).
 */
function matchesPattern(toolName: string, pattern: string): boolean {
  const normName = toolName.toLowerCase();
  const normPattern = pattern.toLowerCase();
  if (normPattern === normName) return true;
  if (!normPattern.includes('*') && !normPattern.includes('?')) return false;
  return globToRegex(normPattern).test(normName);
}

/**
 * Evaluate data flow rules for a tool call given the session history.
 *
 * Checks whether any previously-called tool combined with the current
 * destination tool triggers a deny rule.
 *
 * Returns findings if any data flow rule is violated.
 */
export function evaluateDataFlow(
  currentTool: string,
  previousTools: string[],
  config: DataFlowConfig,
): Finding[] {
  if (!config.enabled || config.rules.length === 0) return [];

  const findings: Finding[] = [];

  for (const previousTool of previousTools) {
    for (const rule of config.rules) {
      if (!matchesPattern(previousTool, rule.from)) continue;
      if (!matchesPattern(currentTool, rule.to)) continue;

      if (rule.action === 'deny') {
        log.warn(`Data flow denied: ${previousTool} -> ${currentTool} (rule: ${rule.from} -> ${rule.to})`);
        findings.push({
          ruleId: 'DFL-001',
          message: `Data flow denied: "${previousTool}" -> "${currentTool}" (rule: ${rule.from} -> ${rule.to})`,
          severity: 'high',
          category: 'data-exfiltration',
          confidence: 1.0,
          metadata: {
            sourceTool: previousTool,
            destinationTool: currentTool,
            ruleFrom: rule.from,
            ruleTo: rule.to,
          },
        });
        // First deny match is sufficient
        return findings;
      }

      if (rule.action === 'allow') {
        // Explicit allow for this flow pair, skip checking further rules for this source
        log.debug(`Data flow allowed: ${previousTool} -> ${currentTool} (rule: ${rule.from} -> ${rule.to})`);
        break;
      }
    }
  }

  return findings;
}
