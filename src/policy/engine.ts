/**
 * Policy engine for mcp-fence.
 *
 * Wraps local policy evaluation and converts results into Finding objects
 * compatible with the scan pipeline.
 *
 * The policy engine only evaluates tools/call requests.
 * Other message types pass through without policy checks.
 */

import type { JsonRpcMessage, Finding, PolicyConfig } from '../types.js';
import { evaluatePolicy } from './local.js';
import { createLogger } from '../logger.js';

const log = createLogger('policy');

/**
 * Extract tool name and arguments from a tools/call request.
 */
function extractToolCall(message: JsonRpcMessage): {
  toolName: string;
  args: Record<string, unknown> | undefined;
} | null {
  if (!('method' in message)) return null;
  if (message.method !== 'tools/call') return null;
  if (!('params' in message) || message.params == null) return null;

  const params = message.params as Record<string, unknown>;
  const toolName = params['name'];
  if (typeof toolName !== 'string') return null;

  const args = params['arguments'] as Record<string, unknown> | undefined;
  return { toolName, args };
}

export class PolicyEngine {
  constructor(private readonly config: PolicyConfig) {
    const ruleCount = config.rules.length;
    log.info(`Policy engine initialized (${ruleCount} rules, default: ${config.defaultAction})`);
  }

  /**
   * Evaluate a message against policy rules.
   * Returns findings if the tool call is denied, empty array otherwise.
   */
  evaluate(message: JsonRpcMessage): Finding[] {
    const call = extractToolCall(message);
    if (!call) return []; // Not a tools/call — no policy check

    const decision = evaluatePolicy(call.toolName, call.args, this.config);

    if (decision.action === 'allow') return [];

    return [
      {
        ruleId: 'POL-001',
        message: decision.reason,
        severity: 'high',
        category: 'policy-violation',
        confidence: 1.0,
        metadata: {
          toolName: call.toolName,
          matchedRule: decision.rule?.tool,
        },
      },
    ];
  }
}
