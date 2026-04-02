/**
 * Policy engine for mcp-fence.
 *
 * Wraps local policy evaluation and OPA integration, converting results
 * into Finding objects compatible with the scan pipeline.
 *
 * The policy engine only evaluates tools/call requests.
 * Other message types pass through without policy checks.
 *
 * When OPA is enabled, it acts as the authoritative source:
 * OPA decision overrides local policy in all cases.
 */

import type { JsonRpcMessage, Finding, PolicyConfig } from '../types.js';
import type { OpaConfig } from './opa-client.js';
import { evaluatePolicy } from './local.js';
import { queryOpa } from './opa-client.js';
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
  private readonly opaConfig?: OpaConfig;

  constructor(private readonly config: PolicyConfig) {
    const ruleCount = config.rules.length;
    log.info(`Policy engine initialized (${ruleCount} rules, default: ${config.defaultAction})`);

    if (config.opa?.enabled) {
      this.opaConfig = config.opa;
      log.info(`OPA integration enabled: ${config.opa.url}`);
    }
  }

  /**
   * Evaluate a message against policy rules.
   * Returns findings if the tool call is denied, empty array otherwise.
   *
   * When OPA is enabled, the OPA decision is authoritative and overrides
   * local policy evaluation.
   */
  async evaluate(message: JsonRpcMessage): Promise<Finding[]> {
    const call = extractToolCall(message);
    if (!call) return []; // Not a tools/call — no policy check

    const localDecision = evaluatePolicy(call.toolName, call.args, this.config);

    // If OPA is enabled, query it and use its decision as authoritative
    if (this.opaConfig) {
      const opaDecision = await queryOpa(this.opaConfig, {
        tool: call.toolName,
        args: call.args,
        direction: 'request',
      });

      if (opaDecision.allow) {
        log.debug(`OPA allows tool "${call.toolName}" (local was: ${localDecision.action})`);
        return [];
      }

      log.debug(`OPA denies tool "${call.toolName}" (local was: ${localDecision.action})`);
      return [
        {
          ruleId: 'OPA-001',
          message: opaDecision.reason ?? `Tool "${call.toolName}" denied by OPA`,
          severity: 'high',
          category: 'policy-violation',
          confidence: 1.0,
          metadata: {
            toolName: call.toolName,
            source: 'opa',
            opaReason: opaDecision.reason,
          },
        },
      ];
    }

    // No OPA — use local decision
    if (localDecision.action === 'allow') return [];

    return [
      {
        ruleId: 'POL-001',
        message: localDecision.reason,
        severity: 'high',
        category: 'policy-violation',
        confidence: 1.0,
        metadata: {
          toolName: call.toolName,
          matchedRule: localDecision.rule?.tool,
        },
      },
    ];
  }
}
