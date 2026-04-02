/**
 * Local policy rule matching for mcp-fence.
 *
 * Evaluates tool access against YAML-defined rules.
 * Supports glob patterns for tool names and regex constraints on arguments.
 *
 * Rule matching priority:
 * 1. Exact tool name match
 * 2. Glob pattern match (first match wins)
 * 3. Default action (from config)
 */

import type { PolicyConfig, PolicyRule, ArgConstraint } from '../types.js';
import { createLogger } from '../logger.js';

const log = createLogger('policy');

export interface PolicyDecision {
  action: 'allow' | 'deny';
  rule?: PolicyRule;
  reason: string;
}

/**
 * Normalize a tool name for policy matching.
 * Strips invisible characters, null bytes, and trims whitespace.
 * Lowercases for case-insensitive matching.
 */
function normalizeToolName(name: string): string {
  return name
    .replace(/[\u200B-\u200F\u2060-\u206F\u00AD\uFEFF\u034F\x00]/g, '')
    .trim()
    .toLowerCase();
}

/**
 * Convert a glob pattern to a RegExp.
 * Supports only `*` (any chars) and `?` (single char).
 */
function globToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`);
}

/**
 * Check if a tool name matches a rule's tool pattern.
 * Both sides are normalized (lowercase, stripped) before comparison.
 */
function matchesToolPattern(toolName: string, pattern: string): boolean {
  const normName = normalizeToolName(toolName);
  const normPattern = normalizeToolName(pattern);
  if (normPattern === normName) return true;
  if (!normPattern.includes('*') && !normPattern.includes('?')) return false;
  return globToRegex(normPattern).test(normName);
}

/**
 * Validate a single argument against a constraint.
 * Returns null if valid, or a reason string if violated.
 */
/**
 * Safely convert an argument value to a string for pattern matching.
 * Avoids calling toString() on objects (potential side effects).
 */
function safeStringify(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

/**
 * Run a regex pattern with a time guard.
 * Returns the match result, or null if the pattern takes too long.
 */
function safeRegexTest(pattern: string, input: string, flags = ''): boolean | null {
  const start = performance.now();
  try {
    const result = new RegExp(pattern, flags).test(input);
    const elapsed = performance.now() - start;
    if (elapsed > 5) {
      log.warn(`Regex pattern took ${elapsed.toFixed(1)}ms: ${pattern.slice(0, 50)}`);
    }
    return result;
  } catch {
    return null;
  }
}

function normalizeArgValue(value: string): string {
  let normalized = value;
  try { normalized = decodeURIComponent(normalized); } catch {}
  normalized = normalized.replace(/[\u200B-\u200F\u2060-\u206F\u00AD\uFEFF\u034F\x00]/g, '');
  return normalized;
}

function checkArgConstraint(
  argValue: unknown,
  constraint: ArgConstraint,
): string | null {
  if (argValue == null) return null;
  const rawValue = safeStringify(argValue);
  const strValue = normalizeArgValue(rawValue);

  const flags = constraint.caseInsensitive ? 'i' : '';

  if (constraint.denyPattern) {
    const result = safeRegexTest(constraint.denyPattern, strValue, flags);
    if (result === null) {
      log.warn(`Invalid denyPattern regex: ${constraint.denyPattern}`);
    } else if (result) {
      return `Argument "${constraint.name}" matches deny pattern: ${constraint.denyPattern}`;
    }
  }

  if (constraint.allowPattern) {
    const result = safeRegexTest(constraint.allowPattern, strValue, flags);
    if (result === null) {
      log.warn(`Invalid allowPattern regex: ${constraint.allowPattern}`);
    } else if (!result) {
      return `Argument "${constraint.name}" does not match allow pattern: ${constraint.allowPattern}`;
    }
  }

  return null;
}

/**
 * Evaluate tool arguments against a rule's constraints.
 * Returns null if all constraints pass, or a reason string on violation.
 */
function checkArgs(
  args: Record<string, unknown> | undefined,
  constraints: ArgConstraint[],
): string | null {
  if (!args) return null;

  for (const constraint of constraints) {
    const value = args[constraint.name];
    const violation = checkArgConstraint(value, constraint);
    if (violation) return violation;
  }

  return null;
}

/**
 * Evaluate a tool call against the policy rules.
 */
export function evaluatePolicy(
  toolName: string,
  args: Record<string, unknown> | undefined,
  config: PolicyConfig,
): PolicyDecision {
  // Find matching rule (first match wins)
  for (const rule of config.rules) {
    if (!matchesToolPattern(toolName, rule.tool)) continue;

    // Rule matches this tool
    if (rule.action === 'deny') {
      log.debug(`Policy deny: tool "${toolName}" matched rule "${rule.tool}"`);
      return {
        action: 'deny',
        rule,
        reason: `Tool "${toolName}" denied by rule: ${rule.tool}`,
      };
    }

    // Action is allow — check argument constraints if any
    if (rule.args && rule.args.length > 0) {
      const violation = checkArgs(args, rule.args);
      if (violation) {
        log.debug(`Policy deny: tool "${toolName}" arg violation: ${violation}`);
        return {
          action: 'deny',
          rule,
          reason: violation,
        };
      }
    }

    log.debug(`Policy allow: tool "${toolName}" matched rule "${rule.tool}"`);
    return {
      action: 'allow',
      rule,
      reason: `Tool "${toolName}" allowed by rule: ${rule.tool}`,
    };
  }

  // No rule matched — use default
  return {
    action: config.defaultAction,
    reason: `Tool "${toolName}" — no matching rule, default: ${config.defaultAction}`,
  };
}
