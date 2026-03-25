/**
 * Risk score calculation for mcp-fence.
 *
 * Aggregates multiple findings into a single risk score (0.0 ~ 1.0)
 * and determines the final decision (allow/warn/block).
 *
 * Scoring strategy:
 * - Takes the highest individual finding score as the base
 * - Applies a multiplier when multiple findings co-occur (compound risk)
 * - Caps the final score at 1.0
 */

import type { Finding, ScanResult, Direction, DetectionConfig } from '../types.js';

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 1.0,
  high: 0.8,
  medium: 0.5,
  low: 0.2,
  info: 0.05,
};

/**
 * Calculate an individual finding's weighted score.
 *
 * score = severity_weight * confidence
 */
function findingScore(finding: Finding): number {
  const weight = SEVERITY_WEIGHTS[finding.severity] ?? 0.5;
  return weight * finding.confidence;
}

/**
 * Compound risk multiplier.
 *
 * When multiple findings fire on the same message, the overall risk
 * is higher than any single finding alone. This models the "smoke means fire" heuristic.
 *
 * 1 finding  → 1.0x (no boost)
 * 2 findings → 1.15x
 * 3 findings → 1.25x
 * 4+ findings → 1.35x (cap)
 */
function compoundMultiplier(count: number): number {
  if (count <= 1) return 1.0;
  if (count === 2) return 1.15;
  if (count === 3) return 1.25;
  return 1.35;
}

/**
 * Aggregate findings into a final risk score.
 */
export function calculateScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;

  const scores = findings.map(findingScore);
  const maxScore = Math.max(...scores);
  const multiplier = compoundMultiplier(findings.length);

  return Math.min(1.0, maxScore * multiplier);
}

/**
 * Determine the decision based on score and thresholds.
 */
export function determineDecision(
  score: number,
  config: DetectionConfig,
): 'allow' | 'warn' | 'block' {
  if (score >= config.blockThreshold) return 'block';
  if (score >= config.warnThreshold) return 'warn';
  return 'allow';
}

/**
 * Build a complete ScanResult from findings.
 */
export function buildScanResult(
  findings: Finding[],
  direction: Direction,
  config: DetectionConfig,
): ScanResult {
  const score = calculateScore(findings);
  const decision = determineDecision(score, config);

  return {
    decision,
    findings,
    score,
    direction,
    timestamp: Date.now(),
  };
}
