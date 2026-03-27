/**
 * Secret masking for audit log storage.
 *
 * Scans text for secret patterns and replaces matches with masked versions
 * before they are written to the audit database. This prevents the audit DB
 * from becoming a high-value target containing plaintext credentials.
 *
 * Masking format:
 *   - Secrets >= 12 chars: first 4 chars + "****" + last 4 chars
 *   - Secrets < 12 chars: replaced entirely with [REDACTED]
 */

import type { DetectionPattern } from '../detection/patterns.js';

const SHORT_SECRET_THRESHOLD = 12;

/**
 * Mask a single secret value based on its length.
 */
export function maskValue(value: string): string {
  if (value.length < SHORT_SECRET_THRESHOLD) {
    return '[REDACTED]';
  }
  const prefix = value.slice(0, 4);
  const suffix = value.slice(-4);
  return `${prefix}${'*'.repeat(value.length - 8)}${suffix}`;
}

/**
 * Scan text for secrets using the provided patterns and replace all
 * matches with masked versions.
 *
 * Each pattern is run independently. Overlapping matches are handled
 * by processing replacements from right to left so earlier offsets
 * remain valid after replacement.
 */
export function maskSecrets(text: string, patterns: readonly DetectionPattern[]): string {
  const matches: Array<{ start: number; end: number; value: string }> = [];

  for (const p of patterns) {
    const flags = p.pattern.flags.includes('g') ? p.pattern.flags : p.pattern.flags + 'g';
    const globalPattern = new RegExp(p.pattern.source, flags);

    let m: RegExpExecArray | null;
    while ((m = globalPattern.exec(text)) !== null) {
      matches.push({
        start: m.index,
        end: m.index + m[0].length,
        value: m[0],
      });
      // Prevent infinite loop on zero-length matches
      if (m[0].length === 0) {
        globalPattern.lastIndex++;
      }
    }
  }

  if (matches.length === 0) return text;

  matches.sort((a, b) => b.start - a.start);

  const deduped: Array<{ start: number; end: number; value: string }> = [];
  for (const match of matches) {
    const overlaps = deduped.some(
      (existing) => match.start < existing.end && match.end > existing.start,
    );
    if (!overlaps) {
      deduped.push(match);
    }
  }

  let result = text;
  for (const match of deduped) {
    const masked = maskValue(match.value);
    result = result.slice(0, match.start) + masked + result.slice(match.end);
  }

  return result;
}
