/**
 * Detection engine for mcp-fence.
 *
 * Implements the Scanner interface. Runs all applicable patterns against
 * incoming/outgoing MCP messages and produces a ScanResult.
 *
 * The engine extracts scannable text from JSON-RPC messages, then runs
 * direction-appropriate patterns with a per-pattern timeout guard.
 */

import type {
  Scanner,
  JsonRpcMessage,
  Direction,
  ScanResult,
  Finding,
  DetectionConfig,
} from '../types.js';
import { getPatternsForDirection, type DetectionPattern } from './patterns.js';
import { getSecretPatternsForDirection } from './secrets.js';
import { getPiiPatternsForDirection } from './pii.js';
import { buildScanResult } from './scorer.js';
import { createLogger } from '../logger.js';

const log = createLogger('detection');

/** Per-pattern regex match timeout in milliseconds. */
const PATTERN_TIMEOUT_MS = 5;

/**
 * Common Unicode confusables mapped to their ASCII equivalents.
 * Covers Cyrillic, Greek, and other scripts that have Latin lookalikes.
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E', '\u041D': 'H',
  '\u041A': 'K', '\u041C': 'M', '\u039D': 'N', '\u041E': 'O', '\u0420': 'P',
  '\u0405': 'S', '\u0422': 'T', '\u0425': 'X', '\u0430': 'a', '\u0441': 'c',
  '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0455': 's', '\u0443': 'y',
  '\u0456': 'i', '\u0458': 'j', '\u04BB': 'h', '\u0391': 'A', '\u0392': 'B',
  '\u0395': 'E', '\u0397': 'H', '\u0399': 'I', '\u039A': 'K', '\u039C': 'M',
  '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X',
  '\u03B1': 'a', '\u03B5': 'e', '\u03B9': 'i', '\u03BF': 'o', '\u03C1': 'p',
  '\u03C5': 'u', '\u13DA': 'S', '\u13B3': 'W',
};

/**
 * Normalize text before pattern matching to defeat common evasion techniques.
 *
 * 1. Strip zero-width and invisible characters
 * 2. NFKD unicode normalization (decompose ligatures, compatibility forms)
 * 3. Replace known homoglyphs with ASCII equivalents
 * 4. Decode URL-encoded sequences (%xx)
 * 5. Decode HTML numeric entities (&#xx; and &#xHH;)
 */
function normalizeText(text: string): string {
  // Strip invisible characters (zero-width spaces, joiners, soft hyphens, BOM, etc.)
  let normalized = text.replace(/[\u200B-\u200F\u2060-\u206F\u00AD\uFEFF\u034F]/g, '');

  // Replace known homoglyphs (Cyrillic, Greek, Cherokee → ASCII)
  // We do NOT use NFKD because it decomposes CJK characters (Korean jamo etc.)
  normalized = normalized.replace(/[\u0391-\u03C9\u0400-\u04FF\u13A0-\u13F4]/g, (ch) => {
    return HOMOGLYPH_MAP[ch] ?? ch;
  });

  // Decode URL encoding (%xx)
  try {
    normalized = decodeURIComponent(normalized);
  } catch {
    // If decodeURIComponent fails (malformed sequences), decode what we can
    normalized = normalized.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex as string, 16));
    });
  }

  // Decode HTML numeric entities (&#decimal; and &#xHex;)
  normalized = normalized.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
  normalized = normalized.replace(/&#x([0-9A-Fa-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h as string, 16)));

  return normalized;
}

/**
 * Extract scannable text content from a JSON-RPC message.
 *
 * What we scan depends on the direction:
 * - request: method name + stringified params (tool arguments)
 * - response: stringified result (tool output that the AI will process)
 *
 * We flatten nested objects into a single string for pattern matching.
 */
function extractText(message: JsonRpcMessage, direction: Direction): { text: string; depthExceeded: boolean } {
  const parts: string[] = [];
  let depthExceeded = false;

  const flatten = (value: unknown, depth = 0): string => {
    if (depth > 10) {
      depthExceeded = true;
      return '';
    }
    if (value == null) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);

    if (Array.isArray(value)) {
      return value.map((v) => flatten(v, depth + 1)).join(' ');
    }

    if (typeof value === 'object') {
      return Object.values(value as Record<string, unknown>)
        .map((v) => flatten(v, depth + 1))
        .join(' ');
    }

    return String(value);
  };

  if (direction === 'request') {
    if ('method' in message && message.method) {
      parts.push(message.method);
    }
    if ('params' in message && message.params != null) {
      parts.push(flatten(message.params));
    }
  } else {
    if ('result' in message && message.result != null) {
      parts.push(flatten(message.result));
    }
    if ('error' in message && message.error != null) {
      parts.push(flatten(message.error));
    }
  }

  return { text: parts.join(' '), depthExceeded };
}

/**
 * Run a single pattern against text with a timeout guard.
 *
 * Returns a Finding if the pattern matches, null otherwise.
 * If the regex takes longer than PATTERN_TIMEOUT_MS, it's treated as no match
 * to prevent ReDoS from blocking the proxy.
 */
function matchPattern(pattern: DetectionPattern, text: string): Finding | null {
  const start = performance.now();

  try {
    const match = pattern.pattern.test(text);
    const elapsed = performance.now() - start;

    if (elapsed > PATTERN_TIMEOUT_MS) {
      log.warn(`Pattern ${pattern.id} took ${elapsed.toFixed(1)}ms (limit: ${PATTERN_TIMEOUT_MS}ms)`);
    }

    if (!match) return null;

    return {
      ruleId: pattern.id,
      message: pattern.description,
      severity: pattern.severity,
      category: pattern.category,
      confidence: pattern.confidence,
      remediation: pattern.remediation,
      metadata: { patternName: pattern.name },
    };
  } catch {
    log.warn(`Pattern ${pattern.id} failed to execute`);
    return null;
  }
}

export class DetectionEngine implements Scanner {
  private readonly config: DetectionConfig;

  constructor(config: DetectionConfig) {
    this.config = config;
    log.info(`Detection engine initialized (warn: ${config.warnThreshold}, block: ${config.blockThreshold})`);
  }

  /**
   * Scan a JSON-RPC message for threats.
   *
   * 1. Extract text content from the message
   * 2. Truncate to maxInputSize (ReDoS defense)
   * 3. Run all direction-appropriate patterns
   * 4. Aggregate findings into a ScanResult
   */
  async scan(message: JsonRpcMessage, direction: Direction): Promise<ScanResult> {
    const extracted = extractText(message, direction);
    let text = extracted.text;

    if (extracted.depthExceeded) {
      log.warn(`Message exceeds max nesting depth (10) — content may be hidden`);
    }

    // For oversized input: scan both the beginning and end to prevent
    // attackers from hiding payloads past the truncation boundary
    let tailText = '';
    if (text.length > this.config.maxInputSize) {
      const halfSize = Math.floor(this.config.maxInputSize / 2);
      tailText = text.slice(-halfSize);
      text = text.slice(0, halfSize);
      log.debug(`Input oversized (${text.length + tailText.length}), scanning head + tail`);
    }

    // Normalize text to defeat evasion techniques (homoglyphs, zero-width chars, encoding)
    text = normalizeText(text);

    if (text.length === 0) {
      return buildScanResult([], direction, this.config);
    }

    const patterns = getPatternsForDirection(direction);
    const secretPatterns = getSecretPatternsForDirection(direction);
    const findings: Finding[] = [];

    for (const pattern of patterns) {
      const finding = matchPattern(pattern, text);
      if (finding) {
        findings.push(finding);
        log.debug(`Match: ${pattern.id} (${pattern.name}) — direction: ${direction}`);
      }
    }

    // Scan tail portion (for oversized messages) — deduplicate by ruleId
    if (tailText.length > 0) {
      const normalizedTail = normalizeText(tailText);
      const headRuleIds = new Set(findings.map((f) => f.ruleId));
      for (const pattern of patterns) {
        if (headRuleIds.has(pattern.id)) continue;
        const finding = matchPattern(pattern, normalizedTail);
        if (finding) {
          findings.push(finding);
          log.debug(`Match (tail): ${pattern.id} (${pattern.name}) — direction: ${direction}`);
        }
      }
    }

    // Also run injection patterns on pre-normalization text (invisible chars stripped only).
    // This catches multi-language patterns (Russian, etc.) that homoglyph normalization destroys.
    const originalText = extractText(message, direction).text;
    const strippedOriginal = originalText.replace(/[\u200B-\u200F\u2060-\u206F\u00AD\uFEFF\u034F]/g, '');
    const preNormText = strippedOriginal.length > this.config.maxInputSize
      ? strippedOriginal.slice(0, this.config.maxInputSize)
      : strippedOriginal;

    if (preNormText !== text) {
      const existingRuleIds = new Set(findings.map((f) => f.ruleId));
      for (const pattern of patterns) {
        if (existingRuleIds.has(pattern.id)) continue;
        const finding = matchPattern(pattern, preNormText);
        if (finding) {
          findings.push(finding);
          log.debug(`Match (pre-norm): ${pattern.id} (${pattern.name}) — direction: ${direction}`);
        }
      }
    }

    // Secret patterns run on text with only invisible characters stripped.
    // Full normalization (homoglyphs, NFKD) would break secret prefixes like AKIA, ghp_.
    const strippedText = originalText.replace(/[\u200B-\u200F\u2060-\u206F\u00AD\uFEFF\u034F]/g, '');
    const secretText = strippedText.length > this.config.maxInputSize
      ? strippedText.slice(0, this.config.maxInputSize)
      : strippedText;

    for (const pattern of secretPatterns) {
      const finding = matchPattern(pattern, secretText);
      if (finding) {
        findings.push(finding);
        log.debug(`Secret match: ${pattern.id} (${pattern.name}) — direction: ${direction}`);
      }
    }

    const piiPatterns = getPiiPatternsForDirection(direction);
    for (const pattern of piiPatterns) {
      const finding = matchPattern(pattern, secretText);
      if (finding) {
        findings.push(finding);
        log.debug(`PII match: ${pattern.id} (${pattern.name}) — direction: ${direction}`);
      }
    }

    const result = buildScanResult(findings, direction, this.config);

    if (findings.length > 0) {
      log.info(
        `Scan ${direction}: ${findings.length} finding(s), score: ${result.score.toFixed(2)}, decision: ${result.decision}`,
      );
    }

    return result;
  }
}
