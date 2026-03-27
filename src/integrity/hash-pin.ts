/**
 * Tool description hash pinning for rug-pull detection.
 *
 * When a tools/list response arrives, this module:
 * 1. Extracts each tool's name and description
 * 2. Normalizes the description (trim whitespace, lowercase, remove extra spaces)
 * 3. Computes SHA-256 hash
 * 4. Compares against the pinned hash (if exists)
 * 5. If hash changed → Finding with category 'rug-pull'
 * 6. If new tool → pin it for future comparison
 *
 * This catches OWASP MCP02 (Tool Poisoning) at runtime — a server that
 * changes tool descriptions after initial approval to inject malicious instructions.
 */

import { createHash } from 'node:crypto';
import type { JsonRpcMessage, Finding } from '../types.js';
import type { HashStore } from './store.js';
import { createLogger } from '../logger.js';

const log = createLogger('integrity');

/**
 * Normalize a tool description before hashing.
 *
 * Removes variations that aren't meaningful changes:
 * - Leading/trailing whitespace
 * - Multiple consecutive spaces → single space
 * - Case normalization (lowercase)
 *
 * This prevents false positives from formatting differences
 * while still catching actual content changes.
 */
function normalizeDescription(description: string): string {
  return description
    .trim()
    .replace(/\s+/g, ' ')
    .toLowerCase();
}

/**
 * Compute SHA-256 hash of a normalized description.
 */
function hashDescription(description: string): string {
  const normalized = normalizeDescription(description);
  return createHash('sha256').update(normalized).digest('hex');
}

/**
 * Tool info extracted from a tools/list response.
 */
interface ToolEntry {
  name: string;
  description: string;
}

/**
 * Extract tools from a tools/list response message.
 *
 * MCP tools/list response format:
 * { "result": { "tools": [{ "name": "...", "description": "...", "inputSchema": {...} }] } }
 */
function extractTools(message: JsonRpcMessage): ToolEntry[] {
  if (!('result' in message) || message.result == null) return [];

  const result = message.result as Record<string, unknown>;
  const tools = result['tools'];
  if (!Array.isArray(tools)) return [];

  const entries: ToolEntry[] = [];
  for (const tool of tools) {
    if (typeof tool !== 'object' || tool == null) continue;
    const t = tool as Record<string, unknown>;
    const name = t['name'];
    const description = t['description'];
    if (typeof name === 'string' && typeof description === 'string') {
      entries.push({ name, description });
    }
  }
  return entries;
}

/**
 * Check if a message is a tools/list response.
 *
 * We can't directly see the original method in a response (JSON-RPC responses
 * only have id, result, error). So we check the result structure:
 * if it has a "tools" array with objects containing "name" and "description",
 * it's almost certainly a tools/list response.
 */
function isToolsListResponse(message: JsonRpcMessage): boolean {
  if (!('result' in message) || message.result == null) return false;
  const result = message.result as Record<string, unknown>;
  return Array.isArray(result['tools']);
}

export class HashPinChecker {
  constructor(private readonly store: HashStore) {}

  /**
   * Check a message for rug-pull attacks.
   *
   * Only processes tools/list responses. For all other messages, returns
   * an empty findings array.
   *
   * Returns findings for each tool whose description hash has changed
   * since it was first pinned.
   */
  check(message: JsonRpcMessage): Finding[] {
    if (!isToolsListResponse(message)) return [];

    const tools = extractTools(message);
    if (tools.length === 0) return [];

    const findings: Finding[] = [];

    for (const tool of tools) {
      const hash = hashDescription(tool.description);
      const pinned = this.store.get(tool.name);

      if (pinned === null) {
        // First encounter — pin it
        this.store.pin(tool.name, hash, tool.description);
        continue;
      }

      if (pinned.hash === hash) {
        // Hash matches — no change
        continue;
      }

      // Hash mismatch — rug-pull detected
      log.warn(
        `Rug-pull detected for tool "${tool.name}": ` +
        `hash changed from ${pinned.hash.slice(0, 12)}... to ${hash.slice(0, 12)}...`,
      );

      this.store.pin(tool.name, hash, tool.description);

      findings.push({
        ruleId: 'RUG-001',
        message: `Tool "${tool.name}" description changed since first approval. ` +
          `Previous: "${pinned.description.slice(0, 80)}..." → ` +
          `Current: "${tool.description.slice(0, 80)}..."`,
        severity: 'critical',
        category: 'rug-pull',
        confidence: 0.98,
        metadata: {
          toolName: tool.name,
          previousHash: pinned.hash,
          currentHash: hash,
          previousDescription: pinned.description,
          currentDescription: tool.description,
        },
      });
    }

    return findings;
  }

  /** Get all currently pinned tools (for CLI inspection). */
  getPinnedTools(): Array<{ name: string; hash: string; pinnedAt: number }> {
    return this.store.getAll().map((t) => ({
      name: t.name,
      hash: t.hash,
      pinnedAt: t.pinnedAt,
    }));
  }
}
