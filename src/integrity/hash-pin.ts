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
import type { HashStore, ServerPin } from './store.js';
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
  inputSchema?: Record<string, unknown>;
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
      const inputSchema = (typeof t['inputSchema'] === 'object' && t['inputSchema'] !== null)
        ? t['inputSchema'] as Record<string, unknown>
        : undefined;
      entries.push({ name, description, inputSchema });
    }
  }
  return entries;
}

/**
 * Deterministic JSON serialization with sorted keys at all levels.
 */
function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}

/**
 * Build a deterministic hash of the full server schema.
 *
 * Sorts tools by name, then hashes the concatenation of each tool's
 * name + normalized description + JSON-serialized inputSchema.
 * This ensures tool ordering doesn't affect the fingerprint.
 */
function hashServerSchema(tools: ToolEntry[]): string {
  const sorted = [...tools].sort((a, b) => a.name.localeCompare(b.name));
  const canonical = sorted.map((t) => {
    const parts = [t.name, normalizeDescription(t.description)];
    if (t.inputSchema !== undefined) {
      parts.push(stableStringify(t.inputSchema));
    }
    return parts.join('\0');
  }).join('\n');
  return createHash('sha256').update(canonical).digest('hex');
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

      const changeCount = pinned.changeCount + 1;
      const isBoilingFrog = changeCount >= 3;

      findings.push({
        ruleId: isBoilingFrog ? 'RUG-002' : 'RUG-001',
        message: isBoilingFrog
          ? `Tool "${tool.name}" has changed ${changeCount} times since original approval (gradual drift). ` +
            `Original: "${pinned.originalDescription.slice(0, 60)}..." → ` +
            `Current: "${tool.description.slice(0, 60)}..."`
          : `Tool "${tool.name}" description changed since ${changeCount === 1 ? 'first approval' : 'last check'}. ` +
            `Previous: "${pinned.description.slice(0, 80)}..." → ` +
            `Current: "${tool.description.slice(0, 80)}..."`,
        severity: 'critical',
        category: 'rug-pull',
        confidence: isBoilingFrog ? 1.0 : 0.98,
        metadata: {
          toolName: tool.name,
          previousHash: pinned.hash,
          currentHash: hash,
          previousDescription: pinned.description,
          currentDescription: tool.description,
          originalHash: pinned.originalHash,
          originalDescription: pinned.originalDescription,
          changeCount,
        },
      });
    }

    return findings;
  }

  /**
   * Check the full server schema for TOFU-based spoofing detection.
   *
   * On first tools/list response, pins the entire schema fingerprint.
   * On subsequent responses, compares against the stored pin and reports
   * any differences: tools added, removed, or schema changed.
   */
  checkServerSchema(message: JsonRpcMessage): Finding[] {
    if (!isToolsListResponse(message)) return [];

    const tools = extractTools(message);
    const currentNames = tools.map((t) => t.name).sort();
    const schemaHash = hashServerSchema(tools);

    const existingPin = this.store.getServerPin();

    if (existingPin === null) {
      // TOFU: first encounter, pin it
      this.store.setServerPin({
        schemaHash,
        toolNames: currentNames,
        pinnedAt: Date.now(),
      });
      return [];
    }

    if (existingPin.schemaHash === schemaHash) {
      return [];
    }

    // Schema changed — identify what changed
    const findings: Finding[] = [];
    const previousNames = new Set(existingPin.toolNames);
    const currentNameSet = new Set(currentNames);

    const addedTools = currentNames.filter((n) => !previousNames.has(n));
    const removedTools = existingPin.toolNames.filter((n) => !currentNameSet.has(n));

    for (const name of addedTools) {
      findings.push({
        ruleId: 'SRV-002',
        message: `New tool "${name}" appeared that was not in the original server schema.`,
        severity: 'high',
        category: 'rug-pull',
        confidence: 0.95,
        metadata: { toolName: name, previousToolNames: existingPin.toolNames, currentToolNames: currentNames },
      });
    }

    for (const name of removedTools) {
      findings.push({
        ruleId: 'SRV-003',
        message: `Tool "${name}" disappeared from the server schema.`,
        severity: 'high',
        category: 'rug-pull',
        confidence: 0.95,
        metadata: { toolName: name, previousToolNames: existingPin.toolNames, currentToolNames: currentNames },
      });
    }

    // If there are no added/removed tools but hash changed, a tool's schema or description changed
    if (addedTools.length === 0 && removedTools.length === 0) {
      findings.push({
        ruleId: 'SRV-001',
        message:
          'Server schema changed — a tool description or inputSchema was modified ' +
          'since the server was first seen.',
        severity: 'high',
        category: 'rug-pull',
        confidence: 0.95,
        metadata: {
          previousHash: existingPin.schemaHash,
          currentHash: schemaHash,
          toolNames: currentNames,
        },
      });
    } else {
      // Also emit a general SRV-001 alongside the specific SRV-002/SRV-003 findings
      findings.push({
        ruleId: 'SRV-001',
        message:
          `Server schema changed: ${addedTools.length} tool(s) added, ${removedTools.length} tool(s) removed.`,
        severity: 'high',
        category: 'rug-pull',
        confidence: 0.95,
        metadata: {
          previousHash: existingPin.schemaHash,
          currentHash: schemaHash,
          addedTools,
          removedTools,
          previousToolNames: existingPin.toolNames,
          currentToolNames: currentNames,
        },
      });
    }

    // Update the pin to the new schema
    this.store.setServerPin({
      schemaHash,
      toolNames: currentNames,
      pinnedAt: existingPin.pinnedAt,
    });

    log.warn(
      `Server schema changed: hash ${existingPin.schemaHash.slice(0, 12)}... → ${schemaHash.slice(0, 12)}...`,
    );

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

  /** Get the server-level schema pin (for CLI inspection). */
  getServerPin(): ServerPin | null {
    return this.store.getServerPin();
  }
}
