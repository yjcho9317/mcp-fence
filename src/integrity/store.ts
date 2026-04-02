/**
 * In-memory hash store for tool description pinning.
 * Tracks original descriptions to detect gradual drift (boiling frog).
 */

import { createLogger } from '../logger.js';

const log = createLogger('integrity');

export interface PinnedTool {
  name: string;
  hash: string;
  pinnedAt: number;
  description: string;
  /** Original hash from the very first pin (never changes) */
  originalHash: string;
  /** Original description from the very first pin */
  originalDescription: string;
  /** Number of times the description has changed */
  changeCount: number;
}

export interface HashStore {
  /** Get the pinned hash for a tool. Returns null if not pinned. */
  get(toolName: string): PinnedTool | null;
  /** Pin a tool's description hash. Returns false if already pinned with a different hash. */
  pin(toolName: string, hash: string, description: string): boolean;
  /** Check if a tool is already pinned. */
  has(toolName: string): boolean;
  /** Get all pinned tools. */
  getAll(): PinnedTool[];
  /** Clear all pinned hashes (for testing or reset). */
  clear(): void;
}

/**
 * In-memory implementation of HashStore.
 */
export class MemoryHashStore implements HashStore {
  private readonly store = new Map<string, PinnedTool>();

  get(toolName: string): PinnedTool | null {
    return this.store.get(toolName) ?? null;
  }

  pin(toolName: string, hash: string, description: string): boolean {
    const existing = this.store.get(toolName);

    if (existing) {
      if (existing.hash === hash) {
        return true; // Same hash, no change
      }
      // Different hash — rug-pull detected. Update the pin to the new hash
      // so subsequent checks compare against the latest known description.
      log.warn(`Hash mismatch for tool "${toolName}": pinned=${existing.hash.slice(0, 8)}... new=${hash.slice(0, 8)}... (change #${existing.changeCount + 1})`);
      this.store.set(toolName, {
        name: toolName,
        hash,
        pinnedAt: existing.pinnedAt,
        description,
        originalHash: existing.originalHash,
        originalDescription: existing.originalDescription,
        changeCount: existing.changeCount + 1,
      });
      return false;
    }

    this.store.set(toolName, {
      name: toolName,
      hash,
      pinnedAt: Date.now(),
      description,
      originalHash: hash,
      originalDescription: description,
      changeCount: 0,
    });
    log.debug(`Pinned tool "${toolName}": ${hash.slice(0, 12)}...`);
    return true;
  }

  has(toolName: string): boolean {
    return this.store.has(toolName);
  }

  getAll(): PinnedTool[] {
    return Array.from(this.store.values());
  }

  clear(): void {
    this.store.clear();
  }
}
