/**
 * Session-level tool call tracker for mcp-fence.
 *
 * Tracks the sequence of tool calls within a session for use by
 * the data flow policy engine. Resets when the session ends (client disconnect).
 */

import { createLogger } from '../logger.js';

const log = createLogger('session');

/** Maximum number of tool calls retained in session history. */
const MAX_HISTORY_SIZE = 1000;

export class SessionTracker {
  /** Ordered list of tool names called in this session */
  private toolHistory: string[] = [];

  /**
   * Record a tool call. Evicts oldest entries when the history exceeds MAX_HISTORY_SIZE.
   */
  recordToolCall(toolName: string): void {
    this.toolHistory.push(toolName);
    if (this.toolHistory.length > MAX_HISTORY_SIZE) {
      const excess = this.toolHistory.length - MAX_HISTORY_SIZE;
      this.toolHistory.splice(0, excess);
    }
    log.debug(`Session tool history: [${this.toolHistory.join(', ')}]`);
  }

  /**
   * Get all previously called tools (excludes the current call).
   */
  getPreviousTools(): string[] {
    return [...this.toolHistory];
  }

  /**
   * Reset the session state (called on client disconnect).
   */
  reset(): void {
    const count = this.toolHistory.length;
    this.toolHistory = [];
    if (count > 0) {
      log.debug(`Session reset (cleared ${count} tool history entries)`);
    }
  }

  /**
   * Number of tool calls recorded in this session.
   */
  get length(): number {
    return this.toolHistory.length;
  }
}
