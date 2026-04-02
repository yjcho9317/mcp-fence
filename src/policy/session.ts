/**
 * Session-level tool call tracker for mcp-fence.
 *
 * Tracks the sequence of tool calls within a session for use by
 * the data flow policy engine. Resets when the session ends (client disconnect).
 */

import { createLogger } from '../logger.js';

const log = createLogger('session');

export class SessionTracker {
  /** Ordered list of tool names called in this session */
  private toolHistory: string[] = [];

  /**
   * Record a tool call.
   */
  recordToolCall(toolName: string): void {
    this.toolHistory.push(toolName);
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
