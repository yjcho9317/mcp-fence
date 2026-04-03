/**
 * SQLite-backed hash store for persistent tool description pinning.
 *
 * Stores tool pins and server schema pins in the same database as the audit log
 * (~/.mcp-fence/audit.db). Pins survive proxy restarts, closing the TOFU gap
 * where MemoryHashStore lost all pins on every restart.
 */

import Database from 'better-sqlite3';
import type { HashStore, PinnedTool, ServerPin } from './store.js';
import { createLogger } from '../logger.js';

const log = createLogger('integrity:sqlite');

const CREATE_TOOL_PINS_TABLE = `
  CREATE TABLE IF NOT EXISTS tool_pins (
    name              TEXT PRIMARY KEY,
    hash              TEXT NOT NULL,
    pinned_at         INTEGER NOT NULL,
    description       TEXT NOT NULL,
    original_hash     TEXT NOT NULL,
    original_description TEXT NOT NULL,
    change_count      INTEGER NOT NULL DEFAULT 0
  )
`;

const CREATE_SERVER_PINS_TABLE = `
  CREATE TABLE IF NOT EXISTS server_pins (
    id            INTEGER PRIMARY KEY,
    schema_hash   TEXT NOT NULL,
    tool_names    TEXT NOT NULL,
    pinned_at     INTEGER NOT NULL
  )
`;

/**
 * SQLite-backed implementation of HashStore.
 * Persists tool and server pins across proxy restarts.
 */
export class SqliteHashStore implements HashStore {
  private readonly db: Database.Database;
  private readonly getStmt: Database.Statement;
  private readonly upsertStmt: Database.Statement;
  private readonly hasStmt: Database.Statement;
  private readonly getAllStmt: Database.Statement;
  private readonly getServerPinStmt: Database.Statement;
  private readonly upsertServerPinStmt: Database.Statement;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');

    this.db.exec(CREATE_TOOL_PINS_TABLE);
    this.db.exec(CREATE_SERVER_PINS_TABLE);

    this.getStmt = this.db.prepare(
      'SELECT name, hash, pinned_at, description, original_hash, original_description, change_count FROM tool_pins WHERE name = ?',
    );
    this.upsertStmt = this.db.prepare(`
      INSERT INTO tool_pins (name, hash, pinned_at, description, original_hash, original_description, change_count)
      VALUES (@name, @hash, @pinnedAt, @description, @originalHash, @originalDescription, @changeCount)
      ON CONFLICT(name) DO UPDATE SET
        hash = @hash,
        description = @description,
        change_count = @changeCount
    `);
    this.hasStmt = this.db.prepare('SELECT 1 FROM tool_pins WHERE name = ?');
    this.getAllStmt = this.db.prepare(
      'SELECT name, hash, pinned_at, description, original_hash, original_description, change_count FROM tool_pins',
    );
    this.getServerPinStmt = this.db.prepare(
      'SELECT id, schema_hash, tool_names, pinned_at FROM server_pins ORDER BY id DESC LIMIT 1',
    );
    this.upsertServerPinStmt = this.db.prepare(`
      INSERT OR REPLACE INTO server_pins (id, schema_hash, tool_names, pinned_at)
      VALUES (1, @schemaHash, @toolNames, @pinnedAt)
    `);

    log.debug(`SQLite hash store initialized: ${dbPath}`);
  }

  get(toolName: string): PinnedTool | null {
    const row = this.getStmt.get(toolName) as {
      name: string;
      hash: string;
      pinned_at: number;
      description: string;
      original_hash: string;
      original_description: string;
      change_count: number;
    } | undefined;

    if (!row) return null;

    return {
      name: row.name,
      hash: row.hash,
      pinnedAt: row.pinned_at,
      description: row.description,
      originalHash: row.original_hash,
      originalDescription: row.original_description,
      changeCount: row.change_count,
    };
  }

  pin(toolName: string, hash: string, description: string): boolean {
    const existing = this.get(toolName);

    if (existing) {
      if (existing.hash === hash) {
        return true;
      }
      log.warn(
        `Hash mismatch for tool "${toolName}": pinned=${existing.hash.slice(0, 8)}... new=${hash.slice(0, 8)}... (change #${existing.changeCount + 1})`,
      );
      this.upsertStmt.run({
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

    this.upsertStmt.run({
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
    return this.hasStmt.get(toolName) != null;
  }

  getAll(): PinnedTool[] {
    const rows = this.getAllStmt.all() as Array<{
      name: string;
      hash: string;
      pinned_at: number;
      description: string;
      original_hash: string;
      original_description: string;
      change_count: number;
    }>;

    return rows.map((row) => ({
      name: row.name,
      hash: row.hash,
      pinnedAt: row.pinned_at,
      description: row.description,
      originalHash: row.original_hash,
      originalDescription: row.original_description,
      changeCount: row.change_count,
    }));
  }

  clear(): void {
    this.db.exec('DELETE FROM tool_pins');
    this.db.exec('DELETE FROM server_pins');
  }

  getServerPin(): ServerPin | null {
    const row = this.getServerPinStmt.get() as {
      id: number;
      schema_hash: string;
      tool_names: string;
      pinned_at: number;
    } | undefined;

    if (!row) return null;

    return {
      schemaHash: row.schema_hash,
      toolNames: JSON.parse(row.tool_names) as string[],
      pinnedAt: row.pinned_at,
    };
  }

  setServerPin(pin: ServerPin): boolean {
    const existing = this.getServerPin();

    if (existing !== null && existing.schemaHash !== pin.schemaHash) {
      log.warn(
        `Server schema changed: pinned=${existing.schemaHash.slice(0, 8)}... ` +
        `new=${pin.schemaHash.slice(0, 8)}...`,
      );
      this.upsertServerPinStmt.run({
        schemaHash: pin.schemaHash,
        toolNames: JSON.stringify(pin.toolNames),
        pinnedAt: pin.pinnedAt,
      });
      return false;
    }

    if (existing === null) {
      this.upsertServerPinStmt.run({
        schemaHash: pin.schemaHash,
        toolNames: JSON.stringify(pin.toolNames),
        pinnedAt: pin.pinnedAt,
      });
      log.debug(`Pinned server schema: ${pin.schemaHash.slice(0, 12)}...`);
    }
    return true;
  }

  close(): void {
    this.db.close();
  }
}
