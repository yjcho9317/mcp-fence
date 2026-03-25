/**
 * SQLite storage adapter for mcp-fence audit log.
 *
 * Uses better-sqlite3 for synchronous, file-based storage.
 * WAL mode is enabled for better concurrent read performance.
 *
 * This is the concrete storage implementation. The AuditLogger in logger.ts
 * depends on the AuditStore interface, not this class directly — allowing
 * future replacement with PostgreSQL, S3, etc.
 */

import Database from 'better-sqlite3';
import { CREATE_EVENTS_TABLE, CREATE_INDEXES, type EventRow } from './schema.js';
import { createLogger } from '../logger.js';

const log = createLogger('audit-storage');

export interface AuditStore {
  /** Insert an audit event. */
  insert(event: AuditEvent): void;
  /** Query events with optional filters. */
  query(filters?: QueryFilters): EventRow[];
  /** Count events matching filters. */
  count(filters?: QueryFilters): number;
  /** Close the database connection. */
  close(): void;
}

export interface AuditEvent {
  timestamp: number;
  direction: 'request' | 'response';
  method?: string;
  toolName?: string;
  decision: 'allow' | 'block' | 'warn';
  score: number;
  findings: string;
  message?: string;
}

export interface QueryFilters {
  /** Filter by minimum timestamp (epoch ms). */
  since?: number;
  /** Filter by maximum timestamp (epoch ms). */
  until?: number;
  /** Filter by decision type. */
  decision?: 'allow' | 'block' | 'warn';
  /** Filter by direction. */
  direction?: 'request' | 'response';
  /** Filter by minimum score. */
  minScore?: number;
  /** Maximum number of results. */
  limit?: number;
  /** Offset for pagination. */
  offset?: number;
}

export class SqliteAuditStore implements AuditStore {
  private readonly db: Database.Database;
  private readonly insertStmt: Database.Statement;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);

    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');

    this.db.exec(CREATE_EVENTS_TABLE);
    for (const sql of CREATE_INDEXES) {
      this.db.exec(sql);
    }

    this.insertStmt = this.db.prepare(`
      INSERT INTO events (timestamp, direction, method, tool_name, decision, score, findings, message)
      VALUES (@timestamp, @direction, @method, @toolName, @decision, @score, @findings, @message)
    `);

    log.info(`Audit storage initialized: ${dbPath}`);
  }

  insert(event: AuditEvent): void {
    this.insertStmt.run({
      timestamp: event.timestamp,
      direction: event.direction,
      method: event.method ?? null,
      toolName: event.toolName ?? null,
      decision: event.decision,
      score: event.score,
      findings: event.findings,
      message: event.message ?? null,
    });
  }

  query(filters?: QueryFilters): EventRow[] {
    const { sql, params } = this.buildQuery('*', filters);
    return this.db.prepare(sql).all(...params) as EventRow[];
  }

  count(filters?: QueryFilters): number {
    const { sql, params } = this.buildQuery('COUNT(*) as cnt', filters);
    const row = this.db.prepare(sql).get(...params) as { cnt: number };
    return row.cnt;
  }

  close(): void {
    this.db.close();
    log.info('Audit storage closed');
  }

  private buildQuery(
    select: string,
    filters?: QueryFilters,
  ): { sql: string; params: unknown[] } {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (filters?.since != null) {
      conditions.push('timestamp >= ?');
      params.push(filters.since);
    }
    if (filters?.until != null) {
      conditions.push('timestamp <= ?');
      params.push(filters.until);
    }
    if (filters?.decision != null) {
      conditions.push('decision = ?');
      params.push(filters.decision);
    }
    if (filters?.direction != null) {
      conditions.push('direction = ?');
      params.push(filters.direction);
    }
    if (filters?.minScore != null) {
      conditions.push('score >= ?');
      params.push(filters.minScore);
    }

    let sql = `SELECT ${select} FROM events`;
    if (conditions.length > 0) {
      sql += ` WHERE ${conditions.join(' AND ')}`;
    }
    sql += ' ORDER BY timestamp DESC';

    if (filters?.limit != null) {
      sql += ` LIMIT ?`;
      params.push(filters.limit);
    } else if (filters?.offset != null) {
      // SQLite requires LIMIT before OFFSET; use -1 for unlimited
      sql += ` LIMIT -1`;
    }
    if (filters?.offset != null) {
      sql += ` OFFSET ?`;
      params.push(filters.offset);
    }

    return { sql, params };
  }
}
