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

import { createHmac, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import Database from 'better-sqlite3';
import { CREATE_EVENTS_TABLE, CREATE_INDEXES, MIGRATE_ADD_HMAC, type EventRow } from './schema.js';
import { createLogger } from '../logger.js';

const log = createLogger('audit-storage');

const GENESIS_HMAC = 'genesis';
const PRUNE_CHECK_INTERVAL = 100;
const PRUNE_TARGET_RATIO = 0.8;

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

export interface ChainVerifyResult {
  valid: boolean;
  brokenAt?: number;
}

/**
 * Read or create the HMAC key used for audit log integrity.
 * The key is stored as hex in `<dataDir>/hmac.key`.
 */
export function getOrCreateHmacKey(dataDir: string): string {
  const keyPath = resolve(dataDir, 'hmac.key');

  if (existsSync(keyPath)) {
    return readFileSync(keyPath, 'utf-8').trim();
  }

  mkdirSync(dataDir, { recursive: true });
  const key = randomBytes(32).toString('hex');
  writeFileSync(keyPath, key, { mode: 0o600 });
  return key;
}

/**
 * Compute the HMAC for an audit event row.
 */
function computeHmac(
  key: string,
  prevHmac: string,
  timestamp: number,
  direction: string,
  decision: string,
  score: number,
  findings: string,
  message: string,
): string {
  const payload = `${prevHmac}|${timestamp}|${direction}|${decision}|${score}|${findings}|${message}`;
  return createHmac('sha256', key).update(payload).digest('hex');
}

/** Method marker used in synthetic prune events to anchor the HMAC chain. */
const PRUNE_MARKER_METHOD = '__mcp_fence_prune_marker';

export class SqliteAuditStore implements AuditStore {
  private readonly db: Database.Database;
  private readonly insertStmt: Database.Statement;
  private readonly dbPath: string;
  private hmacKey: string | null = null;
  private lastHmac: string = GENESIS_HMAC;
  private insertCount = 0;
  private maxDbSizeBytes = 100 * 1024 * 1024; // 100 MB default

  constructor(dbPath: string, options?: { hmacKey?: string; maxDbSizeMb?: number }) {
    this.dbPath = dbPath;
    this.db = new Database(dbPath);

    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');

    this.db.exec(CREATE_EVENTS_TABLE);
    for (const sql of CREATE_INDEXES) {
      this.db.exec(sql);
    }

    // Migrate: add HMAC columns if they don't exist
    this.migrateHmacColumns();

    this.insertStmt = this.db.prepare(`
      INSERT INTO events (timestamp, direction, method, tool_name, decision, score, findings, message, hmac, prev_hmac)
      VALUES (@timestamp, @direction, @method, @toolName, @decision, @score, @findings, @message, @hmac, @prevHmac)
    `);

    if (options?.hmacKey) {
      this.hmacKey = options.hmacKey;
      this.loadLastHmac();
    }

    if (options?.maxDbSizeMb != null) {
      this.maxDbSizeBytes = options.maxDbSizeMb * 1024 * 1024;
    }

    log.info(`Audit storage initialized: ${dbPath}`);
  }

  /** Enable HMAC chain with the given key. Must be called before inserts if not passed via constructor. */
  setHmacKey(key: string): void {
    this.hmacKey = key;
    this.loadLastHmac();
  }

  /** Set the maximum DB size in megabytes. */
  setMaxDbSizeMb(mb: number): void {
    this.maxDbSizeBytes = mb * 1024 * 1024;
  }

  insert(event: AuditEvent): void {
    let hmac: string | null = null;
    let prevHmac: string | null = null;

    if (this.hmacKey) {
      prevHmac = this.lastHmac;
      hmac = computeHmac(
        this.hmacKey,
        prevHmac,
        event.timestamp,
        event.direction,
        event.decision,
        event.score,
        event.findings,
        event.message ?? '',
      );
      this.lastHmac = hmac;
    }

    this.insertStmt.run({
      timestamp: event.timestamp,
      direction: event.direction,
      method: event.method ?? null,
      toolName: event.toolName ?? null,
      decision: event.decision,
      score: event.score,
      findings: event.findings,
      message: event.message ?? null,
      hmac,
      prevHmac,
    });

    this.insertCount++;
    if (this.insertCount % PRUNE_CHECK_INTERVAL === 0) {
      this.pruneIfNeeded();
    }
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

  /**
   * Verify the HMAC hash chain integrity.
   * Returns { valid: true } if the chain is intact, or { valid: false, brokenAt: id }
   * indicating the first event where the chain breaks.
   */
  verifyChain(hmacKey: string): ChainVerifyResult {
    const rows = this.db.prepare(
      'SELECT id, timestamp, direction, method, decision, score, findings, message, hmac, prev_hmac FROM events ORDER BY id ASC',
    ).all() as Array<{
      id: number;
      timestamp: number;
      direction: string;
      method: string | null;
      decision: string;
      score: number;
      findings: string;
      message: string | null;
      hmac: string | null;
      prev_hmac: string | null;
    }>;

    let expectedPrevHmac = GENESIS_HMAC;

    for (const row of rows) {
      if (row.hmac == null || row.prev_hmac == null) {
        // Events inserted before HMAC was enabled are skipped (legacy)
        continue;
      }

      // Prune markers reset the chain — their prev_hmac becomes the new anchor
      if (row.method === PRUNE_MARKER_METHOD) {
        expectedPrevHmac = row.prev_hmac;
      }

      if (row.prev_hmac !== expectedPrevHmac) {
        // Check if this is a legacy event (HMAC computed without message column).
        // Legacy events use the old 6-field payload; try to verify with that format.
        const legacyPayload = `${row.prev_hmac}|${row.timestamp}|${row.direction}|${row.decision}|${row.score}|${row.findings}`;
        const legacyHmac = createHmac('sha256', hmacKey).update(legacyPayload).digest('hex');
        if (row.hmac === legacyHmac) {
          expectedPrevHmac = row.hmac;
          continue;
        }
        return { valid: false, brokenAt: row.id };
      }

      const expected = computeHmac(
        hmacKey,
        row.prev_hmac,
        row.timestamp,
        row.direction,
        row.decision,
        row.score,
        row.findings,
        row.message ?? '',
      );

      if (row.hmac !== expected) {
        // Try legacy format (without message) for backward compatibility
        const legacyPayload = `${row.prev_hmac}|${row.timestamp}|${row.direction}|${row.decision}|${row.score}|${row.findings}`;
        const legacyHmac = createHmac('sha256', hmacKey).update(legacyPayload).digest('hex');
        if (row.hmac === legacyHmac) {
          expectedPrevHmac = row.hmac;
          continue;
        }
        return { valid: false, brokenAt: row.id };
      }

      expectedPrevHmac = row.hmac;
    }

    return { valid: true };
  }

  close(): void {
    this.db.close();
    log.info('Audit storage closed');
  }

  /** Expose the DB path for size checks in tests. */
  getDbPath(): string {
    return this.dbPath;
  }

  private migrateHmacColumns(): void {
    const tableInfo = this.db.prepare("PRAGMA table_info('events')").all() as Array<{ name: string }>;
    const hasHmac = tableInfo.some((col) => col.name === 'hmac');
    if (!hasHmac) {
      for (const sql of MIGRATE_ADD_HMAC) {
        try {
          this.db.exec(sql);
        } catch {
          // Column may already exist in some edge cases
        }
      }
    }
  }

  private loadLastHmac(): void {
    const row = this.db.prepare(
      'SELECT hmac FROM events WHERE hmac IS NOT NULL ORDER BY id DESC LIMIT 1',
    ).get() as { hmac: string } | undefined;

    this.lastHmac = row?.hmac ?? GENESIS_HMAC;
  }

  private pruneIfNeeded(): void {
    try {
      const stat = statSync(this.dbPath);
      if (stat.size <= this.maxDbSizeBytes) return;

      const targetSize = Math.floor(this.maxDbSizeBytes * PRUNE_TARGET_RATIO);
      const totalCount = this.count();
      // Estimate how many rows to delete based on proportional size
      const ratio = 1 - targetSize / stat.size;
      const deleteCount = Math.ceil(totalCount * ratio);

      if (deleteCount <= 0) return;

      log.warn(`Audit DB size (${(stat.size / 1024 / 1024).toFixed(1)}MB) exceeds limit (${(this.maxDbSizeBytes / 1024 / 1024).toFixed(0)}MB). Pruning ${deleteCount} oldest events.`);

      this.db.prepare(
        'DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)',
      ).run(deleteCount);

      // Find the HMAC of the last surviving event to anchor the prune marker.
      const lastSurvivor = this.db.prepare(
        'SELECT hmac FROM events WHERE hmac IS NOT NULL ORDER BY id DESC LIMIT 1',
      ).get() as { hmac: string } | undefined;

      // Reset the chain state so the prune marker links to the surviving chain.
      this.lastHmac = lastSurvivor?.hmac ?? GENESIS_HMAC;

      // Insert a prune marker event that re-anchors the HMAC chain after pruning.
      this.insert({
        timestamp: Date.now(),
        direction: 'request',
        method: PRUNE_MARKER_METHOD,
        decision: 'allow',
        score: 0,
        findings: '[]',
      });

      // Reclaim space
      this.db.pragma('wal_checkpoint(TRUNCATE)');
    } catch (err) {
      log.error('Failed to prune audit DB', err instanceof Error ? err : new Error(String(err)));
    }
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
