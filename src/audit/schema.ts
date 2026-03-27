/** SQL to create the events table. */
export const CREATE_EVENTS_TABLE = `
  CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  INTEGER NOT NULL,
    direction  TEXT    NOT NULL CHECK(direction IN ('request', 'response')),
    method     TEXT,
    tool_name  TEXT,
    decision   TEXT    NOT NULL CHECK(decision IN ('allow', 'block', 'warn')),
    score      REAL    NOT NULL,
    findings   TEXT    NOT NULL DEFAULT '[]',
    message    TEXT
  )
`;

/** SQL to create indexes for common queries. */
export const CREATE_INDEXES = [
  `CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)`,
  `CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision)`,
  `CREATE INDEX IF NOT EXISTS idx_events_direction ON events(direction)`,
];

/** Row shape returned by SELECT queries. */
export interface EventRow {
  id: number;
  timestamp: number;
  direction: string;
  method: string | null;
  tool_name: string | null;
  decision: string;
  score: number;
  findings: string;
  message: string | null;
}
