/**
 * Audit logging for tool calls.
 *
 * MCP communicates over stdio, so stdout is reserved for the protocol. Audit
 * records are written as newline-delimited JSON to stderr, where the host
 * (or a shell redirect) can capture them without disturbing the MCP stream.
 *
 * A record is emitted for every tool call with: tool name, connection, elapsed
 * time, row count, and outcome. Slow queries and write attempts (on read-only
 * connections) are flagged so they can be reviewed.
 */

export interface AuditRecord {
  ts: string;
  tool: string;
  connection?: string;
  dbType?: string;
  elapsedMs: number;
  ok: boolean;
  error?: string;
  rowCount?: number;
  truncated?: boolean;
  slow?: boolean;
  writeAttempt?: boolean;
  /** Classified statement type (read/insert/update/delete/ddl/...). */
  stmtType?: string;
  /** Columns that were masked before the result was returned. */
  maskedColumns?: string[];
  /** True when the byte cap dropped one or more rows. */
  truncatedByBytes?: boolean;
  /** True when a per-call maxRows override was clamped to the connection cap. */
  maxRowsClamped?: boolean;
}

function write(record: AuditRecord): void {
  try {
    process.stderr.write(JSON.stringify(record) + '\n');
  } catch {
    /* never let logging break a tool call */
  }
}

export function auditCall(
  tool: string,
  opts: {
    connection?: string;
    dbType?: string;
    elapsedMs: number;
    ok: boolean;
    error?: string;
    rowCount?: number;
    truncated?: boolean;
    slow?: boolean;
    writeAttempt?: boolean;
    stmtType?: string;
    maskedColumns?: string[];
    truncatedByBytes?: boolean;
    maxRowsClamped?: boolean;
  }
): void {
  write({
    ts: new Date().toISOString(),
    tool,
    ...opts,
  });
}

/** Slow-query threshold in ms (matches DM_SLOW_QUERY_MS convention). */
export function slowQueryThresholdMs(): number {
  const n = Number.parseInt(process.env.MULTIDB_SLOW_QUERY_MS ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : 1000;
}
