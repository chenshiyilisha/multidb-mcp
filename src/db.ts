/**
 * Multi-database access layer.
 *
 * A single Database interface is implemented by:
 *   - DamengDatabase     (dmdb driver)        -> Dameng DM8
 *   - SqlServerDatabase  (mssql driver)       -> Microsoft SQL Server
 *   - MysqlDatabase      (mysql2/promise)     -> MySQL / MariaDB
 *
 * All three return row objects keyed by column name so the MCP tool layer
 * stays database-agnostic.
 *
 * Production-grade hardening applied here:
 *   - Connection pooling (mysql2 pool / mssql pool / dmdb reused conn)
 *   - A DB-agnostic query timeout via Promise.race, so a slow query can
 *     never hang the MCP stdio loop (the underlying statement may keep
 *     running on the server, but the client gets a timely error).
 *   - Every query result is normalized (values -> JSON-safe, row count,
 *     truncation flag, elapsed ms) for the audit layer.
 */

import type { ConnectionConfig } from './config.js';
import { classifySql, toNamedPlaceholders } from './security.js';

export interface TableColumn {
  name: string;
  type: string;
  length: number | null;
  nullable: boolean;
  default: string | null;
  comment: string;
}

export interface TableInfo {
  table: string;
  schema: string;
  columns: TableColumn[];
}

export interface QueryResult {
  columns: string[];
  rows: Record<string, unknown>[];
  rowCount: number;
  truncated: boolean;
  elapsedMs: number;
}

export interface Database {
  readonly type: string;
  connect(): Promise<void>;
  close(): Promise<void>;
  testConnection(): Promise<{ version: string; schema: string }>;
  listTables(schema: string): Promise<string[]>;
  describeTable(table: string, schema: string): Promise<TableInfo>;
  executeSql(sql: string, maxRows: number, params?: unknown[]): Promise<QueryResult>;
}

/* --------------------------- helpers --------------------------- */

/** Convert any driver-specific value into something JSON-serializable. */
function toJsonable(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'bigint') return Number(value);
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Buffer) return value.toString('base64');
  if (typeof value === 'object') {
    const o: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      o[k] = toJsonable(v);
    }
    return o;
  }
  return value;
}

/**
 * Run an async operation with a hard timeout. On timeout the promise rejects
 * with a TimeoutError while the original operation continues in the background
 * (best-effort: guarantees the MCP client is never blocked indefinitely).
 */
export class QueryTimeoutError extends Error {
  constructor(ms: number) {
    super(`query timed out after ${ms} ms`);
    this.name = 'QueryTimeoutError';
  }
}

async function withTimeout<T>(ms: number, fn: () => Promise<T>): Promise<T> {
  if (!ms || ms <= 0) return fn();
  let timer: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new QueryTimeoutError(ms)), ms);
  });
  try {
    return await Promise.race([fn(), timeout]);
  } finally {
    clearTimeout(timer!);
  }
}

/**
 * A timed-out query is NOT cancelled by Promise.race — the driver may still be
 * reading rows on the same socket/pool connection when the next tool call
 * starts. That can interleave results (Dameng keeps one long-lived connection)
 * or return a late result to the wrong caller. Mark the Database instance as
 * poisoned on timeout so the next call drops and rebuilds its connection.
 */
async function withTimeoutAndReset<T>(
  ms: number,
  fn: () => Promise<T>,
  onTimeout: () => void
): Promise<T> {
  try {
    return await withTimeout(ms, fn);
  } catch (e) {
    if (e instanceof QueryTimeoutError) onTimeout();
    throw e;
  }
}

/** Escape a SQL string literal for inline use (identifiers are validated upstream). */
function quoteLiteral(v: string): string {
  return `'${v.replace(/'/g, "''")}'`;
}

/**
 * Detect an error that means "the underlying connection/socket is dead" as
 * opposed to a SQL/logic error. Used to decide whether rebuilding the pool/
 * connection could help; a bad SQL should never trigger a reconnect.
 */
export function isConnectionLostError(e: unknown): boolean {
  const err = e as { code?: string; message?: string; name?: string } | null;
  const code = String(err?.code ?? '');
  const msg = String(err?.message ?? '');
  return (
    [
      'ECONNRESET', 'ECONNREFUSED', 'ENOTFOUND', 'EHOSTUNREACH', 'ESOCKET',
      'EPIPE', 'PROTOCOL_CONNECTION_LOST', 'ERR_SERVER_GONE', 'ER_SERVER_SHUTDOWN',
      'CONNECTION_CLOSED', 'CONNECTION_LOST', 'ConnectionError',
    ].includes(code) ||
    err?.name === 'ConnectionError' ||
    /connection.*(lost|closed|reset|terminated)|socket hang up|server has gone away|closed connection|connection is closed|cannot read.*socket|write.*epipe/i.test(
      msg
    )
  );
}

/* ------------------------------- Dameng ------------------------------- */

class DamengDatabase implements Database {
  readonly type = 'dameng';
  private conn: any = null;
  private readonly cfg: ConnectionConfig;
  /** Set by a timeout; the next call must drop the connection before reuse. */
  private needsReset = false;

  constructor(cfg: ConnectionConfig) {
    this.cfg = cfg;
  }

  private async timed<T>(fn: () => Promise<T>): Promise<T> {
    return withTimeoutAndReset(this.cfg.queryTimeoutMs, fn, () => { this.needsReset = true; });
  }

  private async resetIfNeeded(): Promise<void> {
    if (!this.needsReset) return;
    this.needsReset = false;
    await this.close();
  }

  async connect(): Promise<void> {
    if (this.conn) return;
    const db = (await import('dmdb')).default;
    const connStr = `dm://${encodeURIComponent(this.cfg.user)}:${encodeURIComponent(this.cfg.password)}@${this.cfg.host}:${this.cfg.port}?schema=${encodeURIComponent(this.cfg.schema)}`;
    this.conn = await db.getConnection(connStr);
  }

  async close(): Promise<void> {
    if (this.conn) {
      try {
        await this.conn.close();
      } catch {
        /* ignore */
      }
      this.conn = null;
    }
  }

  /**
   * Return a live connection, transparently reconnecting once if the socket
   * went stale (DB restart / idle reaping). Dameng keeps a single long-lived
   * connection, so unlike a pool it cannot self-heal — `ping()` is the driver's
   * own liveness probe, far more reliable than assuming `conn != null` means
   * alive. NOTE: `connect()` never calls this method, so no recursion.
   */
  private async ensure(): Promise<any> {
    if (!this.conn) {
      await this.connect();
      return this.conn;
    }
    try {
      if (typeof this.conn.ping === 'function') {
        await this.conn.ping();
      }
      return this.conn;
    } catch {
      // Stale: drop it and establish a fresh connection once. If this also
      // fails, the error propagates (structured error layer redacts it).
      await this.close();
      await this.connect();
      return this.conn;
    }
  }

  private async run(sql: string, binds: unknown[] = []): Promise<any> {
    await this.resetIfNeeded();
    const db = (await import('dmdb')).default;
    const opts = { outFormat: db.OUT_FORMAT_OBJECT };
    let conn = await this.ensure();
    try {
      return await conn.execute(sql, binds, opts);
    } catch (e) {
      if (!isConnectionLostError(e)) throw e;
      // Race: connection died between ensure()'s ping and execute(). Rebuild
      // once. Retry ONLY a statement the shared classifier calls read-only —
      // replaying a write after a lost connection could duplicate an
      // INSERT/UPDATE whose commit actually succeeded. Using classifySql (not
      // a SELECT-only regex) keeps WITH/SHOW/EXPLAIN safe and refuses CTEs
      // that hide DML. Callers of write statements get the error to handle.
      if (classifySql(sql) !== 'read') throw e;
      await this.close();
      await this.connect();
      conn = this.conn;
      return conn.execute(sql, binds, opts);
    }
  }

  async testConnection(): Promise<{ version: string; schema: string }> {
    const res = await this.timed(() => this.run("SELECT BANNER FROM V$VERSION WHERE ROWNUM <= 1"));
    const version = res.rows[0]?.BANNER ?? 'DM (unknown version)';
    let schema = this.cfg.schema;
    try {
      const s = await this.timed(() => this.run("SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') AS SCH FROM DUAL"));
      schema = s.rows[0]?.SCH || schema;
    } catch {
      /* keep configured schema */
    }
    return { version, schema };
  }

  async listTables(schema: string): Promise<string[]> {
    const res = await this.timed(() => this.run(
      'SELECT TABLE_NAME FROM ALL_TABLES WHERE UPPER(OWNER) = UPPER(?) ORDER BY TABLE_NAME',
      [schema]
    ));
    return res.rows.map((r: any) => r.TABLE_NAME);
  }

  async describeTable(table: string, schema: string): Promise<TableInfo> {
    const res = await this.timed(() => this.run(
      `SELECT COLUMN_NAME, DATA_TYPE, CHAR_LENGTH, NULLABLE, DATA_DEFAULT,
              (SELECT COMMENTS FROM ALL_COL_COMMENTS
                WHERE OWNER = ? AND TABLE_NAME = ? AND COLUMN_NAME = A.COLUMN_NAME) AS CMT
         FROM ALL_TAB_COLUMNS A
        WHERE UPPER(OWNER) = UPPER(?) AND UPPER(TABLE_NAME) = UPPER(?)
        ORDER BY COLUMN_ID`,
      [schema, schema, table, table]
    ));
    const columns: TableColumn[] = res.rows.map((r: any) => ({
      name: r.COLUMN_NAME,
      type: r.DATA_TYPE,
      length: r.CHAR_LENGTH ?? null,
      nullable: r.NULLABLE === 'Y',
      default: r.DATA_DEFAULT ?? null,
      comment: r.CMT ?? '',
    }));
    return { table, schema, columns };
  }

  async executeSql(sql: string, maxRows: number, params?: unknown[]): Promise<QueryResult> {
    const start = Date.now();
    const res = await this.timed(() => this.run(sql, params));
    const all: Record<string, unknown>[] = (res.rows || []).map((r: any) => toJsonable(r));
    const truncated = all.length > maxRows;
    return {
      columns: res.metaData ? res.metaData.map((m: any) => m.name) : Object.keys(all[0] ?? {}),
      rows: truncated ? all.slice(0, maxRows) : all,
      rowCount: all.length,
      truncated,
      elapsedMs: Date.now() - start,
    };
  }
}

/* ------------------------------ SQL Server ------------------------------ */

class SqlServerDatabase implements Database {
  readonly type = 'sqlserver';
  private pool: any = null;
  private readonly cfg: ConnectionConfig;
  private needsReset = false;

  constructor(cfg: ConnectionConfig) {
    this.cfg = cfg;
  }

  private async timed<T>(fn: () => Promise<T>): Promise<T> {
    return withTimeoutAndReset(this.cfg.queryTimeoutMs, fn, () => { this.needsReset = true; });
  }

  private async resetIfNeeded(): Promise<void> {
    if (!this.needsReset) return;
    this.needsReset = false;
    await this.close();
  }

  async connect(): Promise<void> {
    if (this.pool) return;
    const sql = (await import('mssql')).default;
    this.pool = await sql.connect({
      server: this.cfg.host,
      port: this.cfg.port,
      database: this.cfg.schema,
      user: this.cfg.user,
      password: this.cfg.password,
      // Internal/test SQL Servers commonly use a self-signed cert; trust it
      // while keeping encryption on. These are tedious options -> `options`.
      options: {
        encrypt: process.env.MSSQL_ENCRYPT !== 'false',
        trustServerCertificate: process.env.MSSQL_TRUST_CERT !== 'false',
      },
      connectionTimeout: 15000,
      requestTimeout: this.cfg.queryTimeoutMs > 0 ? this.cfg.queryTimeoutMs : 30000,
    });
  }

  async close(): Promise<void> {
    if (this.pool) {
      try {
        await this.pool.close();
      } catch {
        /* ignore */
      }
      this.pool = null;
    }
  }

  private async run(sql: string, params?: unknown[]): Promise<any> {
    await this.resetIfNeeded();
    if (!this.pool) await this.connect();
    const request = this.pool.request();
    if (params && params.length > 0) {
      // mssql/tedious binds via named @pN parameters, not positional '?'.
      params.forEach((v, i) => request.input(`p${i + 1}`, v));
      return request.query(toNamedPlaceholders(sql));
    }
    return request.query(sql);
  }

  async testConnection(): Promise<{ version: string; schema: string }> {
    const res = await this.timed(() => this.run('SELECT @@VERSION AS VERSION'));
    const version = String(res.recordset[0]?.VERSION ?? 'SQL Server (unknown version)');
    return { version, schema: this.cfg.schema };
  }

  async listTables(schema: string): Promise<string[]> {
    // schema is an identifier already validated by checkIdentifier; safe to inline.
    const res = await this.timed(() => this.run(
      `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_TYPE = 'BASE TABLE' AND UPPER(TABLE_SCHEMA) = UPPER(${quoteLiteral(schema)})
        ORDER BY TABLE_NAME`
    ));
    return res.recordset.map((r: any) => r.TABLE_NAME);
  }

  async describeTable(table: string, schema: string): Promise<TableInfo> {
    const res = await this.timed(() => this.run(
      `SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_DEFAULT
         FROM INFORMATION_SCHEMA.COLUMNS
        WHERE UPPER(TABLE_NAME) = UPPER(${quoteLiteral(table)})
          AND UPPER(TABLE_SCHEMA) = UPPER(${quoteLiteral(schema)})
        ORDER BY ORDINAL_POSITION`
    ));
    const columns: TableColumn[] = res.recordset.map((r: any) => ({
      name: r.COLUMN_NAME,
      type: r.DATA_TYPE,
      length: r.CHARACTER_MAXIMUM_LENGTH ?? null,
      nullable: r.IS_NULLABLE === 'YES',
      default: r.COLUMN_DEFAULT ?? null,
      comment: '',
    }));
    return { table, schema, columns };
  }

  async executeSql(sql: string, maxRows: number, params?: unknown[]): Promise<QueryResult> {
    const start = Date.now();
    const res = await this.timed(() => this.run(sql, params));
    const rs = res.recordset;
    const columns = rs && rs.length > 0 ? Object.keys(rs[0]) : [];
    const all: Record<string, unknown>[] = rs ? rs.map((r: any) => toJsonable(r)) : [];
    const truncated = all.length > maxRows;
    return {
      columns,
      rows: truncated ? all.slice(0, maxRows) : all,
      rowCount: all.length,
      truncated,
      elapsedMs: Date.now() - start,
    };
  }
}

/* ------------------------------- MySQL ------------------------------- */

class MysqlDatabase implements Database {
  readonly type = 'mysql';
  private pool: any = null;
  private readonly cfg: ConnectionConfig;
  private needsReset = false;

  constructor(cfg: ConnectionConfig) {
    this.cfg = cfg;
  }

  private async timed<T>(fn: () => Promise<T>): Promise<T> {
    return withTimeoutAndReset(this.cfg.queryTimeoutMs, fn, () => { this.needsReset = true; });
  }

  private async resetIfNeeded(): Promise<void> {
    if (!this.needsReset) return;
    this.needsReset = false;
    await this.close();
  }

  async connect(): Promise<void> {
    if (this.pool) return;
    const mysql = (await import('mysql2/promise')).default;
    this.pool = mysql.createPool({
      host: this.cfg.host,
      port: this.cfg.port,
      user: this.cfg.user,
      password: this.cfg.password,
      database: this.cfg.schema,
      waitForConnections: true,
      connectionLimit: 8,
      queueLimit: 0,
      connectTimeout: 15000,
      enableKeepAlive: true,
      keepAliveInitialDelay: 0,
    });
  }

  async close(): Promise<void> {
    if (this.pool) {
      try {
        await this.pool.end();
      } catch {
        /* ignore */
      }
      this.pool = null;
    }
  }

  private async run(sql: string, binds: unknown[] = []): Promise<any> {
    await this.resetIfNeeded();
    if (!this.pool) await this.connect();
    return this.pool.query(sql, binds);
  }

  async testConnection(): Promise<{ version: string; schema: string }> {
    const [rows] = await this.timed(() => this.run('SELECT VERSION() AS V'));
    const version = `MySQL ${String(rows[0]?.V ?? '(unknown version)')}`;
    return { version, schema: this.cfg.schema };
  }

  async listTables(schema: string): Promise<string[]> {
    const [rows] = await this.timed(() => this.run(
      `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'
        ORDER BY TABLE_NAME`,
      [schema]
    ));
    return rows.map((r: any) => r.TABLE_NAME);
  }

  async describeTable(table: string, schema: string): Promise<TableInfo> {
    const [rows] = await this.timed(() => this.run(
      `SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_COMMENT
         FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
        ORDER BY ORDINAL_POSITION`,
      [schema, table]
    ));
    const columns: TableColumn[] = rows.map((r: any) => ({
      name: r.COLUMN_NAME,
      type: r.DATA_TYPE,
      length: r.CHARACTER_MAXIMUM_LENGTH ?? null,
      nullable: r.IS_NULLABLE === 'YES',
      default: r.COLUMN_DEFAULT ?? null,
      comment: r.COLUMN_COMMENT ?? '',
    }));
    return { table, schema, columns };
  }

  async executeSql(sql: string, maxRows: number, params?: unknown[]): Promise<QueryResult> {
    const start = Date.now();
    const [result] = await this.timed(() => this.run(sql, params));
    const rows: any = Array.isArray(result) ? result : [];
    const all: Record<string, unknown>[] = rows.map((r: any) => toJsonable(r));
    const truncated = all.length > maxRows;
    return {
      columns: all.length > 0 ? Object.keys(all[0]) : [],
      rows: truncated ? all.slice(0, maxRows) : all,
      rowCount: all.length,
      truncated,
      elapsedMs: Date.now() - start,
    };
  }
}

/* ------------------------------ factory ------------------------------ */

export function createDatabase(cfg: ConnectionConfig): Database {
  switch (cfg.type) {
    case 'dameng':
      return new DamengDatabase(cfg);
    case 'sqlserver':
      return new SqlServerDatabase(cfg);
    case 'mysql':
      return new MysqlDatabase(cfg);
    default:
      throw new Error(`unsupported database type: ${cfg.type}`);
  }
}
