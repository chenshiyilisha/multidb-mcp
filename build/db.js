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
import { classifySql, toNamedPlaceholders } from './security.js';
/* --------------------------- helpers --------------------------- */
/** Convert any driver-specific value into something JSON-serializable. */
function toJsonable(value) {
    if (value === null || value === undefined)
        return value;
    if (typeof value === 'bigint')
        return Number(value);
    if (value instanceof Date)
        return value.toISOString();
    if (value instanceof Buffer)
        return value.toString('base64');
    if (typeof value === 'object') {
        const o = {};
        for (const [k, v] of Object.entries(value)) {
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
    constructor(ms) {
        super(`query timed out after ${ms} ms`);
        this.name = 'QueryTimeoutError';
    }
}
async function withTimeout(ms, fn) {
    if (!ms || ms <= 0)
        return fn();
    let timer;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new QueryTimeoutError(ms)), ms);
    });
    try {
        return await Promise.race([fn(), timeout]);
    }
    finally {
        clearTimeout(timer);
    }
}
/**
 * A timed-out query is NOT cancelled by Promise.race — the driver may still be
 * reading rows on the same socket/pool connection when the next tool call
 * starts. That can interleave results (Dameng keeps one long-lived connection)
 * or return a late result to the wrong caller. Mark the Database instance as
 * poisoned on timeout so the next call drops and rebuilds its connection.
 */
async function withTimeoutAndReset(ms, fn, onTimeout) {
    try {
        return await withTimeout(ms, fn);
    }
    catch (e) {
        if (e instanceof QueryTimeoutError)
            onTimeout();
        throw e;
    }
}
/** Escape a SQL string literal for inline use (identifiers are validated upstream). */
function quoteLiteral(v) {
    return `'${v.replace(/'/g, "''")}'`;
}
/**
 * Detect an error that means "the underlying connection/socket is dead" as
 * opposed to a SQL/logic error. Used to decide whether rebuilding the pool/
 * connection could help; a bad SQL should never trigger a reconnect.
 */
export function isConnectionLostError(e) {
    const err = e;
    const code = String(err?.code ?? '');
    const msg = String(err?.message ?? '');
    return ([
        'ECONNRESET', 'ECONNREFUSED', 'ENOTFOUND', 'EHOSTUNREACH', 'ESOCKET',
        'EPIPE', 'PROTOCOL_CONNECTION_LOST', 'ERR_SERVER_GONE', 'ER_SERVER_SHUTDOWN',
        'CONNECTION_CLOSED', 'CONNECTION_LOST', 'ConnectionError',
    ].includes(code) ||
        err?.name === 'ConnectionError' ||
        /connection.*(lost|closed|reset|terminated)|socket hang up|server has gone away|closed connection|connection is closed|cannot read.*socket|write.*epipe/i.test(msg));
}
/* ------------------------------- Dameng ------------------------------- */
class DamengDatabase {
    type = 'dameng';
    conn = null;
    cfg;
    /** Set by a timeout; the next call must drop the connection before reuse. */
    needsReset = false;
    constructor(cfg) {
        this.cfg = cfg;
    }
    async timed(fn) {
        return withTimeoutAndReset(this.cfg.queryTimeoutMs, fn, () => { this.needsReset = true; });
    }
    async resetIfNeeded() {
        if (!this.needsReset)
            return;
        this.needsReset = false;
        await this.close();
    }
    async connect() {
        if (this.conn)
            return;
        const db = (await import('dmdb')).default;
        const connStr = `dm://${encodeURIComponent(this.cfg.user)}:${encodeURIComponent(this.cfg.password)}@${this.cfg.host}:${this.cfg.port}?schema=${encodeURIComponent(this.cfg.schema)}`;
        this.conn = await db.getConnection(connStr);
    }
    async close() {
        if (this.conn) {
            try {
                await this.conn.close();
            }
            catch {
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
    async ensure() {
        if (!this.conn) {
            await this.connect();
            return this.conn;
        }
        try {
            if (typeof this.conn.ping === 'function') {
                await this.conn.ping();
            }
            return this.conn;
        }
        catch {
            // Stale: drop it and establish a fresh connection once. If this also
            // fails, the error propagates (structured error layer redacts it).
            await this.close();
            await this.connect();
            return this.conn;
        }
    }
    async run(sql, binds = []) {
        await this.resetIfNeeded();
        const db = (await import('dmdb')).default;
        const opts = { outFormat: db.OUT_FORMAT_OBJECT };
        let conn = await this.ensure();
        try {
            return await conn.execute(sql, binds, opts);
        }
        catch (e) {
            if (!isConnectionLostError(e))
                throw e;
            // Race: connection died between ensure()'s ping and execute(). Rebuild
            // once. Retry ONLY a statement the shared classifier calls read-only —
            // replaying a write after a lost connection could duplicate an
            // INSERT/UPDATE whose commit actually succeeded. Using classifySql (not
            // a SELECT-only regex) keeps WITH/SHOW/EXPLAIN safe and refuses CTEs
            // that hide DML. Callers of write statements get the error to handle.
            if (classifySql(sql) !== 'read')
                throw e;
            await this.close();
            await this.connect();
            conn = this.conn;
            return conn.execute(sql, binds, opts);
        }
    }
    async testConnection() {
        const res = await this.timed(() => this.run("SELECT BANNER FROM V$VERSION WHERE ROWNUM <= 1"));
        const version = res.rows[0]?.BANNER ?? 'DM (unknown version)';
        let schema = this.cfg.schema;
        try {
            const s = await this.timed(() => this.run("SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') AS SCH FROM DUAL"));
            schema = s.rows[0]?.SCH || schema;
        }
        catch {
            /* keep configured schema */
        }
        return { version, schema };
    }
    async listTables(schema) {
        const res = await this.timed(() => this.run('SELECT TABLE_NAME FROM ALL_TABLES WHERE UPPER(OWNER) = UPPER(?) ORDER BY TABLE_NAME', [schema]));
        return res.rows.map((r) => r.TABLE_NAME);
    }
    async describeTable(table, schema) {
        const res = await this.timed(() => this.run(`SELECT COLUMN_NAME, DATA_TYPE, CHAR_LENGTH, NULLABLE, DATA_DEFAULT,
              (SELECT COMMENTS FROM ALL_COL_COMMENTS
                WHERE OWNER = ? AND TABLE_NAME = ? AND COLUMN_NAME = A.COLUMN_NAME) AS CMT
         FROM ALL_TAB_COLUMNS A
        WHERE UPPER(OWNER) = UPPER(?) AND UPPER(TABLE_NAME) = UPPER(?)
        ORDER BY COLUMN_ID`, [schema, schema, table, table]));
        const columns = res.rows.map((r) => ({
            name: r.COLUMN_NAME,
            type: r.DATA_TYPE,
            length: r.CHAR_LENGTH ?? null,
            nullable: r.NULLABLE === 'Y',
            default: r.DATA_DEFAULT ?? null,
            comment: r.CMT ?? '',
        }));
        return { table, schema, columns };
    }
    async executeSql(sql, maxRows, params) {
        const start = Date.now();
        const res = await this.timed(() => this.run(sql, params));
        const all = (res.rows || []).map((r) => toJsonable(r));
        const truncated = all.length > maxRows;
        return {
            columns: res.metaData ? res.metaData.map((m) => m.name) : Object.keys(all[0] ?? {}),
            rows: truncated ? all.slice(0, maxRows) : all,
            rowCount: all.length,
            truncated,
            elapsedMs: Date.now() - start,
        };
    }
}
/* ------------------------------ SQL Server ------------------------------ */
class SqlServerDatabase {
    type = 'sqlserver';
    pool = null;
    cfg;
    needsReset = false;
    constructor(cfg) {
        this.cfg = cfg;
    }
    async timed(fn) {
        return withTimeoutAndReset(this.cfg.queryTimeoutMs, fn, () => { this.needsReset = true; });
    }
    async resetIfNeeded() {
        if (!this.needsReset)
            return;
        this.needsReset = false;
        await this.close();
    }
    async connect() {
        if (this.pool)
            return;
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
    async close() {
        if (this.pool) {
            try {
                await this.pool.close();
            }
            catch {
                /* ignore */
            }
            this.pool = null;
        }
    }
    async run(sql, params) {
        await this.resetIfNeeded();
        if (!this.pool)
            await this.connect();
        const request = this.pool.request();
        if (params && params.length > 0) {
            // mssql/tedious binds via named @pN parameters, not positional '?'.
            params.forEach((v, i) => request.input(`p${i + 1}`, v));
            return request.query(toNamedPlaceholders(sql));
        }
        return request.query(sql);
    }
    async testConnection() {
        const res = await this.timed(() => this.run('SELECT @@VERSION AS VERSION'));
        const version = String(res.recordset[0]?.VERSION ?? 'SQL Server (unknown version)');
        return { version, schema: this.cfg.schema };
    }
    async listTables(schema) {
        // schema is an identifier already validated by checkIdentifier; safe to inline.
        const res = await this.timed(() => this.run(`SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_TYPE = 'BASE TABLE' AND UPPER(TABLE_SCHEMA) = UPPER(${quoteLiteral(schema)})
        ORDER BY TABLE_NAME`));
        return res.recordset.map((r) => r.TABLE_NAME);
    }
    async describeTable(table, schema) {
        const res = await this.timed(() => this.run(`SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_DEFAULT
         FROM INFORMATION_SCHEMA.COLUMNS
        WHERE UPPER(TABLE_NAME) = UPPER(${quoteLiteral(table)})
          AND UPPER(TABLE_SCHEMA) = UPPER(${quoteLiteral(schema)})
        ORDER BY ORDINAL_POSITION`));
        const columns = res.recordset.map((r) => ({
            name: r.COLUMN_NAME,
            type: r.DATA_TYPE,
            length: r.CHARACTER_MAXIMUM_LENGTH ?? null,
            nullable: r.IS_NULLABLE === 'YES',
            default: r.COLUMN_DEFAULT ?? null,
            comment: '',
        }));
        return { table, schema, columns };
    }
    async executeSql(sql, maxRows, params) {
        const start = Date.now();
        const res = await this.timed(() => this.run(sql, params));
        const rs = res.recordset;
        const columns = rs && rs.length > 0 ? Object.keys(rs[0]) : [];
        const all = rs ? rs.map((r) => toJsonable(r)) : [];
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
class MysqlDatabase {
    type = 'mysql';
    pool = null;
    cfg;
    needsReset = false;
    constructor(cfg) {
        this.cfg = cfg;
    }
    async timed(fn) {
        return withTimeoutAndReset(this.cfg.queryTimeoutMs, fn, () => { this.needsReset = true; });
    }
    async resetIfNeeded() {
        if (!this.needsReset)
            return;
        this.needsReset = false;
        await this.close();
    }
    async connect() {
        if (this.pool)
            return;
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
    async close() {
        if (this.pool) {
            try {
                await this.pool.end();
            }
            catch {
                /* ignore */
            }
            this.pool = null;
        }
    }
    async run(sql, binds = []) {
        await this.resetIfNeeded();
        if (!this.pool)
            await this.connect();
        return this.pool.query(sql, binds);
    }
    async testConnection() {
        const [rows] = await this.timed(() => this.run('SELECT VERSION() AS V'));
        const version = `MySQL ${String(rows[0]?.V ?? '(unknown version)')}`;
        return { version, schema: this.cfg.schema };
    }
    async listTables(schema) {
        const [rows] = await this.timed(() => this.run(`SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'
        ORDER BY TABLE_NAME`, [schema]));
        return rows.map((r) => r.TABLE_NAME);
    }
    async describeTable(table, schema) {
        const [rows] = await this.timed(() => this.run(`SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_COMMENT
         FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
        ORDER BY ORDINAL_POSITION`, [schema, table]));
        const columns = rows.map((r) => ({
            name: r.COLUMN_NAME,
            type: r.DATA_TYPE,
            length: r.CHARACTER_MAXIMUM_LENGTH ?? null,
            nullable: r.IS_NULLABLE === 'YES',
            default: r.COLUMN_DEFAULT ?? null,
            comment: r.COLUMN_COMMENT ?? '',
        }));
        return { table, schema, columns };
    }
    async executeSql(sql, maxRows, params) {
        const start = Date.now();
        const [result] = await this.timed(() => this.run(sql, params));
        const rows = Array.isArray(result) ? result : [];
        const all = rows.map((r) => toJsonable(r));
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
export function createDatabase(cfg) {
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
