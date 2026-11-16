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
/** Escape a SQL string literal for inline use (identifiers are validated upstream). */
function quoteLiteral(v) {
    return `'${v.replace(/'/g, "''")}'`;
}
/* ------------------------------- Dameng ------------------------------- */
class DamengDatabase {
    type = 'dameng';
    conn = null;
    cfg;
    constructor(cfg) {
        this.cfg = cfg;
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
    /** Reconnect once if the connection went stale. */
    async ensure() {
        if (!this.conn)
            await this.connect();
        return this.conn;
    }
    async run(sql, binds = []) {
        const conn = await this.ensure();
        const db = (await import('dmdb')).default;
        return conn.execute(sql, binds, { outFormat: db.OUT_FORMAT_OBJECT });
    }
    async testConnection() {
        const res = await this.run("SELECT BANNER FROM V$VERSION WHERE ROWNUM <= 1");
        const version = res.rows[0]?.BANNER ?? 'DM (unknown version)';
        let schema = this.cfg.schema;
        try {
            const s = await this.run("SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') AS SCH FROM DUAL");
            schema = s.rows[0]?.SCH || schema;
        }
        catch {
            /* keep configured schema */
        }
        return { version, schema };
    }
    async listTables(schema) {
        const res = await this.run('SELECT TABLE_NAME FROM ALL_TABLES WHERE UPPER(OWNER) = UPPER(?) ORDER BY TABLE_NAME', [schema]);
        return res.rows.map((r) => r.TABLE_NAME);
    }
    async describeTable(table, schema) {
        const res = await this.run(`SELECT COLUMN_NAME, DATA_TYPE, CHAR_LENGTH, NULLABLE, DATA_DEFAULT,
              (SELECT COMMENTS FROM ALL_COL_COMMENTS
                WHERE OWNER = ? AND TABLE_NAME = ? AND COLUMN_NAME = A.COLUMN_NAME) AS CMT
         FROM ALL_TAB_COLUMNS A
        WHERE UPPER(OWNER) = UPPER(?) AND UPPER(TABLE_NAME) = UPPER(?)
        ORDER BY COLUMN_ID`, [schema, schema, table, table]);
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
    async executeSql(sql, maxRows) {
        const start = Date.now();
        const res = await withTimeout(this.cfg.queryTimeoutMs, () => this.run(sql));
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
    constructor(cfg) {
        this.cfg = cfg;
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
    async run(sql) {
        if (!this.pool)
            await this.connect();
        return this.pool.request().query(sql);
    }
    async testConnection() {
        const res = await this.run('SELECT @@VERSION AS VERSION');
        const version = String(res.recordset[0]?.VERSION ?? 'SQL Server (unknown version)');
        return { version, schema: this.cfg.schema };
    }
    async listTables(schema) {
        // schema is an identifier already validated by checkIdentifier; safe to inline.
        const res = await this.run(`SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_TYPE = 'BASE TABLE' AND UPPER(TABLE_SCHEMA) = UPPER(${quoteLiteral(schema)})
        ORDER BY TABLE_NAME`);
        return res.recordset.map((r) => r.TABLE_NAME);
    }
    async describeTable(table, schema) {
        const res = await this.run(`SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_DEFAULT
         FROM INFORMATION_SCHEMA.COLUMNS
        WHERE UPPER(TABLE_NAME) = UPPER(${quoteLiteral(table)})
          AND UPPER(TABLE_SCHEMA) = UPPER(${quoteLiteral(schema)})
        ORDER BY ORDINAL_POSITION`);
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
    async executeSql(sql, maxRows) {
        const start = Date.now();
        const res = await withTimeout(this.cfg.queryTimeoutMs, () => this.run(sql));
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
    constructor(cfg) {
        this.cfg = cfg;
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
        if (!this.pool)
            await this.connect();
        return this.pool.query(sql, binds);
    }
    async testConnection() {
        const [rows] = await this.run('SELECT VERSION() AS V');
        const version = `MySQL ${String(rows[0]?.V ?? '(unknown version)')}`;
        return { version, schema: this.cfg.schema };
    }
    async listTables(schema) {
        const [rows] = await this.run(`SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'
        ORDER BY TABLE_NAME`, [schema]);
        return rows.map((r) => r.TABLE_NAME);
    }
    async describeTable(table, schema) {
        const [rows] = await this.run(`SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_COMMENT
         FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
        ORDER BY ORDINAL_POSITION`, [schema, table]);
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
    async executeSql(sql, maxRows) {
        const start = Date.now();
        const [result] = await withTimeout(this.cfg.queryTimeoutMs, () => this.run(sql));
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
