/**
 * MCP tool layer: exposes database operations as MCP tools.
 *
 * Tools:
 *  - test_connection : verify a connection and report version/schema
 *  - list_connections: show configured connections (passwords never exposed)
 *  - list_tables     : list tables in a schema
 *  - describe_table  : column metadata for a table
 *  - execute_sql     : run a SQL statement (respects read-only policy)
 *
 * Connections are pooled and kept alive across calls (each `getDb` is lazy and
 * cached), so repeated tool calls reuse the pool instead of reconnecting.
 * Audit records for every call are emitted to stderr (see audit.ts).
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { loadConnections, resolveConnection } from './config.js';
import { createDatabase, type Database } from './db.js';
import { SqlPolicyError, checkIdentifier, checkSql } from './security.js';
import { auditCall, slowQueryThresholdMs } from './audit.js';

const server = new McpServer({ name: 'multidb-mcp', version: '0.1.0' });

/** Lazily create + cache one pooled Database per connection name. */
const dbCache = new Map<string, Database>();

async function getDb(name?: string): Promise<{ cfg: ReturnType<typeof resolveConnection>; db: Database }> {
  const cfg = resolveConnection(name);
  let db = dbCache.get(cfg.name);
  if (!db) {
    db = createDatabase(cfg);
    await db.connect();
    dbCache.set(cfg.name, db);
  }
  return { cfg, db };
}

function textResult(payload: unknown): {
  content: { type: 'text'; text: string }[];
} {
  return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
}

/**
 * Resolve the in-database schema to operate on.
 * - Dameng: the schema (defaults to the configured one).
 * - SQL Server: cfg.schema is the *database*; in-database schema defaults to "dbo".
 * - MySQL: cfg.schema is the *database*; the in-database "schema" is the database
 *   itself (MySQL uses database == schema), so it defaults to cfg.schema.
 * An explicitly passed schema always wins.
 */
function resolveTargetSchema(cfg: { type: string; schema: string }, schema?: string): string {
  if (schema) return schema;
  if (cfg.type === 'sqlserver') return 'dbo';
  return cfg.schema;
}

/* --------------------------- test_connection --------------------------- */

server.registerTool(
  'test_connection',
  {
    description:
      'Verify the database connection and return server version and current schema. Use to check connectivity before running queries.',
    inputSchema: {
      connection: z
        .string()
        .optional()
        .describe('Name of the configured connection to test. Omit when only one is configured.'),
    },
  },
  async ({ connection }) => {
    const start = Date.now();
    try {
      const { cfg, db } = await getDb(connection);
      const info = await db.testConnection();
      auditCall('test_connection', {
        connection: cfg.name,
        dbType: cfg.type,
        elapsedMs: Date.now() - start,
        ok: true,
      });
      return textResult({ ok: true, connection: cfg.name, type: cfg.type, ...info });
    } catch (e) {
      auditCall('test_connection', {
        connection,
        elapsedMs: Date.now() - start,
        ok: false,
        error: (e as Error).message,
      });
      return textResult({ ok: false, error: (e as Error).message });
    }
  }
);

/* --------------------------- list_connections --------------------------- */

server.registerTool(
  'list_connections',
  {
    description:
      'List all configured database connections with their type, host and schema. Never exposes passwords. Call this first when unsure which connection name to use.',
    inputSchema: {},
  },
  async () => {
    const conns = loadConnections();
    return textResult(
      conns.map((c) => ({
        name: c.name,
        type: c.type,
        host: c.host,
        port: c.port,
        schema: c.schema,
        readOnly: c.readOnly,
        description: c.description ?? null,
      }))
    );
  }
);

/* ----------------------------- list_tables ----------------------------- */

server.registerTool(
  'list_tables',
  {
    description: 'List all tables in a schema of the target database.',
    inputSchema: {
      connection: z.string().optional().describe('Connection name. Omit when only one is configured.'),
      schema: z.string().optional().describe('Schema to list tables from. Uses the connection default if omitted.'),
    },
  },
  async ({ connection, schema }) => {
    const start = Date.now();
    try {
      const { cfg, db } = await getDb(connection);
      const targetSchema = resolveTargetSchema(cfg, schema);
      checkIdentifier(targetSchema);
      const tables = await db.listTables(targetSchema);
      auditCall('list_tables', {
        connection: cfg.name,
        dbType: cfg.type,
        elapsedMs: Date.now() - start,
        ok: true,
      });
      return textResult({ schema: targetSchema, count: tables.length, tables });
    } catch (e) {
      auditCall('list_tables', {
        connection,
        elapsedMs: Date.now() - start,
        ok: false,
        error: (e as Error).message,
      });
      return textResult({ error: (e as Error).message });
    }
  }
);

/* ---------------------------- describe_table ---------------------------- */

server.registerTool(
  'describe_table',
  {
    description:
      'Return column metadata for a table: column name, type, length, nullability, default and comment.',
    inputSchema: {
      table: z.string().describe('Table name.'),
      connection: z.string().optional().describe('Connection name. Omit when only one is configured.'),
      schema: z.string().optional().describe('Schema the table lives in. Uses the connection default if omitted.'),
    },
  },
  async ({ table, connection, schema }) => {
    const start = Date.now();
    try {
      checkIdentifier(table);
      const { cfg, db } = await getDb(connection);
      const targetSchema = resolveTargetSchema(cfg, schema);
      checkIdentifier(targetSchema);
      const info = await db.describeTable(table, targetSchema);
      auditCall('describe_table', {
        connection: cfg.name,
        dbType: cfg.type,
        elapsedMs: Date.now() - start,
        ok: true,
      });
      return textResult(info);
    } catch (e) {
      auditCall('describe_table', {
        connection,
        elapsedMs: Date.now() - start,
        ok: false,
        error: (e as Error).message,
      });
      return textResult({ error: (e as Error).message });
    }
  }
);

/* ----------------------------- execute_sql ----------------------------- */

server.registerTool(
  'execute_sql',
  {
    description:
      'Execute a single SQL statement and return the result rows. In read-only connections only SELECT/SHOW/DESCRIBE/EXPLAIN/WITH statements are allowed. Multi-statement SQL is rejected. Results are capped at the configured max rows.',
    inputSchema: {
      sql: z.string().describe('The SQL statement to execute. One statement only.'),
      connection: z.string().optional().describe('Connection name. Omit when only one is configured.'),
      maxRows: z.number().int().positive().optional().describe('Override the configured max rows for this call.'),
    },
  },
  async ({ sql, connection, maxRows }) => {
    const start = Date.now();
    let writeAttempt = false;
    try {
      const { cfg, db } = await getDb(connection);
      // Detect a write attempt on a read-only connection for the audit trail.
      writeAttempt = cfg.readOnly && isWriteStatement(sql);
      checkSql(sql, cfg.readOnly);
      const limit = maxRows ?? cfg.maxRows;
      const result = await db.executeSql(sql, limit);
      const elapsed = Date.now() - start;
      auditCall('execute_sql', {
        connection: cfg.name,
        dbType: cfg.type,
        elapsedMs: elapsed,
        ok: true,
        rowCount: result.rowCount,
        truncated: result.truncated,
        slow: elapsed >= slowQueryThresholdMs(),
        writeAttempt,
      });
      return textResult({
        connection: cfg.name,
        readOnly: cfg.readOnly,
        columns: result.columns,
        rowCount: result.rowCount,
        truncated: result.truncated,
        rows: result.rows,
      });
    } catch (e) {
      auditCall('execute_sql', {
        connection,
        elapsedMs: Date.now() - start,
        ok: false,
        error: (e as Error).message,
        writeAttempt,
      });
      const msg =
        e instanceof SqlPolicyError ? `SQL policy violation: ${(e as Error).message}` : (e as Error).message;
      return textResult({ error: msg });
    }
  }
);

/**
 * Best-effort detection of a write statement, used only to flag audit records
 * (the actual enforcement is done by checkSql). Matches DML/DDL verbs at the
 * start of the statement after stripping leading comments/whitespace.
 */
function isWriteStatement(sql: string): boolean {
  const m = sql.trim().match(/^([A-Za-z]+)/);
  if (!m) return false;
  const verb = m[1].toUpperCase();
  return (
    ['INSERT', 'UPDATE', 'DELETE', 'MERGE', 'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'GRANT', 'REVOKE', 'CALL', 'REPLACE']
      .includes(verb)
  );
}

export default server;
