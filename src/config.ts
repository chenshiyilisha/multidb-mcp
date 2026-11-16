/**
 * Connection configuration resolution.
 *
 * Two ways to configure connections:
 *  1. Single-connection env vars (MULTIDB_DB_TYPE / MULTIDB_HOST / ...)
 *  2. MULTIDB_CONNECTIONS env var holding a JSON array of connection objects
 *     (same shape as the single-connection vars, plus a "name" and "type").
 *
 * Resolution rule for tool calls: if exactly one connection is configured it
 * is auto-selected; if several are configured the caller must pass an
 * explicit `connection` name (mirrors the "no silent default" design that
 * prevents LLMs from querying the wrong database).
 */

export type DbType = 'dameng' | 'sqlserver' | 'mysql';

export interface ConnectionConfig {
  name: string;
  type: DbType;
  host: string;
  port: number;
  user: string;
  password: string;
  /** Dameng schema, or SQL Server database name. */
  schema: string;
  readOnly: boolean;
  maxRows: number;
  /** Hard query timeout in ms; 0 disables the JS-side timeout. */
  queryTimeoutMs: number;
  description?: string;
}

const DEFAULT_PORTS: Record<DbType, number> = {
  dameng: 5236,
  sqlserver: 1433,
  mysql: 3306,
};

function parseBool(v: string | undefined, fallback: boolean): boolean {
  if (v === undefined || v === '') return fallback;
  return v.toLowerCase() === 'true' || v === '1' || v === 'yes';
}

function parseIntSafe(v: string | undefined, fallback: number): number {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const DEFAULT_QUERY_TIMEOUT_MS = 30000;

function envConnection(name: string): ConnectionConfig {
  const type = (process.env.MULTIDB_DB_TYPE || 'dameng').toLowerCase() as DbType;
  if (type !== 'dameng' && type !== 'sqlserver' && type !== 'mysql') {
    throw new Error(`MULTIDB_DB_TYPE must be "dameng", "sqlserver" or "mysql", got "${type}"`);
  }
  return {
    name,
    type,
    host: process.env.MULTIDB_HOST || '',
    port: parseIntSafe(process.env.MULTIDB_PORT, DEFAULT_PORTS[type]),
    user: process.env.MULTIDB_USER || '',
    password: process.env.MULTIDB_PASSWORD || '',
    schema: process.env.MULTIDB_SCHEMA || process.env.MULTIDB_DATABASE || '',
    readOnly: parseBool(process.env.MULTIDB_READ_ONLY, true),
    maxRows: parseIntSafe(process.env.MULTIDB_MAX_ROWS, 1000),
    queryTimeoutMs: parseIntSafe(process.env.MULTIDB_QUERY_TIMEOUT_MS, DEFAULT_QUERY_TIMEOUT_MS),
    description: process.env.MULTIDB_DESCRIPTION || undefined,
  };
}

let cached: ConnectionConfig[] | null = null;

/** Clear the cached connections (used by tests when env vars change). */
export function resetConfigCache(): void {
  cached = null;
}

export function loadConnections(): ConnectionConfig[] {
  if (cached) return cached;

  const raw = process.env.MULTIDB_CONNECTIONS;
  if (raw && raw.trim()) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      throw new Error(`MULTIDB_CONNECTIONS is not valid JSON: ${(e as Error).message}`);
    }
    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new Error('MULTIDB_CONNECTIONS must be a non-empty JSON array');
    }
    cached = parsed.map((item, i) => {
      const c = item as Record<string, unknown>;
      const type = String(c.type || 'dameng').toLowerCase() as DbType;
      if (type !== 'dameng' && type !== 'sqlserver' && type !== 'mysql') {
        throw new Error(`connection[${i}].type must be "dameng", "sqlserver" or "mysql"`);
      }
      return {
        name: String(c.name || `conn${i + 1}`),
        type,
        host: String(c.host || ''),
        port: parseIntSafe(String(c.port ?? ''), DEFAULT_PORTS[type]),
        user: String(c.user || ''),
        password: String(c.password || ''),
        schema: String(c.schema || c.database || ''),
        readOnly: parseBool(String(c.readOnly ?? ''), true),
        maxRows: parseIntSafe(String(c.maxRows ?? ''), 1000),
        queryTimeoutMs: (() => {
          const raw = String(c.queryTimeoutMs ?? '');
          if (raw === '' || raw === '0') return DEFAULT_QUERY_TIMEOUT_MS;
          return parseIntSafe(raw, DEFAULT_QUERY_TIMEOUT_MS);
        })(),
        description: c.description ? String(c.description) : undefined,
      };
    });
  } else {
    cached = [envConnection('default')];
  }

  for (const c of cached) {
    if (!c.host || !c.user) {
      throw new Error(`connection "${c.name}" is missing host/user configuration`);
    }
  }
  return cached;
}

export function maxRowsLimit(): number {
  return loadConnections()[0].maxRows;
}

/**
 * Resolve which connection a tool call targets.
 * Returns the matching config, or throws with a connection directory that
 * guides the caller to pick explicitly when multiple connections exist.
 */
export function resolveConnection(name?: string): ConnectionConfig {
  const conns = loadConnections();
  if (conns.length === 1) {
    if (name && name !== conns[0].name) {
      throw new Error(
        `unknown connection "${name}". Only one connection is configured: "${conns[0].name}".`
      );
    }
    return conns[0];
  }
  if (!name) {
    const dir = conns
      .map((c) => `  - ${c.name}${c.description ? ` (${c.description})` : ''} [${c.type}]`)
      .join('\n');
    throw new Error(
      `Multiple connections configured; pass a connection name explicitly.\nConfigured connections:\n${dir}`
    );
  }
  const found = conns.find((c) => c.name === name);
  if (!found) {
    const names = conns.map((c) => c.name).join(', ');
    throw new Error(`unknown connection "${name}". Available: ${names}`);
  }
  return found;
}
