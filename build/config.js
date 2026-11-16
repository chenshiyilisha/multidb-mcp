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
const DEFAULT_PORTS = {
    dameng: 5236,
    sqlserver: 1433,
    mysql: 3306,
};
function parseBool(v, fallback) {
    if (v === undefined || v === '')
        return fallback;
    return v.toLowerCase() === 'true' || v === '1' || v === 'yes';
}
function parseIntSafe(v, fallback) {
    const n = Number.parseInt(v ?? '', 10);
    return Number.isFinite(n) && n > 0 ? n : fallback;
}
/** Timeouts accept an explicit 0 (disable the JS-side cap); other limits must be > 0. */
function parseTimeout(v, fallback) {
    if (v === undefined || v === '')
        return fallback;
    if (v.trim() === '0')
        return 0;
    return parseIntSafe(v, fallback);
}
const DEFAULT_QUERY_TIMEOUT_MS = 30000;
/** 1 MiB — generous for normal results, but stops a single BLOB from flooding the model context. */
const DEFAULT_MAX_RESULT_BYTES = 1024 * 1024;
/** Matches the 50,000-char convention used by production database MCP servers. */
const DEFAULT_MAX_QUERY_LENGTH = 50000;
/**
 * Parse masking rules from a JSON string with fail-closed validation.
 * An invalid regex / unknown strategy aborts config load rather than silently
 * shipping unmasked data (the same fail-closed principle as SQL classification).
 */
function parseMaskingRules(raw, source) {
    if (!raw || !raw.trim())
        return [];
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch (e) {
        throw new Error(`${source} is not valid JSON: ${e.message}`);
    }
    if (!Array.isArray(parsed)) {
        throw new Error(`${source} must be a JSON array of masking rules`);
    }
    return parsed.map((item, i) => {
        const r = item;
        const column = String(r.column ?? '');
        if (!column)
            throw new Error(`${source}[${i}].column is required`);
        const strategy = String(r.strategy ?? 'fixed');
        if (strategy !== 'fixed' && strategy !== 'null' && strategy !== 'partial') {
            throw new Error(`${source}[${i}].strategy must be "fixed", "null" or "partial" (got "${strategy}")`);
        }
        try {
            new RegExp(column, 'i');
        }
        catch (e) {
            throw new Error(`${source}[${i}].column is not a valid regex: ${e.message}`);
        }
        const keepLast = r.keepLast === undefined ? 4 : parseIntSafe(String(r.keepLast), 4);
        return {
            column,
            strategy: strategy,
            value: r.value === undefined ? undefined : String(r.value),
            keepLast,
        };
    });
}
function envConnection(name) {
    const type = (process.env.MULTIDB_DB_TYPE || 'dameng').toLowerCase();
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
        allowInsert: parseBool(process.env.MULTIDB_ALLOW_INSERT, false),
        allowUpdate: parseBool(process.env.MULTIDB_ALLOW_UPDATE, false),
        allowDelete: parseBool(process.env.MULTIDB_ALLOW_DELETE, false),
        allowDdl: parseBool(process.env.MULTIDB_ALLOW_DDL, false),
        maxRows: parseIntSafe(process.env.MULTIDB_MAX_ROWS, 1000),
        queryTimeoutMs: parseTimeout(process.env.MULTIDB_QUERY_TIMEOUT_MS, DEFAULT_QUERY_TIMEOUT_MS),
        maxResultBytes: (() => {
            const raw = process.env.MULTIDB_MAX_RESULT_BYTES;
            if (raw === undefined || raw === '')
                return DEFAULT_MAX_RESULT_BYTES;
            const n = Number.parseInt(raw, 10);
            return Number.isFinite(n) && n >= 0 ? n : DEFAULT_MAX_RESULT_BYTES;
        })(),
        maxQueryLength: parseIntSafe(process.env.MULTIDB_MAX_QUERY_LENGTH, DEFAULT_MAX_QUERY_LENGTH),
        maskingRules: parseMaskingRules(process.env.MULTIDB_MASKING_RULES, 'MULTIDB_MASKING_RULES'),
        description: process.env.MULTIDB_DESCRIPTION || undefined,
    };
}
let cached = null;
/** Clear the cached connections (used by tests when env vars change). */
export function resetConfigCache() {
    cached = null;
}
export function loadConnections() {
    if (cached)
        return cached;
    const raw = process.env.MULTIDB_CONNECTIONS;
    if (raw && raw.trim()) {
        let parsed;
        try {
            parsed = JSON.parse(raw);
        }
        catch (e) {
            throw new Error(`MULTIDB_CONNECTIONS is not valid JSON: ${e.message}`);
        }
        if (!Array.isArray(parsed) || parsed.length === 0) {
            throw new Error('MULTIDB_CONNECTIONS must be a non-empty JSON array');
        }
        cached = parsed.map((item, i) => {
            const c = item;
            const type = String(c.type || 'dameng').toLowerCase();
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
                allowInsert: parseBool(String(c.allowInsert ?? ''), false),
                allowUpdate: parseBool(String(c.allowUpdate ?? ''), false),
                allowDelete: parseBool(String(c.allowDelete ?? ''), false),
                allowDdl: parseBool(String(c.allowDdl ?? ''), false),
                maxRows: parseIntSafe(String(c.maxRows ?? ''), 1000),
                queryTimeoutMs: parseTimeout(String(c.queryTimeoutMs ?? ''), DEFAULT_QUERY_TIMEOUT_MS),
                maxResultBytes: (() => {
                    if (c.maxResultBytes === undefined || c.maxResultBytes === '')
                        return DEFAULT_MAX_RESULT_BYTES;
                    const n = Number.parseInt(String(c.maxResultBytes), 10);
                    return Number.isFinite(n) && n >= 0 ? n : DEFAULT_MAX_RESULT_BYTES;
                })(),
                maxQueryLength: parseIntSafe(String(c.maxQueryLength ?? ''), DEFAULT_MAX_QUERY_LENGTH),
                maskingRules: parseMaskingRules(c.maskingRules === undefined ? undefined : JSON.stringify(c.maskingRules), `connection[${i}].maskingRules`),
                description: c.description ? String(c.description) : undefined,
            };
        });
    }
    else {
        cached = [envConnection('default')];
    }
    for (const c of cached) {
        if (!c.host || !c.user) {
            throw new Error(`connection "${c.name}" is missing host/user configuration`);
        }
    }
    return cached;
}
export function maxRowsLimit() {
    return loadConnections()[0].maxRows;
}
/**
 * A per-call `maxRows` override can only LOWER the configured ceiling. Without
 * this clamp a model (or injected text) could pass a huge value and defeat the
 * result-size guard. Pure function so the governance rule is unit-testable.
 */
export function clampMaxRows(requested, configured) {
    const effective = requested !== undefined && Number.isFinite(requested) && requested > 0
        ? requested
        : configured;
    const limit = Math.min(effective, configured);
    return { limit, clamped: effective > configured };
}
/**
 * Resolve which connection a tool call targets.
 * Returns the matching config, or throws with a connection directory that
 * guides the caller to pick explicitly when multiple connections exist.
 */
export function resolveConnection(name) {
    const conns = loadConnections();
    if (conns.length === 1) {
        if (name && name !== conns[0].name) {
            throw new Error(`unknown connection "${name}". Only one connection is configured: "${conns[0].name}".`);
        }
        return conns[0];
    }
    if (!name) {
        const dir = conns
            .map((c) => `  - ${c.name}${c.description ? ` (${c.description})` : ''} [${c.type}]`)
            .join('\n');
        throw new Error(`Multiple connections configured; pass a connection name explicitly.\nConfigured connections:\n${dir}`);
    }
    const found = conns.find((c) => c.name === name);
    if (!found) {
        const names = conns.map((c) => c.name).join(', ');
        throw new Error(`unknown connection "${name}". Available: ${names}`);
    }
    return found;
}
