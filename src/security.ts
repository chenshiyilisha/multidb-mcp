/**
 * SQL safety policy shared by all databases.
 *
 * Rules:
 *  - Identifier format: [A-Za-z_#$][A-Za-z0-9_$#]* (SQL Server temp-table
 *    prefixes #/## and Dameng $ are allowed as leading characters).
 *  - Multi-statement injection: any ';' that is not a single trailing one is
 *    rejected, so "DROP TABLE x; --" style payloads cannot slip through.
 *  - Read-only mode: only read statements are allowed; everything else is
 *    rejected regardless of write permissions.
 *  - Fine-grained write policy: when a connection is NOT read-only, each
 *    write statement type (INSERT / UPDATE / DELETE / DDL) is gated by its
 *    own permission flag. A statement is executed only if the matching flag
 *    is true. Statements that cannot be classified (forbidden verbs, unknown
 *    verbs) are always rejected — fail-closed.
 *
 * Statement classification follows the verb-classifier pattern:
 *  - Strip SQL comments and string literals before inspecting the verb.
 *  - WITH ... CTE: the CTE bodies live in parentheses; classify by the body
 *    statement that follows them (WITH ... SELECT -> read, WITH ... INSERT
 *    -> insert, etc.).
 *  - EXPLAIN [ANALYZE|PLAN] ...: classify the explained statement, because
 *    EXPLAIN ANALYZE actually executes the underlying statement.
 */

export class SqlPolicyError extends Error {
  readonly name = 'SqlPolicyError';
}

const IDENT_RE = /^[A-Za-z_#$][A-Za-z0-9_$#]*$/;

export function checkIdentifier(name: string): string {
  if (!name || !IDENT_RE.test(name)) {
    throw new SqlPolicyError(
      `invalid identifier: ${JSON.stringify(name)} (must match [A-Za-z_#$][A-Za-z0-9_$#]*)`
    );
  }
  return name;
}

/**
 * MySQL/MariaDB only treat `--` as a line comment when a whitespace/control
 * character or end-of-line follows. `SELECT 1--1; DROP TABLE t` is arithmetic
 * followed by a second statement to MySQL, but a naive regex comment stripper
 * hides the DROP. This exact parser differential is CVE-2026-61789/DBHub.
 * Using the strict rule for every dialect is conservative: SQL Server/Dameng
 * may reject a few `--no-space` comments, which is safe (fail-closed).
 */
function isLineCommentStart(sql: string, i: number): boolean {
  if (sql[i] !== '-' || sql[i + 1] !== '-') return false;
  const next = sql[i + 2];
  return next === undefined || /\s/.test(next);
}

/**
 * Blank out every quoted literal / quoted identifier / comment while keeping
 * real SQL code (and newlines) intact. The policy scanner MUST use one shared
 * view of the statement: stripping literals in one place and comments in
 * another leaves a window where `SELECT 'a; DROP'` can be ablated differently
 * by the two checks.
 */
function removeQuotedAndComments(sql: string): string {
  let out = '';
  let i = 0;
  const blank = (ch: string) => (ch === '\n' || ch === '\r' ? ch : ' ');
  const consumeQuoted = (quote: string, backslashEscapes: boolean): void => {
    // Called with i pointing at the opening quote.
    out += ' ';
    i++;
    while (i < sql.length) {
      const ch = sql[i];
      if (backslashEscapes && ch === '\\' && i + 1 < sql.length) {
        out += blank(ch) + blank(sql[i + 1]);
        i += 2;
        continue;
      }
      if (ch === quote) {
        if (sql[i + 1] === quote) { // doubled quote escape: '' / "" / ``
          out += '  ';
          i += 2;
          continue;
        }
        out += ' ';
        i++;
        return;
      }
      out += blank(ch);
      i++;
    }
  };

  while (i < sql.length) {
    const ch = sql[i];
    const next = sql[i + 1];
    if (ch === "'") { consumeQuoted("'", true); continue; }
    if (ch === '"') { consumeQuoted('"', true); continue; }
    if (ch === '`') { consumeQuoted('`', false); continue; }
    if (ch === '[') { // SQL Server bracket-quoted identifier
      out += ' ';
      i++;
      while (i < sql.length && sql[i] !== ']') { out += blank(sql[i]); i++; }
      if (i < sql.length) { out += ' '; i++; }
      continue;
    }
    if (isLineCommentStart(sql, i)) {
      out += '  ';
      i += 2;
      while (i < sql.length && sql[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    if (ch === '/' && next === '*') {
      out += '  ';
      i += 2;
      while (i < sql.length) {
        if (sql[i] === '*' && sql[i + 1] === '/') { out += '  '; i += 2; break; }
        out += blank(sql[i]);
        i++;
      }
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

/**
 * Replace every balanced parenthesis group (including nested ones) with
 * spaces. Used to erase CTE bodies and inner subqueries so only the outer
 * statement skeleton remains for verb classification.
 */
function blankParenthesised(text: string): string {
  let out = '';
  let depth = 0;
  for (const ch of text) {
    if (ch === '(') {
      depth++;
      out += ' ';
    } else if (ch === ')') {
      depth = Math.max(0, depth - 1);
      out += ' ';
    } else {
      out += depth > 0 ? ' ' : ch;
    }
  }
  return out;
}

/* --------------------------- verb classification --------------------------- */

export type SqlStatementType =
  | 'read'
  | 'insert'
  | 'update'
  | 'delete'
  | 'ddl'
  | 'forbidden'
  | 'unknown';

// NOTE: `use` is deliberately NOT a read verb. It mutates session state on
// pooled MySQL/SQL Server connections and can leak into later tool calls.
const READ_VERBS = new Set(['select', 'show', 'describe', 'desc', 'explain']);
const INSERT_VERBS = new Set(['insert', 'replace']);
const UPDATE_VERBS = new Set(['update', 'merge']);
const DELETE_VERBS = new Set(['delete']);
const DDL_VERBS = new Set(['create', 'alter', 'drop', 'truncate', 'rename']);
// Verbs that are never safe to run through an MCP tool: privilege management,
// session control, filesystem access, process control, etc.
const FORBIDDEN_VERBS = new Set([
  'grant', 'revoke', 'deny', 'set', 'flush', 'reset', 'kill', 'shutdown',
  'load', 'handler', 'install', 'uninstall', 'lock', 'unlock',
  // `use` changes the current database on a pooled session (state leakage).
  'use',
  'call', 'exec', 'execute',
]);

function mapVerb(verb: string): SqlStatementType {
  if (READ_VERBS.has(verb)) return 'read';
  if (INSERT_VERBS.has(verb)) return 'insert';
  if (UPDATE_VERBS.has(verb)) return 'update';
  if (DELETE_VERBS.has(verb)) return 'delete';
  if (DDL_VERBS.has(verb)) return 'ddl';
  if (FORBIDDEN_VERBS.has(verb)) return 'forbidden';
  return 'unknown';
}

function classifyFirstVerb(text: string): SqlStatementType {
  const m = text.trim().match(/^([A-Za-z]+)/);
  return m ? mapVerb(m[1].toLowerCase()) : 'unknown';
}

/**
 * Fail-closed guard for verbs hidden inside parenthesis groups.
 *
 * `classifySql` blanks parenthesised text to classify WITH/CTE bodies by the
 * outer statement. That is correct for ordinary CTEs, but it would also hide a
 * data-modifying CTE: `WITH c AS (DELETE FROM t) SELECT * FROM c` looks like a
 * read after blanking, yet the database may still execute the DELETE. Real
 * CVEs in other database MCP servers (pgEdge/DBHub, 2026) came from exactly
 * this kind of prefix-only "read only" check.
 *
 * Scan every balanced group (including nested ones). If a group starts with a
 * write/forbidden verb, report that type so the caller's read-only policy
 * rejects the whole statement. Groups starting with SELECT/VALUES/etc. are
 * ignored — they cannot introduce a write on the engines we support.
 */
function dangerousVerbInGroups(cleaned: string): SqlStatementType {
  const stack: number[] = [];
  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];
    if (ch === '(') {
      stack.push(i);
    } else if (ch === ')' && stack.length) {
      const start = stack.pop()!;
      const inner = cleaned.slice(start + 1, i).trim();
      const type = classifyFirstVerb(inner);
      if (type !== 'read' && type !== 'unknown') return type;
    }
  }
  return 'unknown';
}

/**
 * Classify a single SQL statement into a statement type.
 *
 * Handles the two statement prefixes that wrap an inner statement:
 *  - WITH ... <body>: CTE definitions sit inside parentheses; drop them and
 *    classify the body that follows.
 *  - EXPLAIN [ANALYZE|PLAN] ...: classify the explained statement.
 *
 * Comments and string literals are stripped first so they cannot influence the
 * classification (e.g. a comment containing "DROP" must not flip a SELECT).
 */
export function classifySql(sql: string): SqlStatementType {
  const cleaned = removeQuotedAndComments(sql).trim();
  if (!cleaned) return 'unknown';

  const first = cleaned.match(/^([A-Za-z]+)/);
  if (!first) return 'unknown';
  const verb = first[1].toLowerCase();

  let result: SqlStatementType;
  if (verb === 'with') {
    // Blank every parenthesis group (CTE bodies, optional column lists,
    // nested subqueries), then strip the CTE header(s) so the remaining first
    // verb is the body statement: WITH c AS (...) SELECT -> read,
    // WITH c AS (...) INSERT/UPDATE/DELETE -> the corresponding write type.
    let body = blankParenthesised(cleaned)
      .replace(/^\s*with\s+(recursive\s+)?/i, '');
    // Remove the first "name AS" (or "name (cols) AS", now blanked) header.
    body = body.replace(/^\s*[A-Za-z_][\w$#]*\s+as\s+/i, '');
    // Remove any additional ", name AS" headers.
    while (/^\s*,\s*[A-Za-z_][\w$#]*\s+as\s+/i.test(body)) {
      body = body.replace(/^\s*,\s*[A-Za-z_][\w$#]*\s+as\s+/i, '');
    }
    result = classifyFirstVerb(body);
  } else if (verb === 'explain') {
    const body = cleaned.replace(/^\s*explain\s+(analyze\s+|plan\s+)?/i, '');
    result = classifyFirstVerb(body);
  } else {
    result = mapVerb(verb);
  }

  // Fail closed: a statement whose outer verb looks read-only must not hide a
  // write inside a CTE/subquery parenthesis group (see helper comment).
  if (result === 'read') {
    const nested = dangerousVerbInGroups(cleaned);
    if (nested !== 'unknown' && nested !== 'read') return nested;
  }
  return result;
}

/* --------------------------- query parameters --------------------------- */

/**
 * Scan a SQL statement and replace every placeholder that appears OUTSIDE of
 * string literals / quoted identifiers / comments (i.e. a real bind marker),
 * in left-to-right order. Returns the rewritten SQL and the placeholder count.
 *
 * Rationale: bind placeholders must never be counted inside literals such as
 * `SELECT '?' ` or comments — doing so would produce false parameter-count
 * errors. This is the shared basis for `?` counting (Dameng/MySQL) and for the
 * `?` -> @pN rewrite required by SQL Server (mssql binds via request.input()).
 * Reference: dmdb index.d.ts (positional `?` binds), mysql2 docs (`?` binds),
 * mssql/tedious docs (`@name` binds via request.input).
 */
export function transformPlaceholders(
  sql: string,
  replacer: (ordinal: number) => string
): { text: string; count: number } {
  let out = '';
  let count = 0;
  let i = 0;
  const n = sql.length;
  type State = 'normal' | 'single' | 'double' | 'backtick' | 'bracket' | 'line' | 'block';
  let state: State = 'normal';

  while (i < n) {
    const ch = sql[i];
    const next = sql[i + 1];
    if (state === 'normal') {
      if (ch === "'") { state = 'single'; out += ch; }
      else if (ch === '"') { state = 'double'; out += ch; }
      else if (ch === '`') { state = 'backtick'; out += ch; }
      else if (ch === '[') { state = 'bracket'; out += ch; }
      // Same strict MySQL-compatible rule as removeQuotedAndComments:
      // `--` without following whitespace is arithmetic, not a comment.
      else if (isLineCommentStart(sql, i)) { state = 'line'; out += '--'; i++; }
      else if (ch === '/' && next === '*') { state = 'block'; out += '/*'; i++; }
      else if (ch === '?') { count++; out += replacer(count); }
      else out += ch;
    } else if (state === 'single') {
      out += ch;
      if (ch === "'") {
        if (next === "'") { out += next; i++; } // escaped '' inside literal
        else state = 'normal';
      } else if (ch === '\\' && next !== undefined) { out += next; i++; }
    } else if (state === 'double') {
      out += ch;
      if (ch === '"') {
        if (next === '"') { out += next; i++; }
        else state = 'normal';
      }
    } else if (state === 'backtick') {
      out += ch;
      if (ch === '`') {
        if (next === '`') { out += next; i++; }
        else state = 'normal';
      }
    } else if (state === 'bracket') {
      out += ch;
      if (ch === ']') state = 'normal';
    } else if (state === 'line') {
      out += ch;
      if (ch === '\n') state = 'normal';
    } else if (state === 'block') {
      out += ch;
      if (ch === '*' && next === '/') { out += next; i++; state = 'normal'; }
    }
    i++;
  }
  return { text: out, count };
}

/** Count real bind placeholders (`?` outside literals/comments). */
export function countPlaceholders(sql: string): number {
  return transformPlaceholders(sql, () => '?').count;
}

/** Rewrite `?` placeholders to SQL Server's positional @p1, @p2, ... form. */
export function toNamedPlaceholders(sql: string): string {
  return transformPlaceholders(sql, (n) => `@p${n}`).text;
}

/* --------------------------- write permissions --------------------------- */

/**
 * Fine-grained write permissions for a connection. Each flag gates exactly one
 * statement type; a write statement runs only when its flag is true.
 */
export interface WritePermissions {
  allowInsert: boolean;
  allowUpdate: boolean;
  allowDelete: boolean;
  allowDdl: boolean;
}

const READONLY_MSG =
  'read-only mode: only SELECT/SHOW/DESCRIBE/EXPLAIN/WITH statements are allowed';

/**
 * Validate a SQL statement against the connection's policy.
 *
 * @param sql       the statement to check
 * @param readOnly  master switch: when true, only read statements pass
 * @param perms     fine-grained write permissions (required for write
 *                  statements when readOnly is false). When omitted, the
 *                  legacy behaviour is kept: all non-forbidden writes pass
 *                  (useful for callers/tests that only pass readOnly).
 * @returns the trimmed SQL when allowed
 * @throws  SqlPolicyError when the statement violates policy
 */
export function checkSql(sql: string, readOnly: boolean, perms?: WritePermissions): string {
  // One shared, literal-and-comment-free view for BOTH the empty check and
  // the multi-statement check. Ablating literals in one check and comments in
  // another allowed `SELECT 'a; DROP' ...` style bypasses in other MCP servers.
  const stripped = removeQuotedAndComments(sql).trim();
  if (!stripped) {
    throw new SqlPolicyError('empty SQL statement');
  }

  // Multi-statement injection: only a single trailing ';' is allowed.
  const body = stripped.replace(/;+$/, '').trim();
  if (body.includes(';')) {
    throw new SqlPolicyError(
      'multi-statement SQL is not allowed (only a single trailing semicolon)'
    );
  }

  const type = classifySql(body);

  if (readOnly) {
    if (type !== 'read') {
      throw new SqlPolicyError(`${READONLY_MSG} (got "${type}")`);
    }
    return sql.trim();
  }

  // Write path.
  if (!perms) {
    // Legacy fallback: allow all non-forbidden writes.
    if (type === 'forbidden' || type === 'unknown') {
      throw new SqlPolicyError(`statement type "${type}" is not allowed`);
    }
    return sql.trim();
  }

  const allowed =
    type === 'read' ? true
    : type === 'insert' ? perms.allowInsert
    : type === 'update' ? perms.allowUpdate
    : type === 'delete' ? perms.allowDelete
    : type === 'ddl' ? perms.allowDdl
    : false; // forbidden / unknown are never allowed

  if (!allowed) {
    throw new SqlPolicyError(
      `statement type "${type}" is not permitted by this connection's write policy`
    );
  }
  return sql.trim();
}
