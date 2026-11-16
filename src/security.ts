/**
 * SQL safety policy shared by all databases.
 *
 * Rules:
 *  - Identifier format: [A-Za-z_#$][A-Za-z0-9_$#]* (SQL Server temp-table
 *    prefixes #/## and Dameng $ are allowed as leading characters).
 *  - Multi-statement injection: any ';' that is not a single trailing one is
 *    rejected, so "DROP TABLE x; --" style payloads cannot slip through.
 *  - Read-only mode: only SELECT / SHOW / DESCRIBE / EXPLAIN / WITH-CTE
 *    (leading WITH) statements are allowed; DML/DDL are rejected.
 */

export class SqlPolicyError extends Error {}

const IDENT_RE = /^[A-Za-z_#$][A-Za-z0-9_$#]*$/;

export function checkIdentifier(name: string): string {
  if (!name || !IDENT_RE.test(name)) {
    throw new SqlPolicyError(
      `invalid identifier: ${JSON.stringify(name)} (must match [A-Za-z_#$][A-Za-z0-9_$#]*)`
    );
  }
  return name;
}

/** Strip SQL string literals ('...' and "...") so checks operate on real code. */
function stripLiterals(sql: string): string {
  return sql.replace(/'(?:[^'\\]|\\.|'')*'|"(?:[^"\\]|\\.)*"/g, "''");
}

const READONLY_PREFIXES = ['select', 'show', 'describe', 'desc', 'explain', 'with'];

export function checkSql(sql: string, readOnly: boolean): string {
  const stripped = stripLiterals(sql).trim();
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

  if (readOnly) {
    const firstWord = body.split(/\s+/)[0].toLowerCase();
    if (!READONLY_PREFIXES.includes(firstWord)) {
      throw new SqlPolicyError(
        `read-only mode: only SELECT / SHOW / DESCRIBE / EXPLAIN / WITH statements are allowed (got "${firstWord}")`
      );
    }
  }

  return sql.trim();
}
