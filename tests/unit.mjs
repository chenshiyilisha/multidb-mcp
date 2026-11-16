/**
 * Unit tests for security policy and configuration routing.
 * No database required. Run: npm run test:unit
 */

import assert from 'node:assert/strict';
import {
  checkIdentifier,
  checkSql,
  classifySql,
  countPlaceholders,
  toNamedPlaceholders,
  SqlPolicyError,
} from '../build/security.js';
import * as config from '../build/config.js';
import { applyMasking, capResultBytes } from '../build/masking.js';
import { structuredError, redact } from '../build/errors.js';

let passed = 0;
const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

/* ---------------------------- security ---------------------------- */

test('checkIdentifier accepts plain names', () => {
  assert.equal(checkIdentifier('USERS'), 'USERS');
  assert.equal(checkIdentifier('user_table_1'), 'user_table_1');
});

test('checkIdentifier accepts #/$ leading (temp tables, dameng $)', () => {
  assert.equal(checkIdentifier('##HISTOGRAMS_TABLE'), '##HISTOGRAMS_TABLE');
  assert.equal(checkIdentifier('$TMP'), '$TMP');
});

test('checkIdentifier rejects injection / bad chars', () => {
  for (const bad of ['bad name', 'a;b', 'x--', '1abc', 'a.b', '', 'a b']) {
    assert.throws(() => checkIdentifier(bad), SqlPolicyError, `should reject ${JSON.stringify(bad)}`);
  }
});

test('checkSql read-only allows SELECT/SHOW/DESCRIBE/EXPLAIN/WITH', () => {
  for (const ok of [
    'SELECT * FROM t',
    'select count(*) from t',
    'SHOW TABLES',
    'DESCRIBE t',
    'EXPLAIN SELECT 1',
    'WITH c AS (SELECT 1) SELECT * FROM c',
    'SELECT 1;',
  ]) {
    assert.doesNotThrow(() => checkSql(ok, true), `should allow ${ok}`);
  }
});

test('checkSql read-only rejects DML/DDL', () => {
  for (const bad of ['DELETE FROM t', 'UPDATE t SET a=1', 'INSERT INTO t VALUES(1)', 'DROP TABLE t', 'CREATE TABLE t (a int)', 'ALTER TABLE t ADD b int']) {
    assert.throws(() => checkSql(bad, true), SqlPolicyError, `should reject ${bad}`);
  }
});

test('checkSql allows DML when not read-only', () => {
  assert.doesNotThrow(() => checkSql('DELETE FROM t', false));
  assert.doesNotThrow(() => checkSql('UPDATE t SET a=1', false));
});

test('checkSql rejects multi-statement', () => {
  assert.throws(() => checkSql('SELECT 1; DROP TABLE t', true), /multi-statement/i);
  assert.throws(() => checkSql('SELECT 1;SELECT 2', true), /multi-statement/i);
});

test('checkSql allows single trailing semicolon', () => {
  assert.doesNotThrow(() => checkSql('SELECT 1;', true));
});

test('checkSql does not trip on semicolons inside string literals', () => {
  assert.doesNotThrow(() => checkSql("SELECT * FROM t WHERE name = 'a;b'", true));
});

test('checkSql strips comments before policy check', () => {
  // comment contains a DML keyword but the statement itself is SELECT
  assert.doesNotThrow(() => checkSql('SELECT 1 -- DELETE FROM t', true));
});

test('checkSql handles MySQL -- comment parser differential correctly', () => {
  // A real line comment (`-- ` with whitespace) hides the rest on every
  // supported engine, so this is one statement and must be accepted.
  assert.equal(checkSql('SELECT 1 -- x; DROP TABLE t', true), 'SELECT 1 -- x; DROP TABLE t');
  // MySQL treats `--1` as arithmetic, NOT a comment: the semicolon is real
  // and the second statement must be caught (DBHub CVE-2026-61789 class).
  assert.throws(() => checkSql('SELECT 1--1; DROP TABLE t', true), SqlPolicyError);
  // A semicolon inside a real string literal is data, not a statement.
  assert.equal(checkSql("SELECT 'a; DROP TABLE t' AS x FROM t", true), "SELECT 'a; DROP TABLE t' AS x FROM t");
});

test('checkSql rejects empty', () => {
  assert.throws(() => checkSql('   ', true), SqlPolicyError);
});

/* ---------------- classifySql: statement classification ---------------- */

test('classifySql: read verbs', () => {
  for (const sql of ['SELECT 1', 'select * from t', 'SHOW TABLES', 'DESCRIBE t', 'DESC t', 'EXPLAIN SELECT 1']) {
    assert.equal(classifySql(sql), 'read', `should classify ${sql} as read`);
  }
  // USE mutates pooled session state; it is not a read statement.
  assert.equal(classifySql('USE db1'), 'forbidden');
  assert.throws(() => checkSql('USE db1', true), SqlPolicyError);
});

test('classifySql: write verb hidden in CTE is not a read', () => {
  assert.equal(classifySql('WITH c AS (DELETE FROM t) SELECT * FROM c'), 'delete');
  assert.equal(classifySql('WITH a AS (SELECT 1), b AS (UPDATE t SET x=1) SELECT * FROM a'), 'update');
  assert.equal(classifySql('WITH c AS (SELECT 1) SELECT * FROM c'), 'read');
  assert.throws(
    () => checkSql('WITH c AS (DELETE FROM t) SELECT * FROM c', true),
    SqlPolicyError
  );
});

test('classifySql: insert verbs', () => {
  assert.equal(classifySql('INSERT INTO t VALUES(1)'), 'insert');
  assert.equal(classifySql('REPLACE INTO t VALUES(1)'), 'insert');
});

test('classifySql: update verbs', () => {
  assert.equal(classifySql('UPDATE t SET a=1'), 'update');
  assert.equal(classifySql('MERGE INTO t USING s ON ...'), 'update');
});

test('classifySql: delete verb', () => {
  assert.equal(classifySql('DELETE FROM t'), 'delete');
});

test('classifySql: ddl verbs', () => {
  for (const sql of ['CREATE TABLE t(a int)', 'ALTER TABLE t ADD b int', 'DROP TABLE t', 'TRUNCATE TABLE t', 'RENAME TABLE a TO b']) {
    assert.equal(classifySql(sql), 'ddl', `should classify ${sql} as ddl`);
  }
});

test('classifySql: forbidden verbs', () => {
  for (const sql of ['GRANT SELECT ON t TO u', 'REVOKE SELECT ON t FROM u', 'SET @a=1', 'KILL 1', 'SHUTDOWN', 'LOAD DATA INFILE x', 'CALL p()', 'EXEC sp']) {
    assert.equal(classifySql(sql), 'forbidden', `should classify ${sql} as forbidden`);
  }
});

test('classifySql: unknown verbs', () => {
  assert.equal(classifySql('SOMETHING WEIRD'), 'unknown');
});

test('classifySql: WITH CTE classified by body statement', () => {
  assert.equal(classifySql('WITH c AS (SELECT 1) SELECT * FROM c'), 'read');
  assert.equal(classifySql('WITH c AS (SELECT 1) INSERT INTO t SELECT * FROM c'), 'insert');
  assert.equal(classifySql('WITH c AS (SELECT 1) UPDATE t SET a=1 WHERE id IN (SELECT * FROM c)'), 'update');
  assert.equal(classifySql('WITH c AS (SELECT 1) DELETE FROM t WHERE id IN (SELECT * FROM c)'), 'delete');
});

test('classifySql: WITH multiple CTEs / RECURSIVE / explicit column list', () => {
  assert.equal(classifySql('WITH a AS (SELECT 1), b AS (SELECT 2) SELECT * FROM a, b'), 'read');
  assert.equal(classifySql('WITH a AS (SELECT 1), b AS (SELECT 2) DELETE FROM t'), 'delete');
  assert.equal(classifySql('WITH RECURSIVE c AS (SELECT 1 UNION ALL SELECT 2) SELECT * FROM c'), 'read');
  assert.equal(classifySql('WITH c(x) AS (SELECT 1) SELECT * FROM c'), 'read');
  assert.equal(classifySql('WITH c AS (SELECT 1) DROP TABLE t'), 'ddl');
});

test('classifySql: EXPLAIN classified by explained statement', () => {
  assert.equal(classifySql('EXPLAIN SELECT 1'), 'read');
  assert.equal(classifySql('EXPLAIN ANALYZE UPDATE t SET a=1'), 'update');
  assert.equal(classifySql('EXPLAIN PLAN DELETE FROM t'), 'delete');
});

test('classifySql: comments and literals do not flip the type', () => {
  assert.equal(classifySql('SELECT 1 -- DROP TABLE t'), 'read');
  assert.equal(classifySql("SELECT 'DROP TABLE' FROM t"), 'read');
  assert.equal(classifySql('/* DELETE FROM t */ SELECT 1'), 'read');
});

/* --------------- checkSql: fine-grained write permissions --------------- */

const ALL_OFF = { allowInsert: false, allowUpdate: false, allowDelete: false, allowDdl: false };
const ALL_ON = { allowInsert: true, allowUpdate: true, allowDelete: true, allowDdl: true };

test('checkSql: read-only still blocks all writes regardless of perms', () => {
  for (const sql of ['DELETE FROM t', 'INSERT INTO t VALUES(1)', 'UPDATE t SET a=1', 'DROP TABLE t']) {
    assert.throws(() => checkSql(sql, true, ALL_ON), SqlPolicyError, `should block ${sql} in read-only`);
  }
});

test('checkSql: write blocked when its flag is off', () => {
  assert.throws(() => checkSql('INSERT INTO t VALUES(1)', false, ALL_OFF), SqlPolicyError);
  assert.throws(() => checkSql('UPDATE t SET a=1', false, ALL_OFF), SqlPolicyError);
  assert.throws(() => checkSql('DELETE FROM t', false, ALL_OFF), SqlPolicyError);
  assert.throws(() => checkSql('DROP TABLE t', false, ALL_OFF), SqlPolicyError);
});

test('checkSql: write allowed only when its own flag is on', () => {
  const insertOnly = { allowInsert: true, allowUpdate: false, allowDelete: false, allowDdl: false };
  assert.doesNotThrow(() => checkSql('INSERT INTO t VALUES(1)', false, insertOnly));
  assert.throws(() => checkSql('UPDATE t SET a=1', false, insertOnly), SqlPolicyError);
  assert.throws(() => checkSql('DELETE FROM t', false, insertOnly), SqlPolicyError);
  assert.throws(() => checkSql('DROP TABLE t', false, insertOnly), SqlPolicyError);

  const updateOnly = { allowInsert: false, allowUpdate: true, allowDelete: false, allowDdl: false };
  assert.doesNotThrow(() => checkSql('UPDATE t SET a=1', false, updateOnly));
  assert.throws(() => checkSql('INSERT INTO t VALUES(1)', false, updateOnly), SqlPolicyError);

  const deleteOnly = { allowInsert: false, allowUpdate: false, allowDelete: true, allowDdl: false };
  assert.doesNotThrow(() => checkSql('DELETE FROM t', false, deleteOnly));
  assert.throws(() => checkSql('INSERT INTO t VALUES(1)', false, deleteOnly), SqlPolicyError);

  const ddlOnly = { allowInsert: false, allowUpdate: false, allowDelete: false, allowDdl: true };
  assert.doesNotThrow(() => checkSql('DROP TABLE t', false, ddlOnly));
  assert.throws(() => checkSql('DELETE FROM t', false, ddlOnly), SqlPolicyError);
});

test('checkSql: read statements always allowed even with all write flags off', () => {
  assert.doesNotThrow(() => checkSql('SELECT 1', false, ALL_OFF));
  assert.doesNotThrow(() => checkSql('SHOW TABLES', false, ALL_OFF));
});

test('checkSql: forbidden/unknown never allowed even with perms', () => {
  assert.throws(() => checkSql('GRANT SELECT ON t TO u', false, ALL_ON), SqlPolicyError);
  assert.throws(() => checkSql('CALL p()', false, ALL_ON), SqlPolicyError);
  assert.throws(() => checkSql('SET @a=1', false, ALL_ON), SqlPolicyError);
  assert.throws(() => checkSql('SOMETHING WEIRD', false, ALL_ON), SqlPolicyError);
});

test('checkSql: perms passed to read-only connection are ignored (read-only wins)', () => {
  // read-only master switch takes precedence over any write flag
  assert.throws(() => checkSql('DROP TABLE t', true, ALL_ON), SqlPolicyError);
});

/* ---------------- config: write permission flags ---------------- */

test('config: write permission flags default to false', async () => {
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'dameng',
    MULTIDB_HOST: '10.0.0.1',
    MULTIDB_USER: 'SYSDBA',
    MULTIDB_PASSWORD: 'pw',
  }, async () => {
    const conns = config.loadConnections();
    assert.equal(conns[0].allowInsert, false);
    assert.equal(conns[0].allowUpdate, false);
    assert.equal(conns[0].allowDelete, false);
    assert.equal(conns[0].allowDdl, false);
  });
});

test('config: write permission flags from env vars', async () => {
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'mysql',
    MULTIDB_HOST: '10.0.0.1',
    MULTIDB_USER: 'root',
    MULTIDB_PASSWORD: 'pw',
    MULTIDB_READ_ONLY: 'false',
    MULTIDB_ALLOW_INSERT: 'true',
    MULTIDB_ALLOW_UPDATE: '1',
    MULTIDB_ALLOW_DELETE: 'yes',
    MULTIDB_ALLOW_DDL: 'false',
  }, async () => {
    const conns = config.loadConnections();
    assert.equal(conns[0].readOnly, false);
    assert.equal(conns[0].allowInsert, true);
    assert.equal(conns[0].allowUpdate, true);
    assert.equal(conns[0].allowDelete, true);
    assert.equal(conns[0].allowDdl, false);
  });
});

test('config: write permission flags from multi-connection JSON', async () => {
  await withEnvAsync({
    MULTIDB_CONNECTIONS: JSON.stringify([
      { name: 'dev', type: 'dameng', host: '10.0.0.1', user: 'SYSDBA', password: 'pw', schema: 'DEV', readOnly: false, allowInsert: true, allowDelete: true },
    ]),
  }, async () => {
    const conns = config.loadConnections();
    assert.equal(conns[0].allowInsert, true);
    assert.equal(conns[0].allowDelete, true);
    assert.equal(conns[0].allowUpdate, false);
    assert.equal(conns[0].allowDdl, false);
  });
});


/* -------------------- placeholder handling (params) -------------------- */

test('countPlaceholders: counts real bind markers only', () => {
  assert.equal(countPlaceholders('SELECT * FROM t WHERE a=? AND b=?'), 2);
  assert.equal(countPlaceholders('SELECT ?'), 1);
  assert.equal(countPlaceholders('SELECT 1'), 0);
});

test('countPlaceholders: ignores ? inside literals, identifiers and comments', () => {
  assert.equal(countPlaceholders("SELECT '?' AS q"), 0);
  assert.equal(countPlaceholders('SELECT "a?b" FROM t'), 0);
  assert.equal(countPlaceholders('SELECT `a?b` FROM t'), 0);
  assert.equal(countPlaceholders('SELECT [a?b] FROM t'), 0);
  assert.equal(countPlaceholders('SELECT 1 -- ? trailing'), 0);
  assert.equal(countPlaceholders('SELECT 1 /* ? */ WHERE a=?'), 1);
  assert.equal(countPlaceholders("SELECT 'it''s ? ok', ?"), 1);
  // MySQL: `--` without trailing whitespace is arithmetic, so `?` is real.
  assert.equal(countPlaceholders('SELECT 1--? AS x'), 1);
});

test('toNamedPlaceholders: rewrites ? to @pN in order, skipping literals', () => {
  assert.equal(
    toNamedPlaceholders('SELECT * FROM t WHERE a=? AND b=?'),
    'SELECT * FROM t WHERE a=@p1 AND b=@p2'
  );
  assert.equal(toNamedPlaceholders("SELECT '?' , ?"), "SELECT '?' , @p1");
});

/* ---------------------------- config ---------------------------- */

async function withEnvAsync(vars, fn) {
  const saved = {};
  for (const k of Object.keys(process.env)) if (k.startsWith('MULTIDB_')) saved[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    await fn();
  } finally {
    config.resetConfigCache();
    for (const k of Object.keys(saved)) process.env[k] = saved[k];
    for (const k of Object.keys(process.env)) if (k.startsWith('MULTIDB_') && !(k in saved)) delete process.env[k];
  }
}

test('config: single connection from env vars', async () => {
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'dameng',
    MULTIDB_HOST: '10.0.0.1',
    MULTIDB_PORT: '5236',
    MULTIDB_USER: 'SYSDBA',
    MULTIDB_PASSWORD: 'pw',
    MULTIDB_SCHEMA: 'SYSDBA',
  }, async () => {
    const conns = config.loadConnections();
    assert.equal(conns.length, 1);
    assert.equal(conns[0].name, 'default');
    assert.equal(conns[0].host, '10.0.0.1');
    assert.equal(conns[0].type, 'dameng');
    assert.equal(conns[0].readOnly, true);
  });
});

test('config: multi-connection requires explicit name', async () => {
  await withEnvAsync({
    MULTIDB_CONNECTIONS: JSON.stringify([
      { name: 'dev', type: 'dameng', host: '10.0.0.1', user: 'SYSDBA', password: 'pw', schema: 'DEV' },
      { name: 'prod', type: 'sqlserver', host: '10.0.0.2', user: 'sa', password: 'pw', schema: 'PROD', readOnly: false },
    ]),
  }, async () => {
    const conns = config.loadConnections();
    assert.equal(conns.length, 2);
    assert.throws(() => config.resolveConnection(), /Multiple connections/i);
    assert.equal(config.resolveConnection('dev').schema, 'DEV');
    assert.equal(config.resolveConnection('prod').readOnly, false);
    assert.throws(() => config.resolveConnection('nope'), /unknown connection/i);
  });
});

test('config: single connection auto-selects even with a wrong name', async () => {
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'sqlserver',
    MULTIDB_HOST: 'localhost',
    MULTIDB_USER: 'sa',
    MULTIDB_PASSWORD: 'pw',
  }, async () => {
    assert.throws(() => config.resolveConnection('other'), /unknown connection/i);
    assert.equal(config.resolveConnection().host, 'localhost');
    assert.equal(config.resolveConnection('default').type, 'sqlserver');
  });
});

test('config: rejects invalid db type', async () => {
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'oracle',
    MULTIDB_HOST: 'h',
    MULTIDB_USER: 'u',
  }, async () => {
    assert.throws(() => config.loadConnections(), /dameng.*sqlserver|type/i);
  });
});

test('config: rejects invalid JSON in MULTIDB_CONNECTIONS', async () => {
  await withEnvAsync({ MULTIDB_CONNECTIONS: 'not json' }, async () => {
    assert.throws(() => config.loadConnections(), /not valid JSON/i);
  });
});

/* ---------------------- maxRows governance clamp ---------------------- */

test('config: queryTimeoutMs=0 disables JS timeout in both config forms', async () => {
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'mysql', MULTIDB_HOST: 'h', MULTIDB_USER: 'u',
    MULTIDB_QUERY_TIMEOUT_MS: '0',
  }, async () => {
    assert.equal(config.loadConnections()[0].queryTimeoutMs, 0);
  });
  await withEnvAsync({
    MULTIDB_CONNECTIONS: JSON.stringify([{
      name: 'z', type: 'mysql', host: 'h', user: 'u', queryTimeoutMs: 0,
    }]),
  }, async () => {
    assert.equal(config.loadConnections()[0].queryTimeoutMs, 0);
  });
});

test('clampMaxRows: per-call override cannot raise the configured ceiling', () => {
  assert.deepEqual(config.clampMaxRows(1_000_000, 500), { limit: 500, clamped: true });
  assert.deepEqual(config.clampMaxRows(50, 500), { limit: 50, clamped: false });
  assert.deepEqual(config.clampMaxRows(undefined, 500), { limit: 500, clamped: false });
  // Invalid overrides fall back to the configured cap instead of widening it.
  assert.deepEqual(config.clampMaxRows(-1, 500), { limit: 500, clamped: false });
  assert.deepEqual(config.clampMaxRows(Number.NaN, 500), { limit: 500, clamped: false });
});

/* ---------------------------- masking ---------------------------- */

function fakeResult(rows, columns) {
  return { columns: columns || Object.keys(rows[0] || {}), rows, rowCount: rows.length, truncated: false, elapsedMs: 1 };
}

test('masking: fixed / null / partial strategies', () => {
  const rows = [
    { ID: 1, EMAIL: 'alice@example.com', PHONE: '13800138000', NAME: 'Alice', NOTE: 'ok' },
    { ID: 2, EMAIL: 'short', PHONE: '123', NAME: 'Bob', NOTE: 'ok' },
  ];
  const rules = [
    { column: '^EMAIL$', strategy: 'fixed', value: '***' },
    { column: 'phone', strategy: 'partial', keepLast: 4 },
    { column: 'name', strategy: 'null' },
  ];
  const { result, maskedColumns } = applyMasking(fakeResult(rows), rules);
  assert.equal(result.rows[0].EMAIL, '***');
  assert.equal(result.rows[1].EMAIL, '***');
  assert.equal(result.rows[0].PHONE, '*******8000'); // 11 chars, keep last 4 -> 7 masked
  assert.equal(result.rows[1].PHONE, '***'); // short value fully masked
  assert.equal(result.rows[0].NAME, null);
  assert.equal(result.rows[0].ID, 1); // non-matching columns untouched
  assert.equal(result.rows[0].NOTE, 'ok');
  assert.deepEqual([...maskedColumns].sort(), ['EMAIL', 'NAME', 'PHONE']);
});

test('masking: empty rules is a no-op (identity)', () => {
  const r = fakeResult([{ A: 1 }]);
  const out = applyMasking(r, []);
  assert.equal(out.result, r);
  assert.deepEqual(out.maskedColumns, []);
});

test('masking: invalid regex throws (fail-closed at use time too)', () => {
  assert.throws(() => applyMasking(fakeResult([{ A: 1 }]), [{ column: '[', strategy: 'fixed' }]));
});

test('masking config: invalid rule aborts config load', async () => {
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'mysql',
    MULTIDB_HOST: '10.0.0.1',
    MULTIDB_USER: 'root',
    MULTIDB_PASSWORD: 'pw',
    MULTIDB_MASKING_RULES: JSON.stringify([{ column: 'email', strategy: 'bogus' }]),
  }, async () => {
    assert.throws(() => config.loadConnections(), /strategy must be/);
  });
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'mysql',
    MULTIDB_HOST: '10.0.0.1',
    MULTIDB_USER: 'root',
    MULTIDB_PASSWORD: 'pw',
    MULTIDB_MASKING_RULES: JSON.stringify([{ column: '[', strategy: 'fixed' }]),
  }, async () => {
    assert.throws(() => config.loadConnections(), /not a valid regex/);
  });
});

test('masking config: valid rules parsed with defaults', async () => {
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'mysql',
    MULTIDB_HOST: '10.0.0.1',
    MULTIDB_USER: 'root',
    MULTIDB_PASSWORD: 'pw',
    MULTIDB_MASKING_RULES: JSON.stringify([{ column: 'SECRET', strategy: 'partial' }]),
    MULTIDB_MAX_RESULT_BYTES: '2048',
    MULTIDB_MAX_QUERY_LENGTH: '500',
  }, async () => {
    const c = config.loadConnections()[0];
    assert.equal(c.maskingRules.length, 1);
    assert.equal(c.maskingRules[0].strategy, 'partial');
    assert.equal(c.maskingRules[0].keepLast, 4);
    assert.equal(c.maxResultBytes, 2048);
    assert.equal(c.maxQueryLength, 500);
  });
});

/* ---------------------------- byte cap ---------------------------- */

test('byte cap: drops whole rows past the budget', () => {
  const rows = [{ A: 'x'.repeat(50) }, { A: 'y'.repeat(50) }, { A: 'z'.repeat(50) }];
  const out = capResultBytes(rows, 120); // each row ~60 bytes -> fits 1, maybe 2
  assert.equal(out.truncatedByBytes, true);
  assert.ok(out.rows.length < rows.length);
  assert.ok(out.bytes <= 120);
});

test('byte cap: 0 disables capping', () => {
  const rows = [{ A: 'x'.repeat(5000) }];
  const out = capResultBytes(rows, 0);
  assert.equal(out.truncatedByBytes, false);
  assert.equal(out.rows.length, 1);
});

test('byte cap: cap larger than result keeps everything', () => {
  const rows = [{ A: 1 }, { A: 2 }];
  const out = capResultBytes(rows, 1_000_000);
  assert.equal(out.truncatedByBytes, false);
  assert.equal(out.rows.length, 2);
});

/* ---------------------------- errors ---------------------------- */

test('structuredError: policy error classified with non-recoverable + suggestion', async () => {
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'mysql',
    MULTIDB_HOST: 'secret-host.internal',
    MULTIDB_USER: 'root',
    MULTIDB_PASSWORD: 'TopSecret123',
  }, async () => {
    const e = new SqlPolicyError('read-only mode: only SELECT allowed');
    const r = structuredError(`SQL policy violation: ${e.message}`, e);
    const p = r.structuredContent;
    assert.equal(r.isError, true);
    assert.equal(p.code, 'READ_ONLY_VIOLATION');
    assert.equal(p.category, 'policy');
    assert.equal(p.recoverable, false);
    assert.ok(p.suggestion && /administrator|write permission/i.test(p.suggestion));
    // text stays JSON-parseable for older clients
    assert.equal(JSON.parse(r.content[0].text).code, 'READ_ONLY_VIOLATION');
  });
});

test('structuredError: parameter mismatch is recoverable validation', () => {
  const e = new SqlPolicyError('parameter count mismatch: 2 vs 1');
  const p = structuredError(`SQL policy violation: ${e.message}`, e).structuredContent;
  assert.equal(p.code, 'PARAM_COUNT_MISMATCH');
  assert.equal(p.category, 'validation');
  assert.equal(p.recoverable, true);
});

test('structuredError: query timeout classified', () => {
  const e = Object.assign(new Error('query timed out after 30000 ms'), { name: 'QueryTimeoutError' });
  const p = structuredError(e.message, e).structuredContent;
  assert.equal(p.code, 'QUERY_TIMEOUT');
  assert.equal(p.recoverable, true);
});

test('structuredError: auth failure is non-recoverable', () => {
  const e = new Error("Access denied for user 'root' (using password: YES)");
  const p = structuredError(e.message, e).structuredContent;
  assert.equal(p.code, 'AUTH_FAILED');
  assert.equal(p.category, 'connection');
  assert.equal(p.recoverable, false);
});

test('redact: scrubs configured password, user, host and URLs', async () => {
  config.resetConfigCache();
  await withEnvAsync({
    MULTIDB_DB_TYPE: 'dameng',
    MULTIDB_HOST: 'db.internal.corp',
    MULTIDB_USER: 'SYSDBA',
    MULTIDB_PASSWORD: 'Gschina0601',
  }, async () => {
    const msg = "connect dm://SYSDBA:Gschina0601@db.internal.corp:5236 failed on host db.internal.corp for user SYSDBA";
    const out = redact(msg);
    assert.ok(!out.includes('Gschina0601'));
    assert.ok(!out.includes('db.internal.corp'));
    assert.ok(!out.includes('SYSDBA'));
    assert.ok(out.includes('[REDACTED]'));
  });
});

/* ---------------------------- runner ---------------------------- */

for (const { name, fn } of tests) {
  try {
    await fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    console.log(`FAIL  ${name}  — ${e.message}`);
    process.exitCode = 1;
  }
}

console.log(`\n${passed}/${tests.length} unit tests passed.`);
