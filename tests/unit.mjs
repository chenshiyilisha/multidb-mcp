/**
 * Unit tests for security policy and configuration routing.
 * No database required. Run: npm run test:unit
 */

import assert from 'node:assert/strict';
import { checkIdentifier, checkSql, SqlPolicyError } from '../build/security.js';
import * as config from '../build/config.js';

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

test('checkSql rejects comment-embedded second statement', () => {
  // a; after comment marker must still be caught as multi-statement
  assert.throws(() => checkSql('SELECT 1 -- x; DROP TABLE t', true), SqlPolicyError);
});

test('checkSql rejects empty', () => {
  assert.throws(() => checkSql('   ', true), SqlPolicyError);
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
