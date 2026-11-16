/**
 * Unit tests for the database layer (no live DB required).
 *
 * We inject a fake pool into each Database instance to verify:
 *   - the SQL each method builds (parameterization / identifier handling)
 *   - row mapping (columns -> TableColumn / QueryResult)
 *   - query timeout behavior
 *
 * Run: node tests/test_db.mjs
 */

import assert from 'node:assert/strict';
import { createDatabase, QueryTimeoutError } from '../build/db.js';

let passed = 0;
const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

/** Build a MySQL config with a fake pool that records queries. */
function makeMysql(poolImpl) {
  const cfg = {
    name: 'mysqltest',
    type: 'mysql',
    host: '10.0.0.9',
    port: 3306,
    user: 'u',
    password: 'p',
    schema: 'appdb',
    readOnly: true,
    maxRows: 1000,
    queryTimeoutMs: 30000,
  };
  const db = createDatabase(cfg);
  db.pool = poolImpl; // inject fake (TS private is just a runtime property)
  return db;
}

/** Fake mysql2 pool: `query(sql, binds)` resolves [rows] and records calls. */
function fakePool(rowsFor) {
  const calls = [];
  return {
    calls,
    async query(sql, binds = []) {
      calls.push({ sql, binds });
      return [rowsFor(sql, binds)];
    },
    async end() {},
  };
}

/* ---------------------------- mysql: listTables ---------------------------- */

test('mysql listTables builds parameterized INFORMATION_SCHEMA query', async () => {
  const pool = fakePool(() => [{ TABLE_NAME: 'users' }, { TABLE_NAME: 'orders' }]);
  const db = makeMysql(pool);
  db.connect = async () => {}; // no real connect
  const tables = await db.listTables('appdb');
  assert.deepEqual(tables, ['users', 'orders']);
  assert.equal(pool.calls.length, 1);
  assert.match(pool.calls[0].sql, /INFORMATION_SCHEMA\.TABLES/);
  assert.match(pool.calls[0].sql, /TABLE_SCHEMA = \?/);
  assert.deepEqual(pool.calls[0].binds, ['appdb']);
});

/* ---------------------------- mysql: describeTable ---------------------------- */

test('mysql describeTable maps columns incl. comment', async () => {
  const pool = fakePool(() => [
    { COLUMN_NAME: 'id', DATA_TYPE: 'int', CHARACTER_MAXIMUM_LENGTH: null, IS_NULLABLE: 'NO', COLUMN_DEFAULT: null, COLUMN_COMMENT: 'pk' },
    { COLUMN_NAME: 'name', DATA_TYPE: 'varchar', CHARACTER_MAXIMUM_LENGTH: 100, IS_NULLABLE: 'YES', COLUMN_DEFAULT: null, COLUMN_COMMENT: 'name col' },
  ]);
  const db = makeMysql(pool);
  db.connect = async () => {};
  const info = await db.describeTable('users', 'appdb');
  assert.equal(info.table, 'users');
  assert.equal(info.schema, 'appdb');
  assert.equal(info.columns.length, 2);
  assert.equal(info.columns[0].name, 'id');
  assert.equal(info.columns[0].nullable, false);
  assert.equal(info.columns[0].comment, 'pk');
  assert.equal(info.columns[1].length, 100);
  assert.equal(info.columns[1].nullable, true);
  assert.match(pool.calls[0].sql, /INFORMATION_SCHEMA\.COLUMNS/);
  assert.deepEqual(pool.calls[0].binds, ['appdb', 'users']);
});

/* ---------------------------- mysql: executeSql ---------------------------- */

test('mysql executeSql normalizes rows, rowCount, truncation, elapsed', async () => {
  const pool = fakePool(() => [
    { id: 1, name: 'a' },
    { id: 2, name: 'b' },
    { id: 3, name: 'c' },
  ]);
  const db = makeMysql(pool);
  db.connect = async () => {};
  const res = await db.executeSql('SELECT * FROM users', 2);
  assert.equal(res.rowCount, 3);
  assert.equal(res.truncated, true);
  assert.equal(res.rows.length, 2);
  assert.deepEqual(res.columns, ['id', 'name']);
  assert.equal(typeof res.elapsedMs, 'number');
  assert.match(pool.calls[0].sql, /SELECT \* FROM users/);
});

test('mysql executeSql handles empty result set', async () => {
  const pool = fakePool(() => []);
  const db = makeMysql(pool);
  db.connect = async () => {};
  const res = await db.executeSql('SELECT * FROM empty_table', 100);
  assert.equal(res.rowCount, 0);
  assert.equal(res.truncated, false);
  assert.deepEqual(res.columns, []);
});

/* ---------------------------- mysql: testConnection ---------------------------- */

test('mysql testConnection returns version and schema', async () => {
  const pool = fakePool(() => [{ V: '8.0.35' }]);
  const db = makeMysql(pool);
  db.connect = async () => {};
  const info = await db.testConnection();
  assert.equal(info.version, 'MySQL 8.0.35');
  assert.equal(info.schema, 'appdb');
});

/* ---------------------------- timeout behavior ---------------------------- */

test('executeSql rejects with QueryTimeoutError when slow', async () => {
  const slowPool = {
    async query() {
      await new Promise((r) => setTimeout(r, 500));
      return [[{ a: 1 }]];
    },
    async end() {},
  };
  const cfg = {
    name: 't',
    type: 'mysql',
    host: 'h',
    port: 3306,
    user: 'u',
    password: 'p',
    schema: 'db',
    readOnly: true,
    maxRows: 100,
    queryTimeoutMs: 50, // very short
  };
  const db = createDatabase(cfg);
  db.pool = slowPool;
  db.connect = async () => {};
  await assert.rejects(() => db.executeSql('SELECT 1', 10), QueryTimeoutError);
});

/* ---------------------------- factory ---------------------------- */

test('createDatabase routes to the right implementation', () => {
  const mk = (type) =>
    createDatabase({
      name: 'x',
      type,
      host: 'h',
      port: 1,
      user: 'u',
      password: 'p',
      schema: 's',
      readOnly: true,
      maxRows: 10,
      queryTimeoutMs: 1000,
    });
  assert.equal(mk('dameng').type, 'dameng');
  assert.equal(mk('sqlserver').type, 'sqlserver');
  assert.equal(mk('mysql').type, 'mysql');
  assert.throws(() => mk('oracle'), /unsupported database type/);
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

console.log(`\n${passed}/${tests.length} db-layer tests passed.`);
