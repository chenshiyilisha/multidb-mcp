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

/* --------------------- parameterized executeSql (all 3 drivers) --------------------- */

test('mysql executeSql binds params via pool.query(sql, binds)', async () => {
  const pool = fakePool(() => [{ id: 1 }]);
  const db = makeMysql(pool);
  db.connect = async () => {};
  await db.executeSql('SELECT * FROM t WHERE id = ? AND name = ?', 100, [7, 'bob']);
  assert.equal(pool.calls[0].sql, 'SELECT * FROM t WHERE id = ? AND name = ?');
  assert.deepEqual(pool.calls[0].binds, [7, 'bob']);
});

test('sqlserver executeSql rewrites ? to @pN and binds via request.input()', async () => {
  const bound = [];
  let queriedSql = '';
  const fakePool = {
    request() {
      return {
        input(name, value) {
          bound.push({ name, value });
          return this;
        },
        async query(sql) {
          queriedSql = sql;
          return { recordset: [{ id: 1 }] };
        },
      };
    },
    async close() {},
  };
  const db = createDatabase({
    name: 'mssql', type: 'sqlserver', host: 'h', port: 1433, user: 'u', password: 'p',
    schema: 'db', readOnly: false, maxRows: 100, queryTimeoutMs: 1000,
  });
  db.pool = fakePool;
  db.connect = async () => {};
  const res = await db.executeSql('SELECT * FROM t WHERE a = ? AND b = ?', 100, [11, 'x']);
  assert.equal(queriedSql, 'SELECT * FROM t WHERE a = @p1 AND b = @p2');
  assert.deepEqual(bound, [
    { name: 'p1', value: 11 },
    { name: 'p2', value: 'x' },
  ]);
  assert.equal(res.rowCount, 1);
});

test('sqlserver executeSql with no params leaves SQL untouched', async () => {
  let queriedSql = '';
  const fakePool = {
    request() {
      return {
        input() { throw new Error('should not bind when no params'); },
        async query(sql) { queriedSql = sql; return { recordset: [] }; },
      };
    },
    async close() {},
  };
  const db = createDatabase({
    name: 'mssql', type: 'sqlserver', host: 'h', port: 1433, user: 'u', password: 'p',
    schema: 'db', readOnly: true, maxRows: 100, queryTimeoutMs: 1000,
  });
  db.pool = fakePool;
  db.connect = async () => {};
  await db.executeSql('SELECT 1', 100);
  assert.equal(queriedSql, 'SELECT 1');
});

test('dameng executeSql passes params through as positional binds', async () => {
  let capturedBinds = null;
  let capturedSql = '';
  const fakeConn = {
    async execute(sql, binds) {
      capturedSql = sql;
      capturedBinds = binds;
      return { rows: [{ ID: 1 }], metaData: [{ name: 'ID' }] };
    },
    async close() {},
  };
  const db = createDatabase({
    name: 'dm', type: 'dameng', host: 'h', port: 5236, user: 'u', password: 'p',
    schema: 'S', readOnly: true, maxRows: 100, queryTimeoutMs: 1000,
  });
  db.conn = fakeConn;
  db.connect = async () => {};
  const res = await db.executeSql('SELECT * FROM t WHERE id = ?', 100, [42]);
  assert.equal(capturedSql, 'SELECT * FROM t WHERE id = ?');
  assert.deepEqual(capturedBinds, [42]);
  assert.equal(res.rowCount, 1);
});

/* ---------------------------- connection self-heal ---------------------------- */

test('isConnectionLostError recognizes socket/connection errors only', async () => {
  const { isConnectionLostError } = await import('../build/db.js');
  assert.equal(isConnectionLostError(Object.assign(new Error('x'), { code: 'ECONNRESET' })), true);
  assert.equal(isConnectionLostError(new Error('socket hang up')), true);
  assert.equal(isConnectionLostError(new Error('ORA-00942: table does not exist')), false);
  assert.equal(isConnectionLostError(new Error('syntax error near SELECT')), false);
});

test('dameng ensure() pings an existing connection before use', async () => {
  let pingCount = 0;
  let execCount = 0;
  const fakeConn = {
    async ping() { pingCount++; },
    async execute() { execCount++; return { rows: [{ N: 1 }], metaData: [{ name: 'N' }] }; },
    async close() {},
  };
  const db = createDatabase({
    name: 'dm', type: 'dameng', host: 'h', port: 5236, user: 'u', password: 'p',
    schema: 'S', readOnly: true, maxRows: 100, queryTimeoutMs: 1000,
  });
  db.conn = fakeConn;
  db.connect = async () => {}; // no real connect
  await db.executeSql('SELECT 1 AS N', 100);
  assert.equal(pingCount, 1, 'should ping before executing');
  assert.equal(execCount, 1);
});

test('dameng ensure() reconnects once when ping fails (stale socket)', async () => {
  let closed = false;
  let newConnPings = 0;
  const staleConn = {
    async ping() { throw new Error('connection closed'); },
    async execute() { throw new Error('should not be used'); },
    async close() { closed = true; },
  };
  const freshConn = {
    async ping() { newConnPings++; },
    async execute(sql) { return { rows: [{ N: 1 }], metaData: [{ name: 'N' }] }; },
    async close() {},
  };
  const db = createDatabase({
    name: 'dm', type: 'dameng', host: 'h', port: 5236, user: 'u', password: 'p',
    schema: 'S', readOnly: true, maxRows: 100, queryTimeoutMs: 1000,
  });
  db.conn = staleConn;
  let connectCalls = 0;
  db.connect = async () => { connectCalls++; db.conn = freshConn; };
  const res = await db.executeSql('SELECT 1 AS N', 100);
  assert.equal(closed, true, 'stale connection should be closed');
  assert.equal(connectCalls, 1, 'should reconnect exactly once');
  assert.equal(res.rowCount, 1, 'query should succeed on the fresh connection');
});

test('dameng does NOT retry a write statement after a lost connection', async () => {
  let executeCalls = 0;
  let reconnects = 0;
  const conn = {
    async ping() {}, // ping passes...
    async execute(sql) {
      executeCalls++;
      // ...but the actual execute dies with a connection-lost error.
      throw Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' });
    },
    async close() {},
  };
  const db = createDatabase({
    name: 'dm', type: 'dameng', host: 'h', port: 5236, user: 'u', password: 'p',
    schema: 'S', readOnly: false, maxRows: 100, queryTimeoutMs: 1000,
  });
  db.conn = conn;
  db.connect = async () => { reconnects++; db.conn = conn; };
  await assert.rejects(() => db.executeSql('INSERT INTO t VALUES (1)', 100));
  assert.equal(executeCalls, 1, 'write statement must NOT be replayed');
});

test('dameng DOES retry a read statement after a lost connection', async () => {
  let executeCalls = 0;
  const makeConn = (fail) => ({
    async ping() {},
    async execute(sql) {
      executeCalls++;
      if (fail) throw Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' });
      return { rows: [{ N: 1 }], metaData: [{ name: 'N' }] };
    },
    async close() {},
  });
  const db = createDatabase({
    name: 'dm', type: 'dameng', host: 'h', port: 5236, user: 'u', password: 'p',
    schema: 'S', readOnly: true, maxRows: 100, queryTimeoutMs: 1000,
  });
  db.conn = makeConn(true);
  db.connect = async () => { db.conn = makeConn(false); };
  const res = await db.executeSql('SELECT 1 AS N', 100);
  assert.equal(executeCalls, 2, 'read should be retried on the fresh connection');
  assert.equal(res.rowCount, 1);
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

test('timeout poisons the connection: next call drops the pool before reuse', async () => {
  const slowPool = {
    async query() {
      await new Promise((r) => setTimeout(r, 300));
      return [[{ a: 1 }]];
    },
    async end() { calls.ended++; },
  };
  const calls = { ended: 0, connects: 0 };
  const db = createDatabase({
    name: 'poison', type: 'mysql', host: 'h', port: 3306, user: 'u', password: 'p',
    schema: 'db', readOnly: true, maxRows: 100, queryTimeoutMs: 30,
  });
  db.pool = slowPool;
  db.connect = async () => {
    calls.connects++;
    db.pool = { async query() { return [[{ a: 2 }]]; }, async end() {} };
  };

  await assert.rejects(() => db.executeSql('SELECT 1', 10), QueryTimeoutError);
  assert.equal(calls.ended, 0); // poisoning is recorded, not applied until next call
  const res = await db.executeSql('SELECT 1', 10);
  assert.equal(calls.ended, 1, 'poisoned pool must be closed before reuse');
  assert.equal(calls.connects, 1, 'a fresh pool must be established');
  assert.equal(res.rows[0].a, 2);
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
