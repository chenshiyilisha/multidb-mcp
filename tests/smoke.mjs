/**
 * Stdio smoke test: drives the built multidb-mcp server over the real MCP
 * protocol against a live database, covering happy paths and policy
 * rejections. Database type is driven by MULTIDB_DB_TYPE.
 *
 * Dameng:
 *   MULTIDB_DB_TYPE=dameng MULTIDB_HOST=... MULTIDB_USER=... MULTIDB_PASSWORD=... MULTIDB_SCHEMA=... node tests/smoke.mjs
 * SQL Server:
 *   MULTIDB_DB_TYPE=sqlserver MULTIDB_HOST=... MULTIDB_PORT=... MULTIDB_USER=... MULTIDB_PASSWORD=... MULTIDB_SCHEMA=<database> node tests/smoke.mjs
 * MySQL:
 *   MULTIDB_DB_TYPE=mysql MULTIDB_HOST=... MULTIDB_PORT=... MULTIDB_USER=... MULTIDB_PASSWORD=... MULTIDB_SCHEMA=<database> node tests/smoke.mjs
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.join(__dirname, '..', 'build', 'index.js');

const dbType = process.env.MULTIDB_DB_TYPE || 'dameng';

const env = {
  ...process.env,
  MULTIDB_DB_TYPE: dbType,
  MULTIDB_READ_ONLY: process.env.MULTIDB_READ_ONLY ?? 'true',
};

const proc = spawn(process.execPath, [serverPath], { env, stdio: ['pipe', 'pipe', 'pipe'] });

let nextId = 1;
const pending = new Map();

function send(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}

function sendNotification(method, params) {
  proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
}

proc.stdout.on('data', (buf) => {
  for (const line of buf.toString().split('\n')) {
    if (!line.trim()) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue;
    }
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id).resolve(msg);
      pending.delete(msg.id);
    }
  }
});

proc.stderr.on('data', (buf) => {
  const s = buf.toString().trim();
  if (s) console.error('[server stderr]', s);
});

function check(name, cond, detail = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!cond) process.exitCode = 1;
}

function callTool(name, args) {
  return send('tools/call', { name, arguments: args });
}

function parseText(msg) {
  const txt = msg.result?.content?.[0]?.text ?? '';
  try {
    return JSON.parse(txt);
  } catch {
    return { _raw: txt };
  }
}

// Type-specific test inputs
const versionPattern =
  dbType === 'sqlserver' ? /SQL Server/i : dbType === 'mysql' ? /MySQL/i : /DM Database Server/;
const countSql =
  dbType === 'sqlserver'
    ? "SELECT COUNT(*) AS CNT FROM sys.tables WHERE type = 'U'"
    : dbType === 'mysql'
      ? 'SELECT COUNT(*) AS CNT FROM information_schema.tables WHERE table_schema = DATABASE()'
      : 'SELECT COUNT(*) AS CNT FROM USER_TABLES';
const dmlSql =
  dbType === 'sqlserver'
    ? 'DELETE FROM sys.tables'
    : dbType === 'mysql'
      ? 'DELETE FROM information_schema.tables'
      : 'DELETE FROM USER_TABLES';

try {
  // 1. initialize handshake
  const init = await send('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'smoke', version: '1.0' },
  });
  check('initialize handshake', init.result?.serverInfo?.name === 'multidb-mcp', JSON.stringify(init.result?.serverInfo));
  sendNotification('notifications/initialized', {});

  // 2. tools/list
  const tools = await send('tools/list', {});
  const names = (tools.result?.tools || []).map((t) => t.name);
  check(
    'tools/list registers 5 tools',
    ['test_connection', 'list_connections', 'list_tables', 'describe_table', 'execute_sql'].every((n) =>
      names.includes(n)
    ),
    names.join(', ')
  );

  // 3. test_connection
  const tc = parseText(await callTool('test_connection', {}));
  check('test_connection ok', tc.ok === true && versionPattern.test(tc.version || ''), tc.version || tc.error);

  // 4. list_connections (password must never leak)
  const lc = parseText(await callTool('list_connections', {}));
  check('list_connections has no password', lc[0] && !('password' in lc[0]) && lc[0].host, `host=${lc[0]?.host}`);

  // 5. list_tables
  const lt = parseText(await callTool('list_tables', {}));
  check('list_tables returns tables', Array.isArray(lt.tables) && lt.count >= 1, `count=${lt.count}`);

  // 6. describe_table
  const t = (lt.tables || [])[0];
  if (t) {
    const dt = parseText(await callTool('describe_table', { table: t }));
    check('describe_table returns columns', Array.isArray(dt.columns) && dt.table === t, `table=${dt.table}, columns=${dt.columns?.length}`);
  } else {
    check('describe_table returns columns', false, 'no table to describe');
  }

  // 7. execute_sql SELECT
  const sq = parseText(await callTool('execute_sql', { sql: countSql }));
  check('execute_sql SELECT works', sq.rows?.[0]?.CNT !== undefined, JSON.stringify(sq.rows));

  // 8. negative: read-only rejects DML
  const dml = parseText(await callTool('execute_sql', { sql: dmlSql }));
  check('read-only rejects DML', /policy violation|read-only/i.test(dml.error || ''), dml.error);

  // 9. negative: multi-statement rejected
  const multi = parseText(await callTool('execute_sql', { sql: 'SELECT 1; DROP TABLE x' }));
  check('multi-statement rejected', /multi-statement/i.test(multi.error || ''), multi.error);

  // 10. negative: invalid identifier rejected
  const badId = parseText(await callTool('describe_table', { table: 'bad name; --' }));
  check('invalid identifier rejected', /invalid identifier/i.test(badId.error || ''), badId.error);

  console.log(`\nSmoke test done (${dbType}).`);
} catch (e) {
  console.error('Smoke test crashed:', e);
  process.exitCode = 1;
} finally {
  proc.kill();
}
