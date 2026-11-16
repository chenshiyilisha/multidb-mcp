/**
 * End-to-end test for MCP-spec enhancements:
 *   - isError:true on tool-execution failures (MCP spec 2025-06-18)
 *   - parameterized queries via ? placeholders (native driver binding)
 *   - placeholder/param count mismatch rejected clearly
 *   - tool annotations present on tools/list
 *
 * Drives the built server over the real MCP stdio protocol. DB-backed checks
 * are skipped (not failed) when the database is unreachable; isError and
 * annotation checks never need a DB.
 *
 * Usage:
 *   ENH_TEST_TYPE=mysql ENH_TEST_HOST=... ENH_TEST_USER=... \
 *   ENH_TEST_PASSWORD=... ENH_TEST_SCHEMA=... node tests/enhancements.mjs
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.join(__dirname, '..', 'build', 'index.js');

const type = process.env.ENH_TEST_TYPE || 'mysql';
const host = process.env.ENH_TEST_HOST;
const port = process.env.ENH_TEST_PORT || (type === 'dameng' ? '5236' : type === 'sqlserver' ? '1433' : '3306');
const user = process.env.ENH_TEST_USER;
const password = process.env.ENH_TEST_PASSWORD;
const schema = process.env.ENH_TEST_SCHEMA || user;

if (!host || !user || password === undefined) {
  console.error('Missing ENH_TEST_HOST / ENH_TEST_USER / ENH_TEST_PASSWORD / ENH_TEST_SCHEMA');
  process.exit(1);
}

const env = {
  ...process.env,
  MULTIDB_DB_TYPE: type,
  MULTIDB_HOST: host,
  MULTIDB_PORT: port,
  MULTIDB_USER: user,
  MULTIDB_PASSWORD: password,
  MULTIDB_SCHEMA: schema,
  MULTIDB_READ_ONLY: 'true',
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
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id).resolve(msg);
      pending.delete(msg.id);
    }
  }
});
proc.stderr.on('data', () => {});

function callTool(name, args) {
  return send('tools/call', { name, arguments: args });
}
function parseText(msg) {
  const txt = msg.result?.content?.[0]?.text ?? '';
  try { return JSON.parse(txt); } catch { return { _raw: txt }; }
}

let passed = 0;
let total = 0;
function check(name, cond, detail = '') {
  total++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (cond) passed++; else process.exitCode = 1;
}
function skip(name, why) {
  console.log(`SKIP  ${name}  — ${why}`);
}

try {
  await send('initialize', {
    protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'enh-test', version: '1.0' },
  });
  sendNotification('notifications/initialized', {});

  // 1. tool annotations exposed on tools/list
  const tools = await send('tools/list', {});
  const byName = Object.fromEntries((tools.result?.tools || []).map((t) => [t.name, t]));
  const execTool = byName['execute_sql'];
  check('execute_sql exposes annotations', !!execTool?.annotations, JSON.stringify(execTool?.annotations));
  check('execute_sql is NOT marked readOnlyHint', execTool?.annotations?.readOnlyHint === false);
  check('test_connection IS marked readOnlyHint', byName['test_connection']?.annotations?.readOnlyHint === true);

  // 2. isError on a policy rejection (no DB needed — fail-fast before connect)
  const denied = await callTool('execute_sql', { sql: 'DELETE FROM users' });
  check('rejected write sets isError=true', denied.result?.isError === true, `isError=${denied.result?.isError}`);

  // 2b. USE must not be treated as a read statement (pooled session state)
  const use = await callTool('execute_sql', { sql: 'USE otherdb' });
  check('USE rejected on read-only connection', use.result?.isError === true,
    use.result?.content?.[0]?.text || '');

  // 2c. Data-modifying CTE must not slip through as a read statement
  const cte = await callTool('execute_sql', { sql: 'WITH c AS (DELETE FROM users) SELECT * FROM c' });
  check('write inside CTE rejected', cte.result?.isError === true,
    cte.result?.content?.[0]?.text || '');

  // 3. isError on invalid identifier (no DB needed)
  const badId = await callTool('describe_table', { table: 'bad name;' });
  check('invalid identifier sets isError=true', badId.result?.isError === true, `isError=${badId.result?.isError}`);

  // 4. placeholder count mismatch is rejected clearly (no DB needed)
  const mismatch = await callTool('execute_sql', {
    sql: 'SELECT * FROM users WHERE id = ? AND name = ?',
    params: [1],
  });
  const mismatchText = mismatch.result?.content?.[0]?.text || '';
  check(
    'param count mismatch rejected with clear message',
    mismatch.result?.isError === true && /placeholder|parameter count mismatch/i.test(mismatchText),
    mismatchText
  );

  // 4b. A placeholder with zero supplied values must be rejected up front
  // (old code skipped the check when params was empty).
  const noParams = await callTool('execute_sql', { sql: 'SELECT ? AS x', params: [] });
  check(
    'placeholder with empty params rejected',
    noParams.result?.isError === true && /parameter count mismatch/i.test(noParams.result?.content?.[0]?.text || ''),
    noParams.result?.content?.[0]?.text || ''
  );

  // DB-backed checks
  const probe = await callTool('test_connection', {});
  const dbOk = probe.result?.content?.[0]?.text && parseText(probe).ok === true;
  if (!dbOk) {
    console.log(`\n[DB not reachable: ${parseText(probe).error || 'unknown'} — DB-backed checks skipped]`);
  } else {
    // 5. parameterized query returns correct row via native binding
    //    Use a literal comparison that must match through the bind path.
    const pq = parseText(await callTool('execute_sql', {
      sql: 'SELECT ? AS bound_value',
      params: ['hello_bind'],
    }));
    check('parameterized SELECT binds value correctly',
      !pq.error && JSON.stringify(pq.rows).includes('hello_bind'),
      pq.error || JSON.stringify(pq.rows));

    // 6. successful query is NOT marked isError
    const ok = await callTool('execute_sql', { sql: 'SELECT 1 AS n' });
    check('successful query has no isError', ok.result?.isError !== true, `isError=${ok.result?.isError}`);
  }

  console.log(`\n${passed}/${total} enhancement checks passed (${type}).`);
} catch (e) {
  console.error('Enhancement test crashed:', e);
  process.exitCode = 1;
} finally {
  proc.kill();
}
