/**
 * End-to-end write-permission test driven through the real MCP tool entry.
 *
 * Spawns the built server with four connections sharing one database but with
 * different write policies, then calls execute_sql over the MCP protocol.
 * To avoid writing real data, the SQL targets a non-existent table: a policy
 * rejection returns "SQL policy violation", while an allowed statement reaches
 * the driver and returns a native "table does not exist" error. This proves the
 * per-connection permission flags are actually enforced at the tool boundary.
 *
 *Usage (credentials come from env, never hardcoded):
 *   PERM_TEST_TYPE=dameng PERM_TEST_HOST=... PERM_TEST_USER=... \
 *   PERM_TEST_PASSWORD=... PERM_TEST_SCHEMA=... node tests/permissions.mjs
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.join(__dirname, '..', 'build', 'index.js');

const type = process.env.PERM_TEST_TYPE || 'dameng';
const host = process.env.PERM_TEST_HOST;
const port = process.env.PERM_TEST_PORT || (type === 'dameng' ? '5236' : type === 'sqlserver' ? '1433' : '3306');
const user = process.env.PERM_TEST_USER;
const password = process.env.PERM_TEST_PASSWORD;
const schema = process.env.PERM_TEST_SCHEMA || user;

if (!host || !user || password === undefined) {
  console.error('Missing PERM_TEST_HOST / PERM_TEST_USER / PERM_TEST_PASSWORD');
  process.exit(1);
}

const base = { type, host, port: Number(port), user, password, schema };
const connections = [
  { ...base, name: 'ro', readOnly: true },
  { ...base, name: 'noins', readOnly: false, allowInsert: false, allowUpdate: false, allowDelete: false, allowDdl: false },
  { ...base, name: 'ins', readOnly: false, allowInsert: true },
  { ...base, name: 'all', readOnly: false, allowInsert: true, allowUpdate: true, allowDelete: true, allowDdl: true },
];

const env = { ...process.env, MULTIDB_CONNECTIONS: JSON.stringify(connections) };
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
proc.stderr.on('data', () => { /* audit records go here; ignore */ });

function callTool(name, args) {
  return send('tools/call', { name, arguments: args });
}
function parseText(msg) {
  const txt = msg.result?.content?.[0]?.text ?? '';
  try { return JSON.parse(txt); } catch { return { _raw: txt }; }
}
const isPolicyErr = (r) => /SQL policy violation/i.test(r.error || '');

let passed = 0;
let total = 0;
function check(name, cond, detail = '') {
  total++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (cond) passed++; else process.exitCode = 1;
}

try {
  await send('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'perm-test', version: '1.0' },
  });
  sendNotification('notifications/initialized', {});

  const insertSql = 'INSERT INTO __multidb_perm_probe__ (id) VALUES (1)';
  const dropSql = 'DROP TABLE __multidb_perm_probe__';

  // Probe DB availability once. Policy checks must pass even when the DB is
  // down (fail-fast), while "reaches the driver" checks need a live DB.
  const probe = parseText(await callTool('test_connection', { connection: 'ins' }));
  const dbOk = probe.ok === true;
  console.log(dbOk ? `[db reachable: ${probe.version || 'ok'}]` : `[db NOT reachable: ${probe.error || 'unknown'} — policy checks still verified]`);

  // A. read-only master switch wins even though other writable connections exist
  const a = parseText(await callTool('execute_sql', { connection: 'ro', sql: insertSql }));
  check('readOnly=true rejects INSERT', isPolicyErr(a), a.error);

  // B. writable connection but allowInsert=false -> rejected
  const b = parseText(await callTool('execute_sql', { connection: 'noins', sql: insertSql }));
  check('allowInsert=false rejects INSERT', isPolicyErr(b), b.error);

  // C. allowInsert=true -> passes policy, reaches DB (native error = table missing)
  if (!dbOk) {
    console.log('SKIP  allowInsert=true passes policy to DB  — DB unreachable');
  } else {
    const c = parseText(await callTool('execute_sql', { connection: 'ins', sql: insertSql }));
    check('allowInsert=true passes policy to DB', !!c.error && !isPolicyErr(c), c.error);
  }

  // D. read statements work on every connection regardless of write flags
  //    (requires a live DB; skipped when unreachable since that is not a policy issue)
  for (const conn of ['ro', 'noins', 'ins', 'all']) {
    if (!dbOk) {
      console.log(`SKIP  SELECT works on ${conn}  — DB unreachable`);
      continue;
    }
    const r = parseText(await callTool('execute_sql', { connection: conn, sql: 'SELECT 1 AS N' }));
    check(`SELECT works on ${conn}`, !r.error && Array.isArray(r.rows) && r.rows.length === 1, r.error || JSON.stringify(r.rows));
  }

  // E. DDL is gated by its own flag
  const d1 = parseText(await callTool('execute_sql', { connection: 'ins', sql: dropSql }));
  check('allowDdl=false rejects DROP', isPolicyErr(d1), d1.error);
  if (!dbOk) {
    console.log('SKIP  allowDdl=true passes DROP to DB  — DB unreachable');
  } else {
    const d2 = parseText(await callTool('execute_sql', { connection: 'all', sql: dropSql }));
    check('allowDdl=true passes DROP to DB', !!d2.error && !isPolicyErr(d2), d2.error);
  }

  // F. forbidden verbs are rejected even on the fully-writable connection
  const f = parseText(await callTool('execute_sql', { connection: 'all', sql: 'GRANT SELECT ON x TO y' }));
  check('forbidden verb rejected on all-allowed conn', isPolicyErr(f), f.error);

  console.log(`\n${passed}/${total} permission checks passed (${type}).`);
} catch (e) {
  console.error('Permission test crashed:', e);
  process.exitCode = 1;
} finally {
  proc.kill();
}
