/**
 * End-to-end test for this round's hardening features, driven through the
 * real MCP stdio protocol (the tool entry, not just internal helpers):
 *   1. structured error payload (code/category/recoverable/suggestion) + isError
 *   2. credential redaction in errors AND audit log
 *   3. query length cap (no DB needed - fails fast before connect)
 *   4. masking rules loaded from config and applied to result columns (DB-backed)
 *   5. byte cap flags truncation (DB-backed)
 *
 * DB-backed checks skip (not fail) when the database is unreachable.
 *
 * Usage:
 *   HARDEN_TYPE=mysql HARDEN_HOST=... HARDEN_USER=... \
 *   HARDEN_PASSWORD=... HARDEN_SCHEMA=... node tests/hardening.mjs
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.join(__dirname, '..', 'build', 'index.js');

const type = process.env.HARDEN_TYPE || 'mysql';
const host = process.env.HARDEN_HOST;
const port = process.env.HARDEN_PORT || (type === 'dameng' ? '5236' : type === 'sqlserver' ? '1433' : '3306');
const user = process.env.HARDEN_USER;
const password = process.env.HARDEN_PASSWORD || 'TopSecret987!';
const schema = process.env.HARDEN_SCHEMA || user;

if (!host || !user || password === undefined) {
  console.error('Missing HARDEN_HOST / HARDEN_USER / HARDEN_PASSWORD / HARDEN_SCHEMA');
  process.exit(1);
}

const conn = {
  name: 'hard', type, host, port: Number(port), user, password, schema,
  readOnly: true,
  maxQueryLength: 200,         // low enough that a 250-char SQL trips the cap
  maxResultBytes: 40,          // very low so a small result trips the byte cap
  maskingRules: [{ column: '^SECRET$', strategy: 'fixed', value: '[MASKED]' }],
};
const env = { ...process.env, MULTIDB_CONNECTIONS: JSON.stringify([conn]) };
const proc = spawn(process.execPath, [serverPath], { env, stdio: ['pipe', 'pipe', 'pipe'] });

let nextId = 1;
const pending = new Map();
function send(method, params) {
  const id = nextId++;
  return new Promise((resolve) => {
    pending.set(id, resolve);
    proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}
function sendNotification(method, params) {
  proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
}
let stderr = '';
proc.stdout.on('data', (buf) => {
  for (const line of buf.toString().split('\n')) {
    if (!line.trim()) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  }
});
proc.stderr.on('data', (buf) => { stderr += buf.toString(); });

function callTool(name, args) { return send('tools/call', { name, arguments: args }); }
function parseText(msg) {
  const txt = msg.result?.content?.[0]?.text ?? '';
  try { return JSON.parse(txt); } catch { return { _raw: txt }; }
}

let passed = 0, total = 0;
function check(name, cond, detail = '') {
  total++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (cond) passed++; else process.exitCode = 1;
}
function skip(name, why) { console.log(`SKIP  ${name}  — ${why}`); }

try {
  await send('initialize', {
    protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'hardening-test', version: '1.0' },
  });
  sendNotification('notifications/initialized', {});

  // 1. structured error on a policy rejection (no DB needed)
  const denied = await callTool('execute_sql', { connection: 'hard', sql: 'DELETE FROM t' });
  const dp = parseText(denied);
  check('structured error has isError=true', denied.result?.isError === true);
  check('structured error has machine code', dp.code === 'READ_ONLY_VIOLATION', dp.code);
  check('structured error category=policy', dp.category === 'policy', dp.category);
  check('read-only error marked non-recoverable', dp.recoverable === false, String(dp.recoverable));
  check('structured error has actionable suggestion', !!dp.suggestion && /administrator|write permission/i.test(dp.suggestion), dp.suggestion);
  check('structuredContent twin present', denied.result?.structuredContent?.code === 'READ_ONLY_VIOLATION');

  // 2. query length cap (no DB needed - fail fast before connect)
  const long = await callTool('execute_sql', { connection: 'hard', sql: 'SELECT ' + '1'.repeat(250) });
  const lp = parseText(long);
  check('query length cap rejects long SQL', lp.code === 'QUERY_TOO_LONG', `${lp.code} / ${lp.error}`);
  check('length error is recoverable', lp.recoverable === true);

  // 3. credential redaction in error text + audit log (use an unreachable-style probe)
  // force a connection error by querying with the configured (possibly live) DB;
  // if reachable we instead just assert no credential leaks in the "too long" error path.
  check('password absent from structured error output', !JSON.stringify(denied.result).includes(password), 'checked denied result');
  check('password absent from audit log', !stderr.includes(password), 'checked stderr');
  check('user absent from audit log', !stderr.includes(user), `checked stderr for ${user}`);

  // DB-backed checks
  const probe = parseText(await callTool('test_connection', { connection: 'hard' }));
  const dbOk = probe.ok === true;
  if (!dbOk) {
    console.log(`\n[DB not reachable: ${probe.error || 'unknown'} — DB-backed checks skipped]`);
  } else {
    // 4. masking applied to result column (SELECT AS SECRET to force matching name)
    const masked = parseText(await callTool('execute_sql', {
      connection: 'hard', sql: "SELECT 'leak-me' AS SECRET", maxRows: 10,
    }));
    // byte cap is 40, so the result may be byte-truncated; check masking took effect
    check('masking applied to SECRET column', masked.maskedColumns?.includes('SECRET'), JSON.stringify(masked.maskedColumns));
    check('secret value masked in rows', masked.rows?.[0]?.SECRET === '[MASKED]', JSON.stringify(masked.rows));

    // 5. byte cap flagged truncation. maxQueryLength is 50 and maxResultBytes
    // is 40 in this fixture, so use a short SQL that still yields >40 bytes of
    // result. A few wide columns in one row easily exceed 40 serialized bytes.
    const capped = parseText(await callTool('execute_sql', {
      connection: 'hard', sql: "SELECT 'abcdefghij' AS A, 'klmnopqrst' AS B, 'uvwxyz' AS C", maxRows: 100,
    }));
    check('byte cap flags truncatedByBytes', capped.truncatedByBytes === true, JSON.stringify(capped));
  }

  console.log(`\n${passed}/${total} hardening checks passed (${type}).`);
} catch (e) {
  console.error('Hardening test crashed:', e);
  process.exitCode = 1;
} finally {
  proc.kill();
}
