/**
 * End-to-end test for the MCP Resources + Prompts primitives.
 *
 * Verifies, over the real MCP stdio protocol:
 *   - resources/list exposes connections://catalog and schema:// templates
 *   - resources/read of connections://catalog returns sanitised connections
 *     (never passwords) and matches the list_connections tool
 *   - resources/templates/list exposes both schema:// templates
 *   - resources/read of a schema:// resource fails gracefully & structurally
 *     when the DB is unreachable (no crash, no leaked credentials)
 *   - prompts/list exposes query_guide / write_guide
 *   - prompts/get returns a usable message with argument substitution
 *
 * No real database required. An unreachable host is used deliberately to
 * exercise the schema resource's error path.
 *
 * Usage:
 *   node tests/primitives.mjs
 */

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.join(__dirname, '..', 'build', 'index.js');

const secret = 'S3cr3t_Password_NoLeak';
const env = {
  ...process.env,
  MULTIDB_DB_TYPE: 'mysql',
  MULTIDB_HOST: '127.0.0.1',
  MULTIDB_PORT: '1', // unreachable: schema resource error path
  MULTIDB_USER: 'probe_user',
  MULTIDB_PASSWORD: secret,
  MULTIDB_SCHEMA: 'probedb',
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
let stderrBuf = '';
proc.stderr.on('data', (b) => { stderrBuf += b.toString(); });

function parseResourceText(msg) {
  const txt = msg.result?.contents?.[0]?.text ?? '';
  try { return JSON.parse(txt); } catch { return { _raw: txt }; }
}

let passed = 0;
let total = 0;
function check(name, cond, detail = '') {
  total++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (cond) passed++; else process.exitCode = 1;
}

try {
  const init = await send('initialize', {
    protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'primitives-test', version: '1.0' },
  });
  sendNotification('notifications/initialized', {});
  const pkg = JSON.parse(readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  check('serverInfo.version tracks package.json',
    init.result?.serverInfo?.version === pkg.version,
    `${init.result?.serverInfo?.version} vs ${pkg.version}`);

  /* --------------------------- Resources --------------------------- */
  const list = await send('resources/list', {});
  const resources = list.result?.resources || [];
  const catalog = resources.find((r) => String(r.uri).includes('connections://catalog'));
  check('resources/list returns connections://catalog', !!catalog, JSON.stringify(resources.map((r) => r.uri)));

  const templates = await send('resources/templates/list', {});
  const tpls = templates.result?.resourceTemplates || [];
  const schemaTpls = tpls.filter((t) => String(t.uriTemplate).includes('schema://'));
  check('resources/templates/list exposes schema:// templates', schemaTpls.length >= 2,
    JSON.stringify(tpls.map((t) => t.uriTemplate)));

  const catRead = await send('resources/read', { uri: 'connections://catalog' });
  const cat = parseResourceText(catRead);
  check('catalog resource returns a list', Array.isArray(cat), JSON.stringify(cat).slice(0, 200));
  check('catalog resource includes configured connection', Array.isArray(cat) && cat[0]?.name === 'default',
    JSON.stringify(cat[0] || {}));
  check('catalog resource NEVER leaks password', !JSON.stringify(cat).includes(secret));
  check('catalog exposes fine-grained write flags',
    ['allowInsert', 'allowUpdate', 'allowDelete', 'allowDdl'].every((k) => typeof cat[0]?.[k] === 'boolean'),
    JSON.stringify(cat[0] || {}));

  // Structured tool output (MCP 2025-06-18): every tool declares outputSchema
  const toolDefs = (await send('tools/list', {})).result?.tools || [];
  check('all tools declare an object outputSchema',
    toolDefs.length === 5 && toolDefs.every((t) => t.outputSchema?.type === 'object'),
    JSON.stringify(toolDefs.map((t) => [t.name, t.outputSchema?.type])));

  // Tool/resource parity: same catalogue content
  const toolList = await send('tools/call', { name: 'list_connections', arguments: {} });
  const toolCatPayload = JSON.parse(toolList.result?.content?.[0]?.text || '[]');
  const toolCat = toolCatPayload?.connections ?? toolCatPayload;
  check('list_connections returns count + connections',
    toolCatPayload?.count === cat.length && Array.isArray(toolCatPayload?.connections),
    JSON.stringify(toolCatPayload).slice(0, 200));
  check('catalog resource matches list_connections tool', JSON.stringify(cat) === JSON.stringify(toolCat));
  check('list_connections structuredContent mirrors text payload',
    JSON.stringify(toolList.result?.structuredContent) === JSON.stringify(toolCatPayload),
    JSON.stringify(toolList.result?.structuredContent).slice(0, 200));

  // schema resource error path: unreachable DB -> structured error, no crash, no secret
  const schemaRead = await send('resources/read', { uri: 'schema://default' });
  const schemaPayload = parseResourceText(schemaRead);
  check('schema resource returns content even on DB failure', !!schemaRead.result?.contents?.[0]?.text,
    JSON.stringify(schemaRead.result || schemaRead.error).slice(0, 200));
  check('schema resource error is structured', schemaPayload?.ok === false && !!schemaPayload?.code,
    JSON.stringify(schemaPayload).slice(0, 200));
  check('schema resource error NEVER leaks password', !JSON.stringify(schemaPayload).includes(secret));

  // invalid identifier via explicit schema -> policy error, structured
  const badSchemaRead = await send('resources/read', { uri: 'schema://default/bad%20schema;' });
  const badPayload = parseResourceText(badSchemaRead);
  check('schema resource rejects invalid identifier', badPayload?.ok === false,
    JSON.stringify(badPayload).slice(0, 200));

  /* --------------------------- Prompts --------------------------- */
  const pList = await send('prompts/list', {});
  const prompts = pList.result?.prompts || [];
  const names = prompts.map((p) => p.name);
  check('prompts/list exposes query_guide', names.includes('query_guide'), JSON.stringify(names));
  check('prompts/list exposes write_guide', names.includes('write_guide'), JSON.stringify(names));

  const qg = await send('prompts/get', {
    name: 'query_guide',
    arguments: { goal: 'find orders from last week', connection: 'default' },
  });
  const qgText = qg.result?.messages?.[0]?.content?.text || '';
  check('query_guide substitutes goal argument', qgText.includes('find orders from last week'), qgText.slice(0, 120));
  check('query_guide mentions params/placeholders', /params|placeholder/i.test(qgText));
  check('query_guide references the target connection', qgText.includes('"default"'));

  const wg = await send('prompts/get', {
    name: 'write_guide',
    arguments: { operation: 'update status to shipped' },
  });
  const wgText = wg.result?.messages?.[0]?.content?.text || '';
  check('write_guide substitutes operation argument', wgText.includes('update status to shipped'), wgText.slice(0, 120));
  check('write_guide mentions permission flags', /allowInsert|allowUpdate|allowDelete|allowDdl/.test(wgText));
  check('write_guide warns about no transaction/rollback', /transaction|rollback/i.test(wgText));

  /* --------------------------- hygiene --------------------------- */
  check('server stderr never leaks password', !stderrBuf.includes(secret));
} finally {
  proc.stdin.end();
  proc.kill();
}

console.log(`\n${passed}/${total} checks passed`);
if (passed !== total) process.exitCode = 1;
