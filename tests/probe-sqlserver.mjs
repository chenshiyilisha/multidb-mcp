/**
 * Probe a SQL Server named instance's real TCP port via the SQL Browser
 * (UDP 1434). Sends a 0x03 request; the browser replies with 0x05 followed
 * by instance metadata containing the tcp port. Falls back to scanning a
 * few candidate TCP ports if the browser is unreachable.
 */

import dgram from 'node:dgram';
import net from 'node:net';

const HOST = '192.168.0.30';
const BROWSER_PORT = 1434;

function browserQuery(host, port) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    const req = Buffer.from([0x03]);
    const timer = setTimeout(() => {
      sock.close();
      resolve(null);
    }, 3000);
    sock.on('message', (msg) => {
      clearTimeout(timer);
      sock.close();
      // Response starts with 0x05; the rest is the instance info string.
      const info = msg.subarray(1).toString('utf8');
      resolve(info);
    });
    sock.on('error', () => {
      clearTimeout(timer);
      sock.close();
      resolve(null);
    });
    sock.send(req, 0, req.length, port, host);
  });
}

function scanTcp(host, ports) {
  return Promise.all(
    ports.map(
      (p) =>
        new Promise((resolve) => {
          const sock = net.connect({ host, port: p });
          const ok = () => {
            sock.destroy();
            resolve(p);
          };
          const fail = () => {
            sock.destroy();
            resolve(null);
          };
          sock.setTimeout(1500);
          sock.once('connect', ok);
          sock.once('timeout', fail);
          sock.once('error', fail);
        })
    )
  ).then((results) => results.filter(Boolean));
}

const info = await browserQuery(HOST, BROWSER_PORT);
if (info) {
  console.log('SQL Browser (UDP 1434) responded:');
  console.log(info);
  // Parse the tcp port out of the response (format: ...;tcp;<port>;...)
  const m = info.match(/tcp;(\d+)/i);
  if (m) {
    console.log(`\n>> Instance tcp port: ${m[1]}`);
  } else {
    console.log('\n>> Could not parse tcp port from response.');
  }
} else {
  console.log('SQL Browser (UDP 1434) not reachable. Scanning candidate TCP ports...');
  const candidates = [1433, 14330, 14331, 14332, 14333, 14334, 14335, 14340, 1435, 50000, 50001, 51000, 5236];
  const open = await scanTcp(HOST, candidates);
  console.log('Open TCP ports from candidates:', open.length ? open.join(', ') : 'none');
}
