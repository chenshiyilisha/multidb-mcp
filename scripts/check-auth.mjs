#!/usr/bin/env node
/**
 * Pre-publish npm auth check.
 *
 * npm 11 hides a missing / expired / revoked publish credential behind a
 * misleading `E404 - PUT ... could not be found or you do not have permission`.
 * Web-login session tokens are short-lived and npm auto-revokes stale tokens,
 * so a publish attempted a few days after the last one can fail with that
 * phantom 404 even though the package name, version and registry are correct.
 *
 * `npm whoami` is the only command that reports the real state (E401).
 * Run `npm run check:auth` before every publish to turn that opaque failure
 * into an actionable instruction.
 */
import { execFileSync } from 'node:child_process';

let user = '';
try {
  user = execFileSync('npm', ['whoami', '--loglevel=silent'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: process.platform === 'win32',
  }).trim();
} catch {
  // Fall through to the actionable message below.
}

if (!user) {
  console.error('[check:auth] FAILED: npm auth token is missing, expired or revoked (npm whoami -> E401).');
  console.error('');
  console.error('  Fix, in YOUR OWN terminal (2FA requires a human):');
  console.error('    npm login      # ENTER -> browser -> security key / passkey');
  console.error('    npm publish');
  console.error('');
  console.error('  Note: an expired token makes `npm publish` fail with a misleading');
  console.error('  E404 on PUT, NOT 401. Do not debug the package name/version in that case.');
  process.exit(1);
}

console.log(`[check:auth] OK: logged in as ${user}`);
