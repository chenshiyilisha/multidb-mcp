#!/usr/bin/env node
/**
 * multidb-mcp entry point.
 *
 * Starts the MCP server over stdio so it can be launched by any MCP client
 * (and, once published to npm, via `npx multidb-mcp`).
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import server, { closeAll } from './server.js';

const transport = new StdioServerTransport();
await server.connect(transport);

/**
 * Graceful shutdown: release every connection pool before exiting. Without
 * this, long-lived pools can keep sockets / timers alive and delay process
 * termination (or leak on abrupt client disconnect).
 */
let closing = false;
async function shutdown(): Promise<void> {
  if (closing) return;
  closing = true;
  try {
    await closeAll();
  } finally {
    process.exit(0);
  }
}

process.on('SIGINT', () => { void shutdown(); });
process.on('SIGTERM', () => { void shutdown(); });
transport.onclose = () => { void shutdown(); };
