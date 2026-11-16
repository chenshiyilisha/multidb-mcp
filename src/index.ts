#!/usr/bin/env node
/**
 * multidb-mcp entry point.
 *
 * Starts the MCP server over stdio so it can be launched by any MCP client
 * (and, once published to npm, via `npx multidb-mcp`).
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import server from './server.js';

const transport = new StdioServerTransport();
await server.connect(transport);
