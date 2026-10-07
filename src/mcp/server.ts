import { errorMessage, logger } from '../core/logger';
import { startHttp } from './http';
import { createToolContext, startStdio } from './mcp';

export { createMcpServer, createToolContext, SERVER_INFO } from './mcp';
export { createHttpApp } from './http';

/**
 * Entry point. MCP_TRANSPORT=http (or --http) serves Streamable HTTP with a bearer token;
 * the default stdio transport is for local MCP clients that spawn this process.
 */
async function main(): Promise<void> {
  const ctx = createToolContext();
  const transport = process.argv.includes('--http') ? 'http' : process.env['MCP_TRANSPORT'] || 'stdio';
  if (transport === 'http') {
    const server = await startHttp(ctx);
    const shutdown = () => server.close(() => process.exit(0));
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
    return;
  }
  if (transport !== 'stdio') throw new Error(`Unknown MCP_TRANSPORT: ${transport}`);
  await startStdio(ctx);
}

if (require.main === module) {
  main().catch((error) => {
    logger.error('Server failed to start', { error: errorMessage(error) });
    process.exit(1);
  });
}
