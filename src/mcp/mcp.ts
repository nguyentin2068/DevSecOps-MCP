import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from '@modelcontextprotocol/sdk/types.js';
import { loadRules } from '../core/config';
import { ValidationError } from '../core/guards';
import { errorMessage, logger } from '../core/logger';
import { ReportStore } from '../core/report-store';
import { callTool, ToolContext, TOOL_DEFINITIONS } from './tools';

export const SERVER_INFO = { name: 'devsecops-mcp-server', version: '2.0.0' };

export function createToolContext(env: NodeJS.ProcessEnv = process.env): ToolContext {
  return {
    store: ReportStore.fromEnv(env),
    rules: loadRules(env['SECURITY_RULES_PATH'] || undefined),
    maxResponseBytes: Number(env['MCP_MAX_RESPONSE_BYTES'] || 1024 * 1024)
  };
}

/** Build an MCP server exposing the read-only tools over the given context. */
export function createMcpServer(ctx: ToolContext): Server {
  const server = new Server(SERVER_INFO, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOL_DEFINITIONS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      return await callTool(name, args, ctx);
    } catch (error) {
      if (error instanceof ValidationError) {
        throw new McpError(ErrorCode.InvalidParams, error.message);
      }
      // Internal details (paths, stack traces) stay in the server log.
      logger.error('Tool execution failed', { tool: name, error: errorMessage(error) });
      throw new McpError(ErrorCode.InternalError, `Tool ${name} failed`);
    }
  });

  return server;
}

export async function startStdio(ctx: ToolContext): Promise<void> {
  const server = createMcpServer(ctx);
  await server.connect(new StdioServerTransport());
  logger.info('DevSecOps MCP server ready on stdio', { reports_dir: ctx.store.baseDir });
}
