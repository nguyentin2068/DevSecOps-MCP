import { createHash, timingSafeEqual } from 'crypto';
import { Server as HttpServer } from 'http';
import express, { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { envSecret } from '../core/config';
import { errorMessage, logger } from '../core/logger';
import { createMcpServer } from './mcp';
import { ToolContext } from './tools';

export const MIN_TOKEN_LENGTH = 32;

export interface HttpOptions {
  token: string;
  /** Host header values accepted by the MCP endpoint (DNS-rebinding protection); empty = any. */
  allowedHosts?: string[];
}

function digest(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

/** Bearer-token check in constant time (hashing first equalizes the lengths). */
export function bearerAuth(token: string) {
  const expected = digest(token);
  return (req: Request, res: Response, next: NextFunction) => {
    const header = req.headers.authorization ?? '';
    const match = /^Bearer\s+(\S+)$/i.exec(header);
    if (!match?.[1] || !timingSafeEqual(digest(match[1]), expected)) {
      logger.warn('Rejected MCP request without a valid bearer token', { ip: req.ip });
      res.setHeader('WWW-Authenticate', 'Bearer realm="devsecops-mcp"');
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
    next();
  };
}

/**
 * Express app exposing:
 *   GET  /health  unauthenticated liveness probe (no internal details)
 *   POST /mcp     MCP Streamable HTTP endpoint (stateless, JSON responses), bearer token required
 */
export function createHttpApp(ctx: ToolContext, options: HttpOptions): express.Express {
  if (options.token.length < MIN_TOKEN_LENGTH) {
    throw new Error(`MCP auth token must be at least ${MIN_TOKEN_LENGTH} characters`);
  }

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.use(helmet());

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  const auth = bearerAuth(options.token);

  app.post('/mcp', auth, express.json({ limit: '256kb' }), async (req, res) => {
    // Stateless mode: a fresh server/transport pair per request, so no session state is shared.
    const server = createMcpServer(ctx);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
      ...(options.allowedHosts?.length ? { enableDnsRebindingProtection: true, allowedHosts: options.allowedHosts } : {})
    });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.error('MCP request failed', { error: errorMessage(error) });
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null });
      }
    }
  });

  // No server-initiated streams or sessions in stateless mode.
  app.all('/mcp', auth, (_req, res) => {
    res.setHeader('Allow', 'POST');
    res.status(405).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null });
  });

  app.use((_req, res) => {
    res.status(404).json({ error: 'not found' });
  });

  return app;
}

export function startHttp(ctx: ToolContext, env: NodeJS.ProcessEnv = process.env): Promise<HttpServer> {
  const token = envSecret('MCP_AUTH_TOKEN', env);
  if (!token) {
    throw new Error('MCP_AUTH_TOKEN (or MCP_AUTH_TOKEN_FILE) is required for the HTTP transport');
  }
  const allowedHosts = (env['MCP_ALLOWED_HOSTS'] ?? '').split(',').map((host) => host.trim()).filter(Boolean);
  const app = createHttpApp(ctx, { token, allowedHosts });
  const host = env['MCP_HOST'] || '127.0.0.1';
  const port = Number(env['MCP_PORT'] || 3000);

  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => {
      logger.info('DevSecOps MCP server listening', { transport: 'http', host, port, reports_dir: ctx.store.baseDir });
      resolve(server);
    });
    server.on('error', reject);
  });
}
