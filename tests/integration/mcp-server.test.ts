import { Server as HttpServer } from 'http';
import { AddressInfo } from 'net';
import { mkdirSync, symlinkSync, writeFileSync } from 'fs';
import path from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ReportStore } from '../../src/core/report-store';
import { createHttpApp } from '../../src/mcp/http';
import { ToolContext } from '../../src/mcp/tools';
import { findings, loadDefaultRules, scanResult, tempDir } from '../helpers';

const TOKEN = 'test-token-0123456789abcdef0123456789';

type ToolResult = { content: Array<{ type: string; text: string }>; isError?: boolean };

describe('MCP server over Streamable HTTP', () => {
  let http: HttpServer;
  let baseUrl: string;
  let ctx: ToolContext;

  beforeAll(async () => {
    const reportsDir = tempDir('mcp-reports-');
    const store = new ReportStore(reportsDir);
    await store.save(scanResult({ scan_id: 'sast-opengrep-0001', finished_at: '2026-01-01T00:00:00Z', findings: findings({ high: 2, low: 3 }) }));
    await store.save(scanResult({ scan_id: 'sca-trivy-0001', scan_type: 'sca', tool: 'trivy', finished_at: '2026-01-02T00:00:00Z' }));

    // A planted symlink to a file outside the reports dir must not be readable through the API.
    const outside = tempDir('outside-');
    writeFileSync(path.join(outside, 'result.json'), JSON.stringify(scanResult({ scan_id: 'sast-leak-0001' })));
    symlinkSync(outside, path.join(reportsDir, 'sast-leak-0001'));
    mkdirSync(path.join(reportsDir, 'not-a-scan'));

    ctx = { store, rules: loadDefaultRules(), maxResponseBytes: 1024 * 1024 };
    const app = createHttpApp(ctx, { token: TOKEN });
    await new Promise<void>((resolve) => {
      http = app.listen(0, '127.0.0.1', () => resolve());
    });
    baseUrl = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise((resolve) => http.close(resolve));
  });

  async function connect(token = TOKEN): Promise<Client> {
    const client = new Client({ name: 'test-client', version: '1.0.0' });
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } }
    });
    await client.connect(transport);
    return client;
  }

  async function call(client: Client, name: string, args: Record<string, unknown>): Promise<unknown> {
    const result = (await client.callTool({ name, arguments: args })) as ToolResult;
    const first = result.content[0];
    if (!first) throw new Error('empty tool result');
    try {
      return JSON.parse(first.text);
    } catch {
      return first.text;
    }
  }

  it('serves an unauthenticated health check without internal details', async () => {
    const response = await fetch(`${baseUrl}/health`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: 'ok' });
    expect(response.headers.get('x-powered-by')).toBeNull();
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it.each([
    ['no token', {}],
    ['wrong token', { Authorization: 'Bearer wrong-token' }],
    ['wrong scheme', { Authorization: `Basic ${TOKEN}` }]
  ])('returns 401 with %s', async (_label, headers) => {
    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
    });
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toMatch(/^Bearer/);
  });

  it('rejects the MCP client when the token is wrong', async () => {
    await expect(connect('wrong-token')).rejects.toThrow();
  });

  it('refuses GET on the MCP endpoint (stateless, no server-initiated streams)', async () => {
    const response = await fetch(`${baseUrl}/mcp`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(response.status).toBe(405);
  });

  it('refuses short tokens at startup', () => {
    expect(() => createHttpApp(ctx, { token: 'short' })).toThrow(/at least 32/);
  });

  describe('with a valid token', () => {
    let client: Client;

    beforeAll(async () => {
      client = await connect();
    });

    afterAll(async () => {
      await client.close();
    });

    it('exposes only read-only tools', async () => {
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name).sort()).toEqual([
        'generate_security_report',
        'get_scan_result',
        'list_scans',
        'summarize_findings',
        'validate_security_policy'
      ]);
      expect(tools.some((tool) => tool.name.startsWith('run_'))).toBe(false);
    });

    it('lists stored scans newest first and ignores non-scan directories', async () => {
      const scans = (await call(client, 'list_scans', {})) as Array<{ scan_id: string }>;
      expect(scans.map((scan) => scan.scan_id)).toEqual(['sca-trivy-0001', 'sast-opengrep-0001']);
      const sast = (await call(client, 'list_scans', { scan_type: 'sast' })) as unknown[];
      expect(sast).toHaveLength(1);
    });

    it('reads a scan result with severity filtering and pagination', async () => {
      const result = (await call(client, 'get_scan_result', { scan_id: 'sast-opengrep-0001', min_severity: 'high' })) as {
        findings: Array<{ severity: string }>;
        pagination: { matching: number; total: number };
      };
      expect(result.findings.map((f) => f.severity)).toEqual(['high', 'high']);
      expect(result.pagination).toMatchObject({ matching: 2, total: 5 });

      const page = (await call(client, 'get_scan_result', { scan_id: 'sast-opengrep-0001', offset: 4, limit: 10 })) as {
        findings: unknown[];
      };
      expect(page.findings).toHaveLength(1);
    });

    it.each(['../../etc/passwd', '..%2F..%2Fetc', 'sast-leak-0001', '/etc/passwd', 'not-a-scan'])(
      'refuses to read %s',
      async (scanId) => {
        await expect(client.callTool({ name: 'get_scan_result', arguments: { scan_id: scanId } })).rejects.toThrow(
          /Invalid scan id|not found|Invalid arguments/
        );
      }
    );

    it('summarizes findings for triage with the policy decision', async () => {
      const digest = (await call(client, 'summarize_findings', { scan_ids: ['sast-opengrep-0001'] })) as {
        policy: { status: string };
        totals: { high: number; low: number };
        groups: Array<{ rule_id: string; count: number }>;
      };
      expect(digest.policy.status).toBe('FAIL');
      expect(digest.totals).toMatchObject({ high: 2, low: 3 });
      expect(digest.groups[0]).toMatchObject({ rule_id: 'rule-high', count: 2 });
    });

    it('validates the policy against stored results', async () => {
      const pass = (await call(client, 'validate_security_policy', { scan_ids: ['sca-trivy-0001'] })) as { status: string };
      expect(pass.status).toBe('PASS');
      const fail = (await call(client, 'validate_security_policy', { scan_ids: ['sast-opengrep-0001', 'sca-trivy-0001'] })) as {
        status: string;
        reasons: string[];
      };
      expect(fail.status).toBe('FAIL');
      expect(fail.reasons.join('\n')).toMatch(/high: 2/);
    });

    it('generates markdown, json and sarif reports', async () => {
      const markdown = (await call(client, 'generate_security_report', { scan_ids: ['sast-opengrep-0001'] })) as string;
      expect(markdown).toMatch(/^# Security Scan Report/);
      const json = (await call(client, 'generate_security_report', { scan_ids: ['sast-opengrep-0001'], format: 'json' })) as {
        policy: { status: string };
      };
      expect(json.policy.status).toBe('FAIL');
      const sarif = (await call(client, 'generate_security_report', { scan_ids: ['sast-opengrep-0001', 'sca-trivy-0001'], format: 'sarif' })) as {
        runs: unknown[];
      };
      expect(sarif.runs).toHaveLength(2);
    });

    it('rejects unknown tools, scan-triggering tools and unexpected arguments', async () => {
      await expect(client.callTool({ name: 'run_sast_scan', arguments: { target: '/' } })).rejects.toThrow(/Unknown tool/);
      await expect(
        client.callTool({ name: 'validate_security_policy', arguments: { scan_ids: ['sast-opengrep-0001'], policy_file: '/etc/passwd' } })
      ).rejects.toThrow(/not allowed/);
      await expect(client.callTool({ name: 'list_scans', arguments: { limit: 100000 } })).rejects.toThrow(/Invalid arguments/);
    });
  });
});
