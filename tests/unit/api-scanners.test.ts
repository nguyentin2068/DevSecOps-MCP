import { collectSonarResults } from '../../src/core/scanners/sonarqube';
import { runZap } from '../../src/core/scanners/zap';

type Route = (url: URL, init?: RequestInit) => unknown;

/** Minimal fetch stand-in: routes by pathname and records every call. */
function fakeFetch(routes: Record<string, Route>) {
  const calls: Array<{ url: URL; headers: Record<string, string> }> = [];
  const impl = (async (input: string | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push({ url, headers: (init?.headers ?? {}) as Record<string, string> });
    const route = routes[url.pathname];
    if (!route) return new Response('not found', { status: 404 });
    return new Response(JSON.stringify(route(url, init)), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { impl, calls };
}

describe('runZap', () => {
  const baseOptions = {
    baseUrl: 'http://zap:8080',
    apiKey: 'zap-key',
    spiderMaxMinutes: 1,
    passiveWaitMinutes: 1,
    activeMaxMinutes: 1,
    maxAlerts: 100,
    pollIntervalMs: 1
  };

  function zapRoutes(alerts: unknown[]) {
    let spiderPolls = 0;
    return {
      '/JSON/core/view/version/': () => ({ version: '2.16.1' }),
      '/JSON/core/action/newSession/': () => ({ Result: 'OK' }),
      '/JSON/core/action/accessUrl/': () => ({ Result: 'OK' }),
      '/JSON/spider/action/scan/': () => ({ scan: '1' }),
      '/JSON/spider/view/status/': () => ({ status: ++spiderPolls >= 2 ? '100' : '50' }),
      '/JSON/ascan/action/scan/': () => ({ scan: '2' }),
      '/JSON/ascan/view/status/': () => ({ status: '100' }),
      '/JSON/pscan/view/recordsToScan/': () => ({ recordsToScan: '0' }),
      '/JSON/alert/view/alerts/': () => ({ alerts })
    };
  }

  it('runs a baseline scan: new session, spider, passive wait, alerts; key sent as a header', async () => {
    const { impl, calls } = fakeFetch(
      zapRoutes([{ pluginId: '10038', name: 'CSP Header Not Set', riskcode: '2', confidence: 'High', url: 'https://app.example/', method: 'GET' }])
    );
    const out = await runZap('https://app.example/', { ...baseOptions, mode: 'baseline', fetchImpl: impl });

    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({ rule_id: '10038', severity: 'medium' });
    expect(out.metadata).toMatchObject({ zap_version: '2.16.1', spider_completed: true, passive_scan_completed: true, mode: 'baseline' });

    const paths = calls.map((call) => call.url.pathname);
    expect(paths.indexOf('/JSON/core/action/newSession/')).toBeLessThan(paths.indexOf('/JSON/spider/action/scan/'));
    expect(paths).not.toContain('/JSON/ascan/action/scan/');
    for (const call of calls) {
      expect(call.headers['X-ZAP-API-Key']).toBe('zap-key');
      expect(call.url.searchParams.has('apikey')).toBe(false);
    }
    const spider = calls.find((call) => call.url.pathname === '/JSON/spider/action/scan/');
    expect(spider?.url.searchParams.get('subtreeOnly')).toBe('true');
  });

  it('adds the active scan in full mode', async () => {
    const { impl, calls } = fakeFetch(zapRoutes([]));
    const out = await runZap('https://app.example/', { ...baseOptions, mode: 'full', fetchImpl: impl });
    expect(out.findings).toEqual([]);
    expect(calls.map((call) => call.url.pathname)).toContain('/JSON/ascan/action/scan/');
    expect(out.metadata?.['active_scan_completed']).toBe(true);
  });

  it('requires an API key and surfaces API errors', async () => {
    await expect(runZap('https://app.example/', { ...baseOptions, apiKey: '', mode: 'baseline' })).rejects.toThrow(/ZAP_API_KEY/);
    const { impl } = fakeFetch({});
    await expect(runZap('https://app.example/', { ...baseOptions, mode: 'baseline', fetchImpl: impl })).rejects.toThrow(/HTTP 404/);
  });
});

describe('collectSonarResults', () => {
  const options = { hostUrl: 'http://sonar:9000', token: 'sqa_token', projectKey: 'my-app', timeoutSeconds: 5, pollIntervalMs: 1 };

  it('waits for the CE task, then reads the quality gate and vulnerability issues', async () => {
    let polls = 0;
    const { impl, calls } = fakeFetch({
      '/api/ce/task': () => ({ task: ++polls < 2 ? { status: 'IN_PROGRESS' } : { status: 'SUCCESS', analysisId: 'AN1' } }),
      '/api/qualitygates/project_status': () => ({ projectStatus: { status: 'ERROR', conditions: [{ metricKey: 'new_vulnerabilities' }] } }),
      '/api/issues/search': () => ({
        issues: [{ key: 'I1', rule: 'js:S2068', severity: 'BLOCKER', component: 'my-app:src/a.js', line: 3, message: 'Hard-coded password' }],
        paging: { total: 1 }
      })
    });

    const out = await collectSonarResults('TASK1', { ...options, fetchImpl: impl });
    expect(out.findings).toEqual([
      { id: 'I1', rule_id: 'js:S2068', title: 'Hard-coded password', severity: 'critical', location: { path: 'src/a.js', line: 3 } }
    ]);
    expect(out.metadata).toMatchObject({ analysis_id: 'AN1', quality_gate_status: 'ERROR' });

    const issues = calls.find((call) => call.url.pathname === '/api/issues/search');
    expect(issues?.url.searchParams.get('types')).toBe('VULNERABILITY');
    expect(issues?.url.searchParams.get('componentKeys')).toBe('my-app');
    expect(calls.every((call) => call.headers['Authorization'] === 'Bearer sqa_token')).toBe(true);
  });

  it('fails when the analysis fails', async () => {
    const { impl } = fakeFetch({ '/api/ce/task': () => ({ task: { status: 'FAILED', errorMessage: 'boom' } }) });
    await expect(collectSonarResults('TASK1', { ...options, fetchImpl: impl })).rejects.toThrow(/FAILED: boom/);
  });
});
