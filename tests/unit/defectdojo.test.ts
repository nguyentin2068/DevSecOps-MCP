import { correlate } from '../../src/core/correlate';
import { DefectDojoClient, importToDefectDojo, toGenericReport } from '../../src/core/defectdojo';
import { runTriage } from '../../src/core/triage';
import { Finding } from '../../src/core/types';
import { loadDefaultRules, scanResult } from '../helpers';

const osvFinding: Finding = {
  id: 'package-lock.json:lodash@4.17.4:GHSA-35jh-r3h4-6jhm',
  rule_id: 'GHSA-35jh-r3h4-6jhm',
  title: 'Command injection in lodash',
  severity: 'high',
  description: 'lodash template is vulnerable',
  location: { path: 'package-lock.json', package: 'lodash', version: '4.17.4' },
  fix: 'Upgrade lodash to 4.17.21',
  cve: ['CVE-2021-23337'],
  cwe: ['CWE-94'],
  references: ['https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm']
};
const trivyFinding: Finding = { ...osvFinding, id: 'package-lock.json:lodash@4.17.4:CVE-2021-23337', rule_id: 'CVE-2021-23337' };
const sastFinding: Finding = {
  id: 'sast-javascript-0095:app.js:4',
  rule_id: 'sast-javascript-0095',
  original_rule_id: 'opt.opengrep-rules.javascript.express.security.injection.tainted-sql-string',
  title: 'Tainted SQL string',
  severity: 'high',
  location: { path: 'app.js', line: 4 },
  cwe: ['CWE-89: SQL Injection']
};

const osv = scanResult({ scan_id: 'sca-osv-b1', scan_type: 'sca', tool: 'osv-scanner', findings: [osvFinding] });
const trivy = scanResult({ scan_id: 'sca-trivy-b1', scan_type: 'sca', tool: 'trivy', findings: [trivyFinding] });
const sast = scanResult({ scan_id: 'sast-opengrep-b1', findings: [sastFinding] });
const failed = scanResult({ scan_id: 'dast-nuclei-b1', scan_type: 'dast', tool: 'nuclei', status: 'failed', error: 'timeout' });

async function triageReport() {
  return runTriage(correlate([osv, trivy, sast]), {
    model: async (batch) =>
      batch.map((input) => ({ group_id: input.group_id, verdict: 'true_positive', confidence: 'high', priority: 'P1', rationale: 'Reachable.', recommendation: 'Upgrade.' })),
    modelName: 'claude-opus-5-5',
    config: loadDefaultRules().triage,
    scanIds: ['sca-osv-b1', 'sca-trivy-b1', 'sast-opengrep-b1']
  });
}

describe('toGenericReport', () => {
  it('uses only allowed keys, keeps hashed fields free of AI output, and tags correlation', async () => {
    const report = await triageReport();
    const [primary] = toGenericReport(osv, report).findings;
    const [duplicate] = toGenericReport(trivy, report).findings;
    const [code] = toGenericReport(sast, report).findings;

    const allowed = new Set(['title', 'severity', 'description', 'mitigation', 'references', 'cwe', 'vulnerability_ids', 'file_path', 'line', 'component_name', 'component_version', 'unique_id_from_tool', 'vuln_id_from_tool', 'static_finding', 'dynamic_finding', 'endpoints', 'param', 'severity_justification', 'tags']);
    for (const finding of [primary!, duplicate!, code!]) for (const key of Object.keys(finding)) expect(allowed.has(key)).toBe(true);

    expect(primary).toMatchObject({ severity: 'High', cwe: 94, vulnerability_ids: ['CVE-2021-23337'], component_name: 'lodash', component_version: '4.17.4', unique_id_from_tool: osvFinding.id });
    // description/title/line/file_path/cwe feed DefectDojo's hash: no AI text in them.
    expect(primary!.description).not.toMatch(/AI|Reachable/);
    expect(primary!.severity_justification).toMatch(/^AI triage \(advisory, claude-opus-5-5\): true_positive/);
    expect(primary!.tags).toEqual(expect.arrayContaining(['osv-scanner', 'sca', 'ai-true-positive', 'ai-confidence-high', 'ai-priority-p1']));

    const corr = primary!.tags.find((tag) => /^corr-[0-9a-f]{12}$/.test(tag));
    expect(duplicate!.tags).toContain(corr);
    // OSV sorts before Trivy in the group, so Trivy's copy is the duplicate.
    expect(duplicate!.tags).toContain('corr-duplicate');
    expect(primary!.tags).not.toContain('corr-duplicate');
    expect(code).toMatchObject({ cwe: 89, line: 4, file_path: 'app.js', vuln_id_from_tool: 'sast-javascript-0095' });
    expect(code!.description).toContain('Rule: opt.opengrep-rules.javascript.express.security.injection.tainted-sql-string');
  });
});

describe('importToDefectDojo', () => {
  function fakeDojo(existing: Array<{ id: number; unique_id_from_tool: string; tags: string[] }>) {
    const calls: Array<{ method: string; url: string; headers: Record<string, string>; body?: unknown }> = [];
    let nextTest = 10;
    const fetchImpl = (async (url: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      calls.push({ method, url, headers: init.headers as Record<string, string>, body: init.body });
      const json = (data: unknown) => new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } });
      if (url.endsWith('/api/v2/reimport-scan/')) return json({ test_id: nextTest++ });
      if (url.includes('offset=200')) return json({ results: existing.slice(1), next: null });
      if (url.includes('/api/v2/findings/?test=10&limit=200')) return json({ results: existing.slice(0, 1), next: 'https://dojo.example.com/dojo/api/v2/findings/?test=10&limit=200&offset=200' });
      if (url.includes('/api/v2/findings/?test=')) return json({ results: [], next: null });
      if (method === 'PATCH') return json({});
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;
    return { client: new DefectDojoClient({ baseUrl: 'https://dojo.example.com/dojo/', apiKey: 'dd-secret', fetchImpl }), calls };
  }

  const context = { productName: 'shop', productTypeName: 'DevSecOps', engagementName: 'CI/CD main', branch: 'main', commit: 'abc123', buildId: '42' };

  it('reimports each completed scan as its own test, skips failed scans, and syncs tags', async () => {
    const report = await triageReport();
    const { client, calls } = fakeDojo([
      { id: 1, unique_id_from_tool: osvFinding.id, tags: ['team-payments', 'ai-needs-review'] },
      { id: 2, unique_id_from_tool: 'gone', tags: ['ai-false-positive'] }
    ]);
    const outcomes = await importToDefectDojo(client, [osv, failed, sast], context, report);

    expect(outcomes.map((o) => [o.test_title, o.status])).toEqual([
      ['osv-scanner (sca)', 'imported'],
      ['nuclei (dast)', 'skipped'],
      ['opengrep (sast)', 'imported']
    ]);
    const imports = calls.filter((call) => call.url.endsWith('/reimport-scan/'));
    expect(imports).toHaveLength(2);
    expect(imports[0]!.url).toBe('https://dojo.example.com/dojo/api/v2/reimport-scan/');
    expect(imports[0]!.headers['Authorization']).toBe('Token dd-secret');
    const form = imports[0]!.body as FormData;
    expect(Object.fromEntries(['scan_type', 'product_name', 'engagement_name', 'test_title', 'auto_create_context', 'close_old_findings', 'branch_tag', 'commit_hash', 'build_id'].map((k) => [k, form.get(k)]))).toEqual({
      scan_type: 'Generic Findings Import',
      product_name: 'shop',
      engagement_name: 'CI/CD main',
      test_title: 'osv-scanner (sca)',
      auto_create_context: 'true',
      close_old_findings: 'true',
      branch_tag: 'main',
      commit_hash: 'abc123',
      build_id: '42'
    });
    const uploaded = JSON.parse(await (form.get('file') as Blob).text());
    expect(uploaded.findings).toHaveLength(1);

    // Pagination follows the absolute next link under the /dojo prefix.
    expect(calls.some((call) => call.url === 'https://dojo.example.com/dojo/api/v2/findings/?test=10&limit=200&offset=200')).toBe(true);
    // Managed tags are replaced, people's tags are kept; a finding with no wanted tags loses only ai-*/corr-*.
    const patches = calls.filter((call) => call.method === 'PATCH');
    expect(patches.map((call) => [call.url.replace(/.*findings\//, ''), JSON.parse(String(call.body)).tags])).toEqual([
      ['1/', ['team-payments', expect.stringMatching(/^corr-[0-9a-f]{12}$/), 'ai-true-positive', 'ai-confidence-high', 'ai-priority-p1']],
      ['2/', []]
    ]);
    expect(outcomes[0]!.tags_updated).toBe(2);
  });

  it('refuses URLs with credentials, pagination to another host, and reports HTTP errors without the token', async () => {
    expect(() => new DefectDojoClient({ baseUrl: 'https://user:pw@dojo.example.com', apiKey: 'k' })).toThrow(/credentials/);

    const hostile = new DefectDojoClient({
      baseUrl: 'https://dojo.example.com',
      apiKey: 'dd-secret',
      fetchImpl: (async () => new Response(JSON.stringify({ results: [], next: 'https://evil.example.net/steal' }), { status: 200 })) as unknown as typeof fetch
    });
    await expect(hostile.findingsOfTest(1)).rejects.toThrow(/another host/);

    const looping = new DefectDojoClient({
      baseUrl: 'https://dojo.example.com',
      apiKey: 'k',
      fetchImpl: (async () => new Response(JSON.stringify({ results: [], next: 'https://dojo.example.com/api/v2/findings/?test=1&limit=200' }), { status: 200 })) as unknown as typeof fetch
    });
    await expect(looping.findingsOfTest(1)).rejects.toThrow(/pagination/);

    const failing = new DefectDojoClient({
      baseUrl: 'https://dojo.example.com',
      apiKey: 'dd-secret',
      fetchImpl: (async () => new Response('{"product_name":["Product not found"]}', { status: 400 })) as unknown as typeof fetch
    });
    const error = await failing.reimport({ findings: [] }, 't', context, '2026-01-01').catch((e: Error) => e);
    expect(String(error)).toMatch(/HTTP 400 .*Product not found/);
    expect(String(error)).not.toContain('dd-secret');
  });
});
