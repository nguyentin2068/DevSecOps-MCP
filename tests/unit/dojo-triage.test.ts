import { correlate } from '../../src/core/correlate';
import { DefectDojoClient, DojoFinding, ImportsRecord } from '../../src/core/defectdojo';
import { triageInDefectDojo } from '../../src/core/dojo-triage';
import { computeRuleStats, renderRuleStatsMarkdown } from '../../src/core/rule-stats';
import { TriageInput, TriageModel } from '../../src/core/triage';
import { Finding } from '../../src/core/types';
import { loadDefaultRules, scanResult } from '../helpers';

function code(id: string, line: number, cwe: string): Finding {
  return { id, rule_id: `sast-javascript-${String(line).padStart(4, '0')}`, title: `issue ${id}`, severity: 'high', location: { path: 'app.js', line }, cwe: [cwe] };
}

/** DefectDojo stand-in: findings by test, records PATCH and note calls. */
function fakeDojo(findings: DojoFinding[]) {
  const writes: Array<{ method: string; path: string; body: unknown }> = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    const { pathname, searchParams } = new URL(url);
    const method = init.method ?? 'GET';
    const json = (data: unknown) => new Response(JSON.stringify(data), { status: 200 });
    if (method === 'GET' && pathname === '/api/v2/findings/') {
      return json({ results: findings.filter((f) => String(f.test) === searchParams.get('test')), next: null });
    }
    writes.push({ method, path: pathname, body: JSON.parse(String(init.body)) });
    return json({});
  }) as unknown as typeof fetch;
  return { client: new DefectDojoClient({ baseUrl: 'https://dojo.example.com', apiKey: 'k', fetchImpl }), writes };
}

describe('triageInDefectDojo', () => {
  // Four code issues: one a person marked false positive, one closed, one AI-triaged last
  // build, one new and reported by two rules (a correlated group).
  const sast = scanResult({
    scan_id: 'sast-b2',
    findings: [code('fp', 1, 'CWE-79'), code('closed', 2, 'CWE-79'), code('old', 3, 'CWE-79'), code('new-a', 4, 'CWE-89'), { ...code('new-b', 4, 'CWE-89'), rule_id: 'sast-javascript-0099' }]
  });
  const dojo: DojoFinding[] = [
    { id: 1, test: 7, unique_id_from_tool: 'fp', active: false, false_p: true, tags: ['opengrep'] },
    { id: 2, test: 7, unique_id_from_tool: 'closed', active: false, is_mitigated: true, tags: [] },
    { id: 3, test: 7, unique_id_from_tool: 'old', active: true, tags: ['ai-needs-review', 'ai-priority-p3'] },
    { id: 4, test: 7, unique_id_from_tool: 'new-a', active: true, tags: ['team-web', 'corr-x'] },
    { id: 5, test: 7, unique_id_from_tool: 'new-b', active: true, tags: ['corr-x', 'corr-duplicate'] }
  ];
  const imports: ImportsRecord = {
    schema_version: 1,
    product: 'shop',
    engagement: 'CI/CD main',
    imports: [{ scan_id: 'sast-b2', test_title: 'opengrep (sast)', status: 'imported', test_id: 7, findings: 5, tags_updated: 0 }]
  };
  const config = loadDefaultRules().triage;

  function model() {
    const seen: TriageInput[][] = [];
    const fn: TriageModel = async (batch) => {
      seen.push(batch);
      return batch.map((input) => ({ group_id: input.group_id, verdict: 'true_positive', confidence: 'high', priority: 'P1', rationale: 'User input reaches the query.', recommendation: 'Use parameters.' }));
    };
    return { fn, seen };
  }

  it('sends only undecided, untriaged groups to the model and writes verdicts back to their open findings', async () => {
    const { client, writes } = fakeDojo(dojo);
    const { fn, seen } = model();
    const { report, findings_tagged, notes_added } = await triageInDefectDojo(client, correlate([sast]), imports, { model: fn, modelName: 'claude-opus-5-5', config, scanIds: ['sast-b2'] });

    expect(seen.flat().map((input) => input.findings.length)).toEqual([2]);
    const status = (findingId: string) => report.groups.find((group) => group.findings.some((f) => f.finding_id === findingId))!.triage_status;
    expect([status('fp'), status('closed'), status('old'), status('new-a')]).toEqual(['human_decided', 'human_decided', 'previously_triaged', 'triaged']);

    // Findings 4 and 5 get the ai-* tags (people's and corr-* tags kept) and one note each; 1-3 untouched.
    expect(writes.filter((w) => w.method === 'PATCH')).toEqual([
      { method: 'PATCH', path: '/api/v2/findings/4/', body: { tags: ['team-web', 'corr-x', 'ai-true-positive', 'ai-confidence-high', 'ai-priority-p1'] } },
      { method: 'PATCH', path: '/api/v2/findings/5/', body: { tags: ['corr-x', 'corr-duplicate', 'ai-true-positive', 'ai-confidence-high', 'ai-priority-p1'] } }
    ]);
    const notes = writes.filter((w) => w.path.endsWith('/notes/'));
    expect(notes.map((w) => w.path)).toEqual(['/api/v2/findings/4/notes/', '/api/v2/findings/5/notes/']);
    expect((notes[0]!.body as { entry: string }).entry).toMatch(/^AI triage \(advisory, claude-opus-5-5\): true_positive[\s\S]*Correlated group corr-/);
    expect([findings_tagged, notes_added]).toEqual([2, 2]);
    // Status fields are never written.
    for (const write of writes) expect(Object.keys(write.body as object).sort()).not.toContain('false_p');
  });

  it('triages previously triaged findings again with retriage, and never decided ones', async () => {
    const { client } = fakeDojo(dojo);
    const { fn, seen } = model();
    await triageInDefectDojo(client, correlate([sast]), imports, { model: fn, modelName: 'm', config, scanIds: ['sast-b2'], retriage: true });
    expect(seen.flat()).toHaveLength(2);
  });
});

describe('computeRuleStats', () => {
  const finding = (id: number, rule: string, extra: Partial<DojoFinding> = {}): DojoFinding => ({ id, test: 1, vuln_id_from_tool: rule, active: true, tags: ['opengrep', 'sast'], ...extra });

  it('ranks noisy rules first using decisions made by people, with AI tags as a hint', () => {
    const findings = [
      // Noisy: 4 of 5 reviewed are false positives.
      ...[1, 2, 3, 4].map((i) => finding(i, 'sast-javascript-0126', { false_p: true, active: false })),
      finding(5, 'sast-javascript-0126', { verified: true }),
      // Reliable: 5 verified.
      ...[6, 7, 8, 9, 10].map((i) => finding(i, 'sast-python-0002', { verified: true })),
      // Redundant: every finding is a correlated duplicate.
      ...[11, 12, 13].map((i) => finding(i, 'sast-python-0042', { tags: ['opengrep', 'corr-duplicate'] })),
      // Unreviewed, but the AI flags most as false positives.
      ...[14, 15, 16].map((i) => finding(i, 'sast-go-0010', { tags: ['opengrep', 'ai-false-positive'] })),
      finding(17, 'CVE-2021-23337', { tags: ['trivy', 'sca'] })
    ];
    const stats = computeRuleStats(findings, { minReviewed: 5, originals: { 'sast-javascript-0126': 'javascript.lang.security.audit.detect-non-literal-fs-filename' } });
    expect(stats.map((s) => [s.rule, s.suggestion])).toEqual([
      ['sast-javascript-0126', 'tune-or-disable'],
      ['sast-python-0042', 'redundant'],
      ['sast-go-0010', 'review-ai-suspects-fp'],
      ['CVE-2021-23337', 'not-enough-data'],
      ['sast-python-0002', 'reliable']
    ]);
    expect(stats[0]).toMatchObject({ tool: 'opengrep', total: 5, false_positive: 4, confirmed: 1, fp_rate: 0.8, original: 'javascript.lang.security.audit.detect-non-literal-fs-filename' });
    expect(stats.find((s) => s.rule === 'CVE-2021-23337')!.tool).toBe('trivy');

    const md = renderRuleStatsMarkdown('shop', stats, 5);
    expect(md).toMatch(/\| sast-javascript-0126 \| javascript\.lang\.security\.audit\.detect-non-literal-fs-filename \| opengrep \| 5 \| 1 \| 4 \| 1 \| 80% \|/);
  });
});
