import { ScanResult, Finding, Severity } from './types';
import { TriageReport } from './triage';

/**
 * DefectDojo's "Generic Findings Import" format (dojo/tools/generic/json_parser.py). Only
 * keys from the parser's allow-list are used; any other key makes the import fail.
 *
 * Reimport matches existing findings by hash_code, which for this parser is computed from
 * title, cwe, line, file_path and description. Those fields therefore carry scanner data only:
 * anything that changes between builds (AI verdicts, correlation) goes into tags and
 * severity_justification, or a reimport would close and recreate every finding.
 */
export interface GenericFinding {
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  description: string;
  mitigation?: string;
  references?: string;
  cwe?: number;
  vulnerability_ids?: string[];
  file_path?: string;
  line?: number;
  component_name?: string;
  component_version?: string;
  unique_id_from_tool: string;
  vuln_id_from_tool: string;
  static_finding: boolean;
  dynamic_finding: boolean;
  endpoints?: string[];
  param?: string;
  severity_justification?: string;
  tags: string[];
}

const SEVERITY: Record<Severity, GenericFinding['severity']> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info'
};

/** Tags this integration owns on a finding; everything else (added by people) is preserved. */
export const MANAGED_TAG = /^(ai-|corr-)/;

/** AI and correlation tags for each finding id, from the triage report. */
export function annotations(report: TriageReport | undefined): Map<string, { tags: string[]; justification?: string }> {
  const out = new Map<string, { tags: string[]; justification?: string }>();
  for (const group of report?.groups ?? []) {
    group.findings.forEach((finding, index) => {
      const tags: string[] = [];
      if (group.findings.length > 1) {
        tags.push(`corr-${group.id.replace(/^corr-/, '')}`);
        if (index > 0) tags.push('corr-duplicate');
      }
      let justification: string | undefined;
      if (group.triage) {
        const t = group.triage;
        tags.push(`ai-${t.verdict.replace(/_/g, '-')}`, `ai-confidence-${t.confidence}`, `ai-priority-${t.priority.toLowerCase()}`);
        justification = `AI triage (advisory, ${report?.model ?? 'model'}): ${t.verdict}, confidence ${t.confidence}, priority ${t.priority}. ${t.rationale}${
          t.recommendation ? ` Recommendation: ${t.recommendation}` : ''
        }`;
      }
      const entry: { tags: string[]; justification?: string } = { tags };
      if (justification) entry.justification = justification;
      out.set(`${finding.scan_id}:${finding.finding_id}`, entry);
    });
  }
  return out;
}

function cweNumber(finding: Finding): number | undefined {
  for (const cwe of finding.cwe ?? []) {
    const match = /CWE-(\d+)/i.exec(cwe);
    if (match) return Number(match[1]);
  }
  return undefined;
}

/** Stable, scanner-only description (part of DefectDojo's hash; see the module comment). */
function describe(result: ScanResult, finding: Finding): string {
  const lines = [finding.description || finding.title, '', `Rule: ${finding.original_rule_id ?? finding.rule_id}`, `Tool: ${result.tool} (${result.scan_type})`];
  if (finding.original_rule_id) lines.push(`Project rule ID: ${finding.rule_id}`);
  return lines.join('\n');
}

export function toGenericFinding(result: ScanResult, finding: Finding, extra?: { tags: string[]; justification?: string }): GenericFinding {
  const location = finding.location;
  const out: GenericFinding = {
    title: finding.title.slice(0, 500),
    severity: SEVERITY[finding.severity],
    description: describe(result, finding),
    unique_id_from_tool: finding.id,
    vuln_id_from_tool: finding.rule_id,
    static_finding: result.scan_type !== 'dast',
    dynamic_finding: result.scan_type === 'dast',
    tags: [result.tool, result.scan_type, ...(extra?.tags ?? [])]
  };
  if (finding.fix) out.mitigation = finding.fix;
  if (finding.references?.length) out.references = finding.references.join('\n');
  const cwe = cweNumber(finding);
  if (cwe !== undefined) out.cwe = cwe;
  if (finding.cve?.length) out.vulnerability_ids = finding.cve;
  if (location.path) out.file_path = location.path;
  if (location.line) out.line = location.line;
  if (location.package) {
    out.component_name = location.package;
    if (location.version) out.component_version = location.version;
  }
  if (location.url) out.endpoints = [location.url];
  if (location.parameter) out.param = location.parameter;
  if (extra?.justification) out.severity_justification = extra.justification;
  return out;
}

export function toGenericReport(result: ScanResult, report?: TriageReport): { name: string; type: string; findings: GenericFinding[] } {
  const notes = annotations(report);
  return {
    name: 'devsecops-scan',
    type: `${result.tool} (${result.scan_type})`,
    findings: result.findings.map((finding) => toGenericFinding(result, finding, notes.get(`${result.scan_id}:${finding.id}`)))
  };
}

export interface DefectDojoContext {
  productName: string;
  productTypeName: string;
  engagementName: string;
  branch?: string;
  commit?: string;
  buildId?: string;
  scmUri?: string;
}

export interface DefectDojoClientOptions {
  baseUrl: string;
  apiKey: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export interface ImportOutcome {
  scan_id: string;
  test_title: string;
  status: 'imported' | 'skipped';
  reason?: string;
  test_id?: number;
  findings: number;
  tags_updated: number;
}

export class DefectDojoClient {
  private readonly base: string;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: DefectDojoClientOptions) {
    const url = new URL(options.baseUrl);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('DEFECTDOJO_URL must be an http(s) URL');
    if (url.username || url.password) throw new Error('DEFECTDOJO_URL must not contain credentials; use DEFECTDOJO_API_KEY');
    this.base = url.toString().replace(/\/+$/, '');
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  /** `target` is a path under the base URL, or an absolute URL on the same origin (pagination links). */
  private async request(target: string, init: RequestInit): Promise<unknown> {
    let url: string;
    if (/^https?:\/\//.test(target)) {
      if (new URL(target).origin !== new URL(this.base).origin) throw new Error('DefectDojo returned a link to another host');
      url = target;
    } else {
      url = `${this.base}${target}`;
    }
    const pathname = new URL(url).pathname;
    const response = await this.fetchImpl(url, {
      ...init,
      headers: { Authorization: `Token ${this.options.apiKey}`, Accept: 'application/json', ...(init.headers ?? {}) },
      signal: AbortSignal.timeout(this.options.timeoutMs ?? 120_000)
    });
    const body = await response.text();
    if (!response.ok) {
      // The body is DefectDojo's validation message; never echo request headers.
      throw new Error(`DefectDojo ${init.method ?? 'GET'} ${pathname} failed: HTTP ${response.status} ${body.slice(0, 500)}`);
    }
    return body ? JSON.parse(body) : {};
  }

  async reimport(report: object, testTitle: string, context: DefectDojoContext, scanDate: string): Promise<number> {
    const form = new FormData();
    form.set('scan_type', 'Generic Findings Import');
    form.set('file', new Blob([JSON.stringify(report)], { type: 'application/json' }), 'findings.json');
    form.set('product_type_name', context.productTypeName);
    form.set('product_name', context.productName);
    form.set('engagement_name', context.engagementName);
    form.set('test_title', testTitle);
    form.set('auto_create_context', 'true');
    // Findings no longer reported by this tool are closed; mitigated ones that come back reopen.
    form.set('close_old_findings', 'true');
    form.set('active', 'true');
    form.set('verified', 'false');
    form.set('minimum_severity', 'Info');
    form.set('scan_date', scanDate);
    if (context.branch) form.set('branch_tag', context.branch);
    if (context.commit) form.set('commit_hash', context.commit);
    if (context.buildId) form.set('build_id', context.buildId);
    if (context.scmUri) form.set('source_code_management_uri', context.scmUri);
    const response = (await this.request('/api/v2/reimport-scan/', { method: 'POST', body: form })) as { test_id?: number; test?: number };
    const testId = response.test_id ?? response.test;
    if (typeof testId !== 'number') throw new Error('DefectDojo reimport response has no test_id');
    return testId;
  }

  async findingsOfTest(testId: number): Promise<Array<{ id: number; unique_id_from_tool?: string | null; tags?: string[] }>> {
    const out: Array<{ id: number; unique_id_from_tool?: string | null; tags?: string[] }> = [];
    let next: string | null = `/api/v2/findings/?test=${testId}&limit=200`;
    const seen = new Set<string>();
    while (next) {
      // A server that repeats a link, or never ends, must not loop the build.
      if (seen.has(next) || seen.size >= 500) throw new Error('DefectDojo pagination did not terminate');
      seen.add(next);
      const page = (await this.request(next, { method: 'GET' })) as { results?: typeof out; next?: string | null };
      out.push(...(page.results ?? []));
      next = page.next ?? null;
    }
    return out;
  }

  async setTags(findingId: number, tags: string[]): Promise<void> {
    await this.request(`/api/v2/findings/${findingId}/`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tags })
    });
  }
}

/**
 * Reimport every completed scan as its own DefectDojo test, then bring the AI and correlation
 * tags of findings that already existed up to date (reimport does not rewrite matched findings).
 * Failed scans are skipped: reimporting an empty result would close all of the tool's findings.
 */
export async function importToDefectDojo(
  client: DefectDojoClient,
  results: ScanResult[],
  context: DefectDojoContext,
  report?: TriageReport
): Promise<ImportOutcome[]> {
  const notes = annotations(report);
  const outcomes: ImportOutcome[] = [];
  for (const result of results) {
    const testTitle = `${result.tool} (${result.scan_type})`;
    if (result.status !== 'completed') {
      outcomes.push({ scan_id: result.scan_id, test_title: testTitle, status: 'skipped', reason: 'scan failed; existing findings left open', findings: 0, tags_updated: 0 });
      continue;
    }
    const generic = toGenericReport(result, report);
    const testId = await client.reimport(generic, testTitle, context, result.finished_at.slice(0, 10));

    let updated = 0;
    if (report) {
      for (const existing of await client.findingsOfTest(testId)) {
        const uid = existing.unique_id_from_tool;
        if (!uid) continue;
        const wanted = notes.get(`${result.scan_id}:${uid}`)?.tags ?? [];
        const current = existing.tags ?? [];
        const next = [...current.filter((tag) => !MANAGED_TAG.test(tag)), ...wanted];
        if (next.length === current.length && next.every((tag) => current.includes(tag))) continue;
        await client.setTags(existing.id, next);
        updated++;
      }
    }
    outcomes.push({ scan_id: result.scan_id, test_title: testTitle, status: 'imported', test_id: testId, findings: generic.findings.length, tags_updated: updated });
  }
  return outcomes;
}
