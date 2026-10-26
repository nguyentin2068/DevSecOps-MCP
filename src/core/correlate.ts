import { createHash } from 'crypto';
import { Finding, FindingLocation, ScanResult, ScanType, Severity, severityRank } from './types';

/** One finding as it appears in one scan, kept intact so reports can point back to it. */
export interface FindingRef {
  scan_id: string;
  scan_type: ScanType;
  tool: string;
  /** Root the scan ran against (a directory for sast/sca); finding paths are relative to it. */
  target: string;
  finding: Finding;
}

export type CorrelationKind = 'dependency' | 'code' | 'endpoint' | 'other';

/** Findings from one or more tools that describe the same issue. */
export interface CorrelatedGroup {
  /** Stable across builds for the same issue: derived from the correlation key only. */
  id: string;
  kind: CorrelationKind;
  severity: Severity;
  title: string;
  tools: string[];
  location: FindingLocation;
  cwe: string[];
  cve: string[];
  /** The group's representative first (highest severity), then the others. */
  refs: FindingRef[];
}

function normalizedCwes(finding: Finding): string[] {
  const ids = (finding.cwe ?? []).map((cwe) => /CWE-(\d+)/i.exec(cwe)?.[1]).filter((id): id is string => Boolean(id));
  return Array.from(new Set(ids)).sort((a, b) => Number(a) - Number(b)).map((id) => `CWE-${id}`);
}

/** The vulnerability identifier two dependency scanners agree on: the lowest CVE if any, else the rule id. */
function vulnerabilityKey(finding: Finding): string {
  const cves = (finding.cve ?? []).map((cve) => cve.toUpperCase()).sort();
  return cves[0] ?? finding.rule_id.toUpperCase();
}

/**
 * The correlation key. Findings with the same key describe the same issue:
 * - dependency: same package and version, same vulnerability (OSV reports GHSA ids with CVE
 *   aliases, Trivy reports CVEs, so both land on the CVE);
 * - code: same file and line with the same CWEs (several rules, or SAST and Trivy secrets);
 * - endpoint: same method, URL (without query) and parameter, same CWEs or template.
 * Anything else is its own group.
 */
export function correlationKey(ref: FindingRef): { kind: CorrelationKind; key: string } {
  const { finding } = ref;
  const location = finding.location;
  const cwes = normalizedCwes(finding).join(',');

  if (location.package) {
    return { kind: 'dependency', key: `dep|${location.package.toLowerCase()}@${location.version ?? ''}|${vulnerabilityKey(finding)}` };
  }
  if (location.url) {
    let base = location.url;
    try {
      const url = new URL(location.url);
      base = `${url.origin}${url.pathname}`;
    } catch {
      // keep the raw value
    }
    const what = cwes || finding.rule_id;
    return { kind: 'endpoint', key: `url|${location.method ?? 'GET'}|${base}|${location.parameter ?? ''}|${what}` };
  }
  if (location.path && location.line) {
    // Without CWEs, two rules on one line may be unrelated: keep them apart by rule.
    const what = cwes || `${ref.tool}:${finding.rule_id}`;
    return { kind: 'code', key: `code|${location.path}|${location.line}|${what}` };
  }
  return { kind: 'other', key: `other|${ref.scan_id}|${finding.id}` };
}

export function groupId(key: string): string {
  return `corr-${createHash('sha256').update(key).digest('hex').slice(0, 12)}`;
}

/** Group the findings of a build's scans into correlated issues, most severe first. */
export function correlate(results: ScanResult[]): CorrelatedGroup[] {
  const groups = new Map<string, { kind: CorrelationKind; refs: FindingRef[] }>();
  for (const result of results) {
    if (result.status !== 'completed') continue;
    for (const finding of result.findings) {
      const ref: FindingRef = { scan_id: result.scan_id, scan_type: result.scan_type, tool: result.tool, target: result.target, finding };
      const { kind, key } = correlationKey(ref);
      const group = groups.get(key) ?? { kind, refs: [] };
      group.refs.push(ref);
      groups.set(key, group);
    }
  }

  const out: CorrelatedGroup[] = [];
  for (const [key, { kind, refs }] of groups) {
    refs.sort((a, b) => severityRank(b.finding.severity) - severityRank(a.finding.severity) || a.tool.localeCompare(b.tool));
    const lead = refs[0] as FindingRef;
    out.push({
      id: groupId(key),
      kind,
      severity: lead.finding.severity,
      title: lead.finding.title,
      tools: Array.from(new Set(refs.map((ref) => ref.tool))).sort(),
      location: lead.finding.location,
      cwe: Array.from(new Set(refs.flatMap((ref) => normalizedCwes(ref.finding)))).sort(),
      cve: Array.from(new Set(refs.flatMap((ref) => ref.finding.cve ?? []))).sort(),
      refs
    });
  }
  return out.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.refs.length - a.refs.length || a.id.localeCompare(b.id));
}
