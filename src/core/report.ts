import { PolicyDecision } from './policy';
import { toSarif } from './sarif';
import { emptySummary, Finding, ScanResult, SEVERITIES, severityRank, Summary } from './types';

export type ReportFormat = 'json' | 'markdown' | 'sarif';

export interface FindingGroup {
  rule_id: string;
  title: string;
  severity: Finding['severity'];
  count: number;
  scan_ids: string[];
  examples: Array<Finding['location']>;
  fix?: string;
}

export interface FindingsDigest {
  scans: Array<Pick<ScanResult, 'scan_id' | 'scan_type' | 'tool' | 'status' | 'target' | 'finished_at'> & { summary: Summary; error?: string }>;
  totals: Summary;
  groups: FindingGroup[];
  truncated: boolean;
}

/**
 * Collapse findings into rule-level groups ordered by severity and frequency. This is the
 * compact view an LLM client uses for triage instead of thousands of raw findings.
 */
export function digestFindings(results: ScanResult[], maxGroups = 50, minSeverity: Finding['severity'] = 'info'): FindingsDigest {
  const totals = emptySummary();
  const groups = new Map<string, FindingGroup>();
  const minRank = severityRank(minSeverity);

  for (const result of results) {
    for (const severity of SEVERITIES) totals[severity] += result.summary?.[severity] ?? 0;
    totals.total += result.summary?.total ?? 0;
    for (const finding of result.findings ?? []) {
      if (severityRank(finding.severity) < minRank) continue;
      const key = `${result.tool}:${finding.rule_id}:${finding.severity}`;
      let group = groups.get(key);
      if (!group) {
        group = { rule_id: finding.rule_id, title: finding.title, severity: finding.severity, count: 0, scan_ids: [], examples: [] };
        if (finding.fix) group.fix = finding.fix;
        groups.set(key, group);
      }
      group.count++;
      if (!group.scan_ids.includes(result.scan_id)) group.scan_ids.push(result.scan_id);
      if (group.examples.length < 3) group.examples.push(finding.location);
    }
  }

  const ordered = Array.from(groups.values()).sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || b.count - a.count
  );

  return {
    scans: results.map((result) => ({
      scan_id: result.scan_id,
      scan_type: result.scan_type,
      tool: result.tool,
      status: result.status,
      target: result.target,
      finished_at: result.finished_at,
      summary: result.summary,
      ...(result.error ? { error: result.error } : {})
    })),
    totals,
    groups: ordered.slice(0, maxGroups),
    truncated: ordered.length > maxGroups
  };
}

function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').slice(0, 200);
}

function locationText(location: Finding['location']): string {
  if (location.package) return `${location.package}@${location.version ?? '?'}${location.path ? ` (${location.path})` : ''}`;
  if (location.url) return `${location.method ?? 'GET'} ${location.url}${location.parameter ? ` [${location.parameter}]` : ''}`;
  return `${location.path ?? '?'}${location.line ? `:${location.line}` : ''}`;
}

export function renderMarkdown(results: ScanResult[], decision: PolicyDecision, includeRemediation = true): string {
  const digest = digestFindings(results, 100);
  const lines: string[] = [];
  lines.push('# Security Scan Report', '');
  lines.push(`**Policy:** ${decision.status} (enforcement: ${decision.enforcement_level})  `);
  lines.push(`**Generated:** ${decision.evaluated_at}`, '');

  if (decision.reasons.length) {
    lines.push('## Policy violations', '');
    for (const reason of decision.reasons) lines.push(`- ${reason}`);
    lines.push('');
  }

  lines.push('## Scans', '');
  lines.push('| Scan | Type | Tool | Status | Critical | High | Medium | Low | Info |');
  lines.push('|---|---|---|---|---|---|---|---|---|');
  for (const scan of digest.scans) {
    const s = scan.summary ?? emptySummary();
    lines.push(`| ${scan.scan_id} | ${scan.scan_type} | ${scan.tool} | ${scan.status} | ${s.critical} | ${s.high} | ${s.medium} | ${s.low} | ${s.info} |`);
  }
  lines.push('');

  lines.push('## Findings by rule', '');
  if (digest.groups.length === 0) {
    lines.push('No findings.');
  } else {
    lines.push(`| Severity | Rule | Count | Example${includeRemediation ? ' | Remediation' : ''} |`);
    lines.push(`|---|---|---|---${includeRemediation ? '|---' : ''}|`);
    for (const group of digest.groups) {
      const example = group.examples[0] ? locationText(group.examples[0]) : '';
      const row = [group.severity, `${escapeCell(group.rule_id)}: ${escapeCell(group.title)}`, String(group.count), escapeCell(example)];
      if (includeRemediation) row.push(escapeCell(group.fix ?? ''));
      lines.push(`| ${row.join(' | ')} |`);
    }
    if (digest.truncated) lines.push('', '_Only the top 100 rule groups are shown._');
  }
  lines.push('');
  return lines.join('\n');
}

export function renderReport(results: ScanResult[], decision: PolicyDecision, format: ReportFormat, includeRemediation = true): string {
  switch (format) {
    case 'markdown':
      return renderMarkdown(results, decision, includeRemediation);
    case 'sarif': {
      const runs = results.flatMap((result) => (toSarif(result)['runs'] as unknown[]) ?? []);
      return JSON.stringify({ $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs }, null, 2);
    }
    case 'json':
    default: {
      const findings = includeRemediation
        ? results
        : results.map((result) => ({ ...result, findings: result.findings.map(({ fix: _fix, ...rest }) => rest) }));
      return JSON.stringify({ policy: decision, results: findings }, null, 2);
    }
  }
}
