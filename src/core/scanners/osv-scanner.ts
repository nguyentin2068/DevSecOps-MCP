import path from 'path';
import { parseJsonOutput, runCommand, stderrTail } from '../process';
import { Finding, ScannerOutput, Severity, UNKNOWN_SEVERITY, severityFromCvss } from '../types';

export interface OsvOptions {
  bin: string;
  timeoutSeconds: number;
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  references?: Array<{ type?: string; url: string }>;
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

interface OsvPackage {
  package: { name: string; version: string; ecosystem: string };
  vulnerabilities?: OsvVulnerability[];
  groups?: Array<{ ids: string[]; aliases?: string[]; max_severity?: string }>;
}

interface OsvReport {
  results?: Array<{ source: { path: string; type?: string }; packages?: OsvPackage[] }>;
}

const DATABASE_SEVERITY: Record<string, Severity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MODERATE: 'medium',
  MEDIUM: 'medium',
  LOW: 'low'
};

function groupSeverity(maxSeverity: string | undefined, vulns: OsvVulnerability[]): Severity {
  const score = maxSeverity ? Number.parseFloat(maxSeverity) : Number.NaN;
  if (Number.isFinite(score) && score > 0) return severityFromCvss(score);
  for (const vuln of vulns) {
    const mapped = DATABASE_SEVERITY[(vuln.database_specific?.severity ?? '').toUpperCase()];
    if (mapped) return mapped;
  }
  return UNKNOWN_SEVERITY;
}

function fixedVersions(vulns: OsvVulnerability[], packageName: string): string[] {
  const fixed = new Set<string>();
  for (const vuln of vulns) {
    for (const affected of vuln.affected ?? []) {
      if (affected.package?.name !== packageName) continue;
      for (const range of affected.ranges ?? []) {
        for (const event of range.events ?? []) {
          if (event.fixed) fixed.add(event.fixed);
        }
      }
    }
  }
  return Array.from(fixed);
}

export function parseOsv(report: OsvReport, targetRoot: string): ScannerOutput {
  const findings: Finding[] = [];

  for (const result of report.results ?? []) {
    const source = path.isAbsolute(result.source.path) ? path.relative(targetRoot, result.source.path) : result.source.path;
    for (const pkg of result.packages ?? []) {
      const vulns = pkg.vulnerabilities ?? [];
      const byId = new Map(vulns.map((vuln) => [vuln.id, vuln]));
      // OSV groups aliases of the same issue (GHSA + CVE ...) together; one finding per group.
      const groups = pkg.groups?.length ? pkg.groups : vulns.map((vuln) => ({ ids: [vuln.id], aliases: vuln.aliases ?? [] }));

      for (const group of groups) {
        const members = group.ids.map((id) => byId.get(id)).filter((vuln): vuln is OsvVulnerability => !!vuln);
        const primary = members[0];
        const ruleId = group.ids[0] ?? 'unknown';
        const aliases = new Set<string>([...group.ids, ...(group.aliases ?? []), ...members.flatMap((m) => m.aliases ?? [])]);
        const { name, version, ecosystem } = pkg.package;

        const finding: Finding = {
          id: `${source}:${ecosystem}/${name}@${version}:${ruleId}`,
          rule_id: ruleId,
          title: primary?.summary || `${ruleId} in ${name}@${version}`,
          severity: groupSeverity('max_severity' in group ? group.max_severity : undefined, members),
          location: { path: source, package: name, version, ecosystem }
        };
        if (primary?.details) finding.description = primary.details;
        const fixes = fixedVersions(members, name);
        if (fixes.length) finding.fix = `Upgrade ${name} to ${fixes.join(' or ')}`;
        const cves = Array.from(aliases).filter((alias) => alias.startsWith('CVE-'));
        if (cves.length) finding.cve = cves;
        const cwe = members.flatMap((m) => m.database_specific?.cwe_ids ?? []);
        if (cwe.length) finding.cwe = Array.from(new Set(cwe));
        finding.references = [`https://osv.dev/vulnerability/${ruleId}`];
        findings.push(finding);
      }
    }
  }

  return { findings, metadata: { sources: (report.results ?? []).length } };
}

export async function runOsvScanner(target: string, options: OsvOptions): Promise<ScannerOutput> {
  const args = ['scan', 'source', '--format', 'json', '--recursive', '--', target];
  const { code, stdout, stderr } = await runCommand(options.bin, args, {
    cwd: target,
    timeoutMs: options.timeoutSeconds * 1000
  });

  // 0 = clean, 1 = vulnerabilities found, 128 = no lockfiles/packages found.
  if (code === 128) {
    return { findings: [], metadata: { note: 'osv-scanner found no supported lockfiles or manifests' } };
  }
  if (code !== 0 && code !== 1) {
    throw new Error(`osv-scanner exited with code ${code}: ${stderrTail(stderr)}`);
  }
  return parseOsv(parseJsonOutput<OsvReport>('osv-scanner', stdout), target);
}
