import { parseJsonOutput, runCommand, stderrTail } from '../process';
import { Finding, ScannerOutput, Severity, UNKNOWN_SEVERITY } from '../types';

export interface TrivyOptions {
  bin: string;
  timeoutSeconds: number;
  scanners: string[];
  ignoreUnfixed: boolean;
  cacheDir?: string;
}

interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  CweIDs?: string[];
  PrimaryURL?: string;
  References?: string[];
}

interface TrivySecret {
  RuleID: string;
  Category?: string;
  Severity?: string;
  Title?: string;
  StartLine?: number;
  // Match and Code contain the secret itself and are deliberately never copied into reports.
}

interface TrivyMisconfiguration {
  ID: string;
  AVDID?: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Resolution?: string;
  Severity?: string;
  PrimaryURL?: string;
  Status?: string;
  CauseMetadata?: { StartLine?: number };
}

interface TrivyReport {
  SchemaVersion?: number;
  ArtifactName?: string;
  Results?: Array<{
    Target: string;
    Class?: string;
    Type?: string;
    Vulnerabilities?: TrivyVulnerability[] | null;
    Secrets?: TrivySecret[] | null;
    Misconfigurations?: TrivyMisconfiguration[] | null;
  }>;
}

const SEVERITY_MAP: Record<string, Severity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
};

function mapSeverity(value: string | undefined): Severity {
  return SEVERITY_MAP[(value ?? '').toUpperCase()] ?? UNKNOWN_SEVERITY;
}

export function parseTrivy(report: TrivyReport): ScannerOutput {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (finding: Finding) => {
    if (seen.has(finding.id)) return;
    seen.add(finding.id);
    findings.push(finding);
  };

  for (const result of report.Results ?? []) {
    for (const vuln of result.Vulnerabilities ?? []) {
      const finding: Finding = {
        id: `${result.Target}:${vuln.PkgName}@${vuln.InstalledVersion ?? ''}:${vuln.VulnerabilityID}`,
        rule_id: vuln.VulnerabilityID,
        title: vuln.Title || `${vuln.VulnerabilityID} in ${vuln.PkgName}`,
        severity: mapSeverity(vuln.Severity),
        location: { path: result.Target, package: vuln.PkgName, version: vuln.InstalledVersion ?? '' }
      };
      if (result.Type) finding.location.ecosystem = result.Type;
      if (vuln.Description) finding.description = vuln.Description;
      if (vuln.FixedVersion) finding.fix = `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion}`;
      if (vuln.CweIDs?.length) finding.cwe = vuln.CweIDs;
      if (vuln.VulnerabilityID.startsWith('CVE-')) finding.cve = [vuln.VulnerabilityID];
      const references = [vuln.PrimaryURL, ...(vuln.References ?? [])].filter((ref): ref is string => !!ref);
      if (references.length) finding.references = Array.from(new Set(references)).slice(0, 10);
      push(finding);
    }

    for (const secret of result.Secrets ?? []) {
      const line = secret.StartLine ?? 0;
      push({
        id: `${result.Target}:${line}:${secret.RuleID}`,
        rule_id: `secret:${secret.RuleID}`,
        title: secret.Title || `Secret detected (${secret.RuleID})`,
        severity: mapSeverity(secret.Severity),
        description: `${secret.Category ?? 'Secret'} found; rotate the credential and remove it from the source tree.`,
        location: { path: result.Target, line }
      });
    }

    for (const misconfig of result.Misconfigurations ?? []) {
      if (misconfig.Status && misconfig.Status !== 'FAIL') continue;
      const line = misconfig.CauseMetadata?.StartLine ?? 0;
      const ruleId = misconfig.AVDID || misconfig.ID;
      const finding: Finding = {
        id: `${result.Target}:${line}:${ruleId}`,
        rule_id: ruleId,
        title: misconfig.Title || ruleId,
        severity: mapSeverity(misconfig.Severity),
        location: { path: result.Target, line }
      };
      const description = misconfig.Message || misconfig.Description;
      if (description) finding.description = description;
      if (misconfig.Resolution) finding.fix = misconfig.Resolution;
      if (misconfig.PrimaryURL) finding.references = [misconfig.PrimaryURL];
      push(finding);
    }
  }

  return { findings, metadata: { artifact: report.ArtifactName } };
}

async function runTrivy(mode: 'fs' | 'image', target: string, options: TrivyOptions, cwd?: string): Promise<ScannerOutput> {
  const args = [mode, '--format', 'json', '--quiet', '--exit-code', '0', '--scanners', options.scanners.join(',')];
  if (options.ignoreUnfixed) args.push('--ignore-unfixed');
  if (options.cacheDir) args.push('--cache-dir', options.cacheDir);
  args.push('--', target);

  const runOptions = { timeoutMs: options.timeoutSeconds * 1000, ...(cwd ? { cwd } : {}) };
  const { code, stdout, stderr } = await runCommand(options.bin, args, runOptions);
  if (code !== 0) {
    throw new Error(`trivy exited with code ${code}: ${stderrTail(stderr)}`);
  }
  return parseTrivy(parseJsonOutput<TrivyReport>('trivy', stdout));
}

export function runTrivyFilesystem(target: string, options: TrivyOptions): Promise<ScannerOutput> {
  return runTrivy('fs', target, options, target);
}

export function runTrivyImage(imageRef: string, options: TrivyOptions): Promise<ScannerOutput> {
  return runTrivy('image', imageRef, options);
}
