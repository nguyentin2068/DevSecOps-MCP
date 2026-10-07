import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { validateOptionValue } from '../guards';
import { runCommand, stderrTail } from '../process';
import { Finding, ScannerOutput, Severity, UNKNOWN_SEVERITY } from '../types';

export interface NucleiOptions {
  bin: string;
  templates: string[];
  severities: string[];
  includeTags: string[];
  excludeTags: string[];
  excludeTemplateIds: string[];
  rateLimit: number;
  concurrency: number;
  requestTimeoutSeconds: number;
  timeoutSeconds: number;
  env?: NodeJS.ProcessEnv;
}

export interface NucleiTargets {
  /** URLs for the regular templates. Templates build their own paths from these base URLs. */
  templateTargets: string[];
  /** URLs for the DAST fuzzing pass (only those with query parameters are fuzzed); empty = no fuzzing. */
  fuzzTargets: string[];
}

interface NucleiResult {
  'template-id'?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    remediation?: string;
    reference?: string[] | string | null;
    classification?: { 'cve-id'?: string[] | null; 'cwe-id'?: string[] | null };
  };
  'matcher-name'?: string;
  'matched-at'?: string;
  host?: string;
  type?: string;
  'fuzzing_parameter'?: string;
  'fuzzing_method'?: string;
  // extracted-results, curl-command, request and response are deliberately ignored: they can
  // carry tokens or response bodies from the target and must not end up in reports.
}

const SEVERITY_MAP: Record<string, Severity> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info'
};

function asList(value: string[] | string | null | undefined): string[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

/** Parse nuclei's JSONL output (one finding per line). */
export function parseNuclei(output: string): ScannerOutput {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  let malformed = 0;

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let result: NucleiResult;
    try {
      result = JSON.parse(trimmed) as NucleiResult;
    } catch {
      malformed++;
      continue;
    }
    const templateId = result['template-id'];
    if (!templateId) continue;

    const matcher = result['matcher-name'];
    const url = result['matched-at'] ?? result.host ?? '';
    const id = `${templateId}:${matcher ?? ''}:${url}:${result['fuzzing_parameter'] ?? ''}`;
    if (seen.has(id)) continue;
    seen.add(id);

    const info = result.info ?? {};
    const finding: Finding = {
      id,
      rule_id: templateId,
      title: `${info.name ?? templateId}${matcher ? ` [${matcher}]` : ''}`,
      severity: SEVERITY_MAP[(info.severity ?? '').toLowerCase()] ?? UNKNOWN_SEVERITY,
      location: { url, method: (result['fuzzing_method'] ?? 'GET').toUpperCase() }
    };
    if (result['fuzzing_parameter']) finding.location.parameter = result['fuzzing_parameter'];
    if (info.description) finding.description = info.description.trim();
    if (info.remediation) finding.fix = info.remediation.trim();
    const references = asList(info.reference).filter((ref) => /^https?:\/\//.test(ref));
    if (references.length) finding.references = references.slice(0, 10);
    const cves = asList(info.classification?.['cve-id']).map((cve) => cve.toUpperCase());
    if (cves.length) finding.cve = cves;
    const cwes = asList(info.classification?.['cwe-id']).map((cwe) => cwe.toUpperCase());
    if (cwes.length) finding.cwe = cwes;
    findings.push(finding);
  }

  return { findings, metadata: { malformed_lines: malformed } };
}

/** Arguments shared by both passes. Every value from the rules file is checked for flag-like input. */
export function nucleiArgs(listFile: string, options: NucleiOptions, fuzzPass: boolean): string[] {
  const args = [
    '-l', listFile,
    '-jsonl',
    '-silent',
    '-nc',
    '-duc',
    // No out-of-band callbacks to public interactsh servers (would leak target details).
    '-ni',
    // Do not follow redirects off the vetted target.
    '-dr',
    // Keep raw requests/responses and encoded templates out of the output.
    '-or',
    '-ot',
    // HTTP templates only: no code, headless, file, network or DNS protocols.
    '-pt', 'http',
    '-rl', String(options.rateLimit),
    '-c', String(options.concurrency),
    '-timeout', String(options.requestTimeoutSeconds)
  ];
  for (const template of options.templates) args.push('-t', validateOptionValue(template, 'Nuclei templates'));
  if (options.severities.length) args.push('-s', options.severities.join(','));
  if (options.includeTags.length) args.push('-tags', options.includeTags.join(','));
  if (options.excludeTags.length) args.push('-etags', options.excludeTags.join(','));
  if (options.excludeTemplateIds.length) args.push('-eid', options.excludeTemplateIds.join(','));
  if (fuzzPass) args.push('-dast');
  return args;
}

async function runPass(listFile: string, options: NucleiOptions, fuzzPass: boolean): Promise<ScannerOutput> {
  const { code, stdout, stderr } = await runCommand(options.bin, nucleiArgs(listFile, options, fuzzPass), {
    timeoutMs: options.timeoutSeconds * 1000,
    ...(options.env ? { env: options.env } : {})
  });
  if (code !== 0) {
    throw new Error(`nuclei exited with code ${code}: ${stderrTail(stderr || stdout)}`);
  }
  return parseNuclei(stdout);
}

/**
 * Run nuclei over already-vetted, same-origin URLs.
 * Pass 1: the regular HTTP templates against the base target(s). These templates append
 * their own paths to the input URL, so running them on every crawled page would multiply
 * requests without adding coverage.
 * Pass 2 (optional): the DAST fuzzing templates against crawled URLs that have query
 * parameters, which is what the fuzzer mutates.
 */
export async function runNuclei(targets: NucleiTargets, options: NucleiOptions): Promise<ScannerOutput> {
  if (targets.templateTargets.length === 0) throw new Error('nuclei needs at least one URL');
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'nuclei-'));
  try {
    const listFile = path.join(dir, 'targets.txt');
    await fs.writeFile(listFile, `${targets.templateTargets.join('\n')}\n`);
    const baseline = await runPass(listFile, options, false);

    const fuzzable = targets.fuzzTargets.filter((url) => new URL(url).search.length > 1);
    let fuzzed: ScannerOutput = { findings: [] };
    if (fuzzable.length) {
      const fuzzFile = path.join(dir, 'fuzz-targets.txt');
      await fs.writeFile(fuzzFile, `${fuzzable.join('\n')}\n`);
      fuzzed = await runPass(fuzzFile, options, true);
    }

    const seen = new Set(baseline.findings.map((finding) => finding.id));
    const findings = [...baseline.findings, ...fuzzed.findings.filter((finding) => !seen.has(finding.id))];
    return {
      findings,
      metadata: {
        template_targets: targets.templateTargets.length,
        fuzzed_urls: fuzzable.length,
        malformed_lines:
          Number(baseline.metadata?.['malformed_lines'] ?? 0) + Number(fuzzed.metadata?.['malformed_lines'] ?? 0)
      }
    };
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}
