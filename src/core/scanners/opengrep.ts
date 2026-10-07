import path from 'path';
import { validateOptionValue } from '../guards';
import { parseJsonOutput, runCommand, stderrTail } from '../process';
import { Finding, ScannerOutput, Severity, UNKNOWN_SEVERITY } from '../types';

export interface OpengrepOptions {
  bin: string;
  configs: string[];
  exclude: string[];
  timeoutSeconds: number;
  /** Cross-function taint tracking within a file (Opengrep's --taint-intrafile). */
  taintIntrafile: boolean;
  env?: NodeJS.ProcessEnv;
}

interface OpengrepResult {
  check_id: string;
  path: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    fix?: string;
    metadata?: {
      cwe?: string | string[];
      references?: string | string[];
      category?: string;
      confidence?: string;
    };
  };
}

interface OpengrepOutput {
  results?: OpengrepResult[];
  errors?: Array<{ level?: string; message?: string }>;
  version?: string;
}

const SEVERITY_MAP: Record<string, Severity> = {
  CRITICAL: 'critical',
  ERROR: 'high',
  HIGH: 'high',
  WARNING: 'medium',
  MEDIUM: 'medium',
  INFO: 'low',
  LOW: 'low',
  INVENTORY: 'info',
  EXPERIMENT: 'info'
};

function asList(value: string | string[] | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

/** Opengrep keeps Semgrep's JSON output format (it forked Semgrep 1.100). */
export function parseOpengrep(output: OpengrepOutput, targetRoot: string): ScannerOutput {
  const findings: Finding[] = (output.results ?? []).map((result) => {
    const file = path.isAbsolute(result.path) ? path.relative(targetRoot, result.path) : result.path;
    const line = result.start?.line ?? 0;
    const metadata = result.extra?.metadata ?? {};
    const finding: Finding = {
      id: `${result.check_id}:${file}:${line}`,
      rule_id: result.check_id,
      title: (result.extra?.message ?? '').split('\n')[0]?.slice(0, 200) || (result.check_id.split('.').pop() ?? result.check_id),
      severity: SEVERITY_MAP[(result.extra?.severity ?? '').toUpperCase()] ?? UNKNOWN_SEVERITY,
      location: { path: file, line }
    };
    if (result.extra?.message) finding.description = result.extra.message;
    if (result.extra?.fix) finding.fix = result.extra.fix;
    const cwe = asList(metadata.cwe);
    if (cwe.length) finding.cwe = cwe;
    const references = asList(metadata.references);
    if (references.length) finding.references = references;
    return finding;
  });

  return {
    findings,
    metadata: {
      scanner_version: output.version,
      scanner_errors: (output.errors ?? []).map((error) => error.message ?? 'unknown error').slice(0, 20)
    }
  };
}

export async function runOpengrep(target: string, options: OpengrepOptions): Promise<ScannerOutput> {
  const args = ['scan', '--json', '--disable-version-check', '--quiet'];
  if (options.taintIntrafile) args.push('--taint-intrafile');
  for (const config of options.configs) args.push('--config', validateOptionValue(config, 'Opengrep config'));
  for (const pattern of options.exclude) args.push('--exclude', validateOptionValue(pattern, 'Opengrep exclude'));
  args.push('--', target);

  const base = options.env ?? process.env;
  const { code, stdout, stderr } = await runCommand(options.bin, args, {
    cwd: target,
    timeoutMs: options.timeoutSeconds * 1000,
    // The bundled runtime reads rule files with the locale's encoding; without a UTF-8
    // locale (common in minimal containers) rules containing non-ASCII text fail to load.
    env: { ...base, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' }
  });
  // 0 = success, 1 = findings with --error; anything else is a scanner failure.
  if (code !== 0 && code !== 1) {
    throw new Error(`opengrep exited with code ${code}: ${stderrTail(stderr)}`);
  }
  return parseOpengrep(parseJsonOutput<OpengrepOutput>('opengrep', stdout), target);
}
