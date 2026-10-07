import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { runCommand, stderrTail } from '../process';
import { Finding, ScannerOutput, Severity } from '../types';

export interface SonarOptions {
  scannerBin: string;
  hostUrl: string;
  token: string;
  projectKey: string;
  exclusions: string[];
  timeoutSeconds: number;
  pollIntervalMs?: number;
  fetchImpl?: typeof fetch;
}

interface SonarIssue {
  key: string;
  rule: string;
  severity?: string;
  component: string;
  line?: number;
  message: string;
  type?: string;
  impacts?: Array<{ softwareQuality: string; severity: string }>;
}

const IMPACT_SEVERITY: Record<string, Severity> = {
  BLOCKER: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
};

const LEGACY_SEVERITY: Record<string, Severity> = {
  BLOCKER: 'critical',
  CRITICAL: 'high',
  MAJOR: 'medium',
  MINOR: 'low',
  INFO: 'info'
};

function issueSeverity(issue: SonarIssue): Severity {
  const security = issue.impacts?.find((impact) => impact.softwareQuality === 'SECURITY');
  return (
    (security && IMPACT_SEVERITY[security.severity]) ?? LEGACY_SEVERITY[issue.severity ?? ''] ?? 'medium'
  );
}

export function parseSonarIssues(issues: SonarIssue[], projectKey: string): Finding[] {
  return issues.map((issue) => {
    const file = issue.component.startsWith(`${projectKey}:`) ? issue.component.slice(projectKey.length + 1) : issue.component;
    return {
      id: issue.key,
      rule_id: issue.rule,
      title: issue.message,
      severity: issueSeverity(issue),
      location: { path: file, line: issue.line ?? 0 }
    };
  });
}

/** sonar-scanner writes report-task.txt as key=value lines; ceTaskId identifies the analysis. */
export function parseReportTask(content: string): Record<string, string> {
  const entries: Record<string, string> = {};
  for (const line of content.split('\n')) {
    const index = line.indexOf('=');
    if (index > 0) entries[line.slice(0, index).trim()] = line.slice(index + 1).trim();
  }
  return entries;
}

class SonarClient {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly hostUrl: string, private readonly token: string, fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? fetch;
  }

  async get<T>(apiPath: string, params: Record<string, string | number>): Promise<T> {
    const url = new URL(apiPath, this.hostUrl);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, String(value));
    const response = await this.fetchImpl(url, {
      headers: { Authorization: `Bearer ${this.token}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(60_000)
    });
    if (!response.ok) {
      throw new Error(`SonarQube API ${apiPath} returned HTTP ${response.status}`);
    }
    return (await response.json()) as T;
  }
}

/** Fetch analysis results for a finished compute-engine task. */
export async function collectSonarResults(
  ceTaskId: string,
  options: Pick<SonarOptions, 'hostUrl' | 'token' | 'projectKey' | 'timeoutSeconds' | 'pollIntervalMs' | 'fetchImpl'>
): Promise<ScannerOutput> {
  const client = new SonarClient(options.hostUrl, options.token, options.fetchImpl);
  const deadline = Date.now() + options.timeoutSeconds * 1000;
  let analysisId: string | undefined;

  while (Date.now() < deadline) {
    const { task } = await client.get<{ task: { status: string; analysisId?: string; errorMessage?: string } }>(
      '/api/ce/task',
      { id: ceTaskId }
    );
    if (task.status === 'SUCCESS') {
      analysisId = task.analysisId;
      break;
    }
    if (task.status === 'FAILED' || task.status === 'CANCELED') {
      throw new Error(`SonarQube analysis ${task.status}: ${task.errorMessage ?? 'no details'}`);
    }
    await new Promise((resolve) => setTimeout(resolve, options.pollIntervalMs ?? 5000));
  }
  if (!analysisId) throw new Error('Timed out waiting for the SonarQube analysis to finish');

  const gate = await client.get<{ projectStatus: { status: string; conditions?: unknown[] } }>(
    '/api/qualitygates/project_status',
    { analysisId }
  );

  const issues: SonarIssue[] = [];
  const pageSize = 500;
  // The issues API refuses to page beyond 10,000 results.
  for (let page = 1; page <= 20; page++) {
    const response = await client.get<{ issues: SonarIssue[]; paging?: { total: number } }>('/api/issues/search', {
      componentKeys: options.projectKey,
      types: 'VULNERABILITY',
      resolved: 'false',
      ps: pageSize,
      p: page
    });
    issues.push(...response.issues);
    if (response.issues.length < pageSize || issues.length >= (response.paging?.total ?? 0)) break;
  }

  return {
    findings: parseSonarIssues(issues, options.projectKey),
    metadata: {
      analysis_id: analysisId,
      quality_gate_status: gate.projectStatus.status,
      quality_gate_conditions: gate.projectStatus.conditions ?? [],
      dashboard_url: new URL(`/dashboard?id=${encodeURIComponent(options.projectKey)}`, options.hostUrl).toString()
    }
  };
}

export async function runSonarQube(target: string, options: SonarOptions): Promise<ScannerOutput> {
  if (!options.token) throw new Error('SONAR_TOKEN is required for SonarQube scans');
  const workDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sonar-'));
  try {
    const args = [
      `-Dsonar.projectKey=${options.projectKey}`,
      '-Dsonar.sources=.',
      `-Dsonar.host.url=${options.hostUrl}`,
      `-Dsonar.working.directory=${workDir}`,
      '-Dsonar.qualitygate.wait=false'
    ];
    if (options.exclusions.length) args.push(`-Dsonar.exclusions=${options.exclusions.join(',')}`);

    // The token is passed through the environment, never on the command line (visible in ps).
    const { code, stderr, stdout } = await runCommand(options.scannerBin, args, {
      cwd: target,
      timeoutMs: options.timeoutSeconds * 1000,
      env: { ...process.env, SONAR_TOKEN: options.token }
    });
    if (code !== 0) {
      throw new Error(`sonar-scanner exited with code ${code}: ${stderrTail(stderr || stdout)}`);
    }

    const reportTask = parseReportTask(await fs.readFile(path.join(workDir, 'report-task.txt'), 'utf8'));
    const ceTaskId = reportTask['ceTaskId'];
    if (!ceTaskId) throw new Error('sonar-scanner did not report a compute-engine task id');

    return await collectSonarResults(ceTaskId, options);
  } finally {
    await fs.rm(workDir, { recursive: true, force: true });
  }
}
