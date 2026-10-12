import { mkdtempSync, readFileSync } from 'fs';
import os from 'os';
import path from 'path';
import { parseRules, SecurityRules } from '../src/core/config';
import { emptySummary, Finding, ScanResult, ScanType, summarize } from '../src/core/types';

export const RULES_PATH = path.join(__dirname, '..', 'src', 'config', 'security-rules.yml');

export function loadDefaultRules(): SecurityRules {
  return parseRules(readFileSync(RULES_PATH, 'utf8'));
}

export function tempDir(prefix = 'devsecops-test-'): string {
  return mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function finding(severity: Finding['severity'], index = 0): Finding {
  return {
    id: `rule-${severity}-${index}`,
    rule_id: `rule-${severity}`,
    title: `${severity} issue`,
    severity,
    location: { path: 'app.js', line: index + 1 }
  };
}

export function findings(counts: Partial<Record<Finding['severity'], number>>): Finding[] {
  return Object.entries(counts).flatMap(([severity, count]) =>
    Array.from({ length: count ?? 0 }, (_, i) => finding(severity as Finding['severity'], i))
  );
}

export function scanResult(overrides: Partial<ScanResult> & { findings?: Finding[] } = {}): ScanResult {
  const list = overrides.findings ?? [];
  const scanType: ScanType = overrides.scan_type ?? 'sast';
  return {
    schema_version: 1,
    scan_id: overrides.scan_id ?? `${scanType}-test-0001`,
    scan_type: scanType,
    tool: overrides.tool ?? 'opengrep',
    status: overrides.status ?? 'completed',
    target: overrides.target ?? '/workspace',
    started_at: '2026-01-01T00:00:00.000Z',
    finished_at: overrides.finished_at ?? '2026-01-01T00:01:00.000Z',
    duration_ms: 60000,
    summary: overrides.summary ?? (overrides.status === 'failed' ? emptySummary() : summarize(list)),
    findings: list,
    metadata: overrides.metadata ?? {},
    ...(overrides.error ? { error: overrides.error } : {})
  };
}
