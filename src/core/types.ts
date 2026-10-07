export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SCAN_TYPES = ['sast', 'sca', 'container', 'dast'] as const;
export type ScanType = (typeof SCAN_TYPES)[number];

export const TOOLS_BY_SCAN_TYPE: Record<ScanType, readonly string[]> = {
  sast: ['opengrep'],
  sca: ['osv-scanner', 'trivy'],
  container: ['trivy'],
  dast: ['nuclei']
};

export interface FindingLocation {
  path?: string;
  line?: number;
  url?: string;
  method?: string;
  parameter?: string;
  package?: string;
  version?: string;
  ecosystem?: string;
}

export interface Finding {
  /** Stable identifier of this finding inside the scan (used for dedup). */
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  description?: string;
  location: FindingLocation;
  fix?: string;
  references?: string[];
  cwe?: string[];
  cve?: string[];
}

export type Summary = Record<Severity, number> & { total: number };

export interface ScanResult {
  schema_version: 1;
  scan_id: string;
  scan_type: ScanType;
  tool: string;
  status: 'completed' | 'failed';
  target: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  summary: Summary;
  findings: Finding[];
  error?: string;
  metadata: Record<string, unknown>;
}

/** What a scanner adapter returns before the runner adds ids and timing. */
export interface ScannerOutput {
  findings: Finding[];
  metadata?: Record<string, unknown>;
}

/** Severity used when a scanner gives none; conservative on purpose for a security gate. */
export const UNKNOWN_SEVERITY: Severity = 'medium';

export function emptySummary(): Summary {
  return { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function summarize(findings: Finding[]): Summary {
  const summary = emptySummary();
  for (const finding of findings) {
    summary[finding.severity]++;
    summary.total++;
  }
  return summary;
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

export function severityRank(severity: Severity): number {
  return SEVERITIES.length - SEVERITIES.indexOf(severity);
}

/** Bucket a CVSS base score into a severity, following the CVSS v3 qualitative scale. */
export function severityFromCvss(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
