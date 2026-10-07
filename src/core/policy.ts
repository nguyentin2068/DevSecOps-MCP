import { effectiveThresholds, SecurityRules } from './config';
import { isSeverity, ScanResult, SCAN_TYPES, SEVERITIES, Severity } from './types';

export type PolicyStatus = 'PASS' | 'WARN' | 'FAIL';

export interface ScanEvaluation {
  scan_id: string;
  scan_type: string;
  tool: string;
  counts: Partial<Record<Severity, number>>;
  thresholds: Partial<Record<Severity, number | null>>;
  violations: string[];
}

export interface PolicyDecision {
  status: PolicyStatus;
  enforcement_level: SecurityRules['global_policy']['enforcement_level'];
  evaluated_at: string;
  reasons: string[];
  scans: ScanEvaluation[];
}

function validCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

function evaluateScan(result: Partial<ScanResult> | undefined, rules: SecurityRules): ScanEvaluation {
  const evaluation: ScanEvaluation = {
    scan_id: result?.scan_id ?? 'unknown',
    scan_type: result?.scan_type ?? 'unknown',
    tool: result?.tool ?? 'unknown',
    counts: {},
    thresholds: {},
    violations: []
  };

  if (!result || !result.scan_type || !(SCAN_TYPES as readonly string[]).includes(result.scan_type)) {
    evaluation.violations.push('missing data: result has no valid scan_type');
    return evaluation;
  }
  if (result.status !== 'completed') {
    evaluation.violations.push(`scan did not complete (${result.status ?? 'no status'}): ${result.error ?? 'no error message'}`);
    return evaluation;
  }
  if (!result.summary || typeof result.summary !== 'object') {
    evaluation.violations.push('missing data: result has no summary');
    return evaluation;
  }

  const thresholds = effectiveThresholds(rules, result.scan_type);
  evaluation.thresholds = thresholds;

  for (const severity of SEVERITIES) {
    const count = result.summary[severity];
    if (!validCount(count)) {
      evaluation.violations.push(`missing data: summary.${severity} is not a valid count`);
      continue;
    }
    evaluation.counts[severity] = count;
    const max = thresholds[severity];
    if (max !== undefined && max !== null && count > max) {
      evaluation.violations.push(`${severity}: ${count} finding(s) exceed the threshold of ${max}`);
    }
  }

  // Cross-check the summary against the findings so a hand-edited summary cannot pass the gate.
  if (Array.isArray(result.findings)) {
    for (const severity of SEVERITIES) {
      const actual = result.findings.filter((finding) => isSeverity(finding?.severity) && finding.severity === severity).length;
      if (validCount(result.summary[severity]) && actual > result.summary[severity]) {
        evaluation.violations.push(`missing data: summary.${severity} (${result.summary[severity]}) is lower than the ${actual} finding(s) recorded`);
      }
    }
  }

  return evaluation;
}

/**
 * Evaluate scan results against the policy. No results, failed scans and incomplete data
 * are violations: the gate never passes on missing evidence.
 */
export function evaluatePolicy(results: Array<Partial<ScanResult> | undefined>, rules: SecurityRules, now = new Date()): PolicyDecision {
  const scans = results.map((result) => evaluateScan(result, rules));
  const reasons = scans.flatMap((scan) => scan.violations.map((violation) => `[${scan.scan_id}] ${violation}`));
  if (results.length === 0) reasons.push('missing data: no scan results were provided');

  const enforcement = rules.global_policy.enforcement_level;
  let status: PolicyStatus = 'PASS';
  if (reasons.length > 0) status = enforcement === 'strict' ? 'FAIL' : 'WARN';

  return { status, enforcement_level: enforcement, evaluated_at: now.toISOString(), reasons, scans };
}
