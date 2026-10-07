import { parseRules } from '../../src/core/config';
import { evaluatePolicy } from '../../src/core/policy';
import { findings, loadDefaultRules, scanResult } from '../helpers';

const rules = loadDefaultRules();

describe('evaluatePolicy', () => {
  it('passes a clean scan', () => {
    const decision = evaluatePolicy([scanResult()], rules);
    expect(decision.status).toBe('PASS');
    expect(decision.reasons).toEqual([]);
  });

  it('fails when a critical finding exceeds a threshold of 0', () => {
    const decision = evaluatePolicy([scanResult({ findings: findings({ critical: 1 }) })], rules);
    expect(decision.status).toBe('FAIL');
    expect(decision.reasons.join('\n')).toMatch(/critical: 1 finding\(s\) exceed the threshold of 0/);
  });

  it('fails when high findings exceed a threshold of 0', () => {
    const decision = evaluatePolicy([scanResult({ findings: findings({ high: 2 }) })], rules);
    expect(decision.status).toBe('FAIL');
    expect(decision.reasons.join('\n')).toMatch(/high: 2/);
  });

  it('allows medium findings up to the threshold and fails above it', () => {
    // sast.thresholds.medium is 5 in the default rules
    expect(evaluatePolicy([scanResult({ findings: findings({ medium: 5 }) })], rules).status).toBe('PASS');
    const decision = evaluatePolicy([scanResult({ findings: findings({ medium: 6 }) })], rules);
    expect(decision.status).toBe('FAIL');
    expect(decision.reasons.join('\n')).toMatch(/medium: 6 finding\(s\) exceed the threshold of 5/);
  });

  it('inherits global thresholds the scan type does not set', () => {
    // sast sets no low threshold; global_policy.thresholds.low is 20
    expect(evaluatePolicy([scanResult({ findings: findings({ low: 20 }) })], rules).status).toBe('PASS');
    expect(evaluatePolicy([scanResult({ findings: findings({ low: 21 }) })], rules).status).toBe('FAIL');
  });

  it('applies per-scan-type thresholds', () => {
    // sca.thresholds.medium is 3, stricter than sast
    const sca = scanResult({ scan_type: 'sca', tool: 'trivy', findings: findings({ medium: 4 }) });
    expect(evaluatePolicy([sca], rules).status).toBe('FAIL');
  });

  it('treats a null threshold as unlimited', () => {
    const custom = parseRules(`
version: "2.0"
global_policy:
  thresholds: { critical: 0, high: null }
`);
    expect(evaluatePolicy([scanResult({ findings: findings({ high: 50 }) })], custom).status).toBe('PASS');
  });

  it('fails when no results are provided', () => {
    const decision = evaluatePolicy([], rules);
    expect(decision.status).toBe('FAIL');
    expect(decision.reasons).toContain('missing data: no scan results were provided');
  });

  it('fails a scan that did not complete', () => {
    const decision = evaluatePolicy([scanResult({ status: 'failed', error: 'opengrep crashed' })], rules);
    expect(decision.status).toBe('FAIL');
    expect(decision.reasons.join('\n')).toMatch(/did not complete.*opengrep crashed/);
  });

  it('fails a result without a summary', () => {
    const broken = { ...scanResult(), summary: undefined } as never;
    expect(evaluatePolicy([broken], rules).status).toBe('FAIL');
  });

  it('fails a summary with non-numeric counts', () => {
    const broken = scanResult();
    (broken.summary as unknown as Record<string, unknown>)['high'] = 'zero';
    const decision = evaluatePolicy([broken], rules);
    expect(decision.status).toBe('FAIL');
    expect(decision.reasons.join('\n')).toMatch(/summary.high is not a valid count/);
  });

  it('fails a summary that under-reports the recorded findings', () => {
    const tampered = scanResult({ findings: findings({ critical: 2 }) });
    tampered.summary.critical = 0;
    tampered.summary.total = 0;
    const decision = evaluatePolicy([tampered], rules);
    expect(decision.status).toBe('FAIL');
    expect(decision.reasons.join('\n')).toMatch(/summary.critical \(0\) is lower than the 2 finding/);
  });

  it('fails an unknown scan type', () => {
    const odd = { ...scanResult(), scan_type: 'iast' } as never;
    expect(evaluatePolicy([odd], rules).status).toBe('FAIL');
  });

  it('reports WARN instead of FAIL under permissive enforcement', () => {
    const permissive = parseRules(`
version: "2.0"
global_policy:
  enforcement_level: permissive
  thresholds: { critical: 0 }
`);
    const decision = evaluatePolicy([scanResult({ findings: findings({ critical: 3 }) })], permissive);
    expect(decision.status).toBe('WARN');
    expect(decision.reasons).toHaveLength(1);
  });

  it('fails the whole decision when one of several scans fails', () => {
    const decision = evaluatePolicy(
      [scanResult({ scan_id: 'sast-a-0001' }), scanResult({ scan_id: 'sca-b-0001', scan_type: 'sca', tool: 'trivy', findings: findings({ critical: 1 }) })],
      rules
    );
    expect(decision.status).toBe('FAIL');
    expect(decision.scans.map((scan) => scan.violations.length)).toEqual([0, 1]);
  });
});
