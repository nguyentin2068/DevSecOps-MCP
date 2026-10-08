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
    // sca.thresholds.medium is 3 in the default rules
    const sca = (count: number) => scanResult({ scan_type: 'sca', tool: 'trivy', findings: findings({ medium: count }) });
    expect(evaluatePolicy([sca(3)], rules).status).toBe('PASS');
    const decision = evaluatePolicy([sca(4)], rules);
    expect(decision.status).toBe('FAIL');
    expect(decision.reasons.join('\n')).toMatch(/medium: 4 finding\(s\) exceed the threshold of 3/);
  });

  it('inherits global thresholds the scan type does not set', () => {
    // dast sets no low threshold; global_policy.thresholds.low is 20
    const dast = (count: number) => scanResult({ scan_type: 'dast', tool: 'nuclei', findings: findings({ low: count }) });
    expect(evaluatePolicy([dast(20)], rules).status).toBe('PASS');
    expect(evaluatePolicy([dast(21)], rules).status).toBe('FAIL');
  });

  it('reports but does not gate medium and low SAST findings by default', () => {
    // sast sets medium/low to null, overriding the global 5/20: opengrep-rules is noisy
    const decision = evaluatePolicy([scanResult({ findings: findings({ medium: 50, low: 100 }) })], rules);
    expect(decision.status).toBe('PASS');
    expect(decision.scans[0]?.counts).toMatchObject({ medium: 50, low: 100 });
    expect(evaluatePolicy([scanResult({ findings: findings({ high: 1, medium: 50 }) })], rules).status).toBe('FAIL');
  });

  it('fails DAST on any medium finding (e.g. reflected XSS) but never on info', () => {
    const dast = (counts: Parameters<typeof findings>[0]) => scanResult({ scan_type: 'dast', tool: 'nuclei', findings: findings(counts) });
    expect(evaluatePolicy([dast({ info: 40 })], rules).status).toBe('PASS');
    const decision = evaluatePolicy([dast({ medium: 1, info: 40 })], rules);
    expect(decision.status).toBe('FAIL');
    expect(decision.reasons.join('\n')).toMatch(/medium: 1 finding\(s\) exceed the threshold of 0/);
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
