import { writeFileSync } from 'fs';
import path from 'path';
import { effectiveThresholds, envSecret, loadRules, parseRules } from '../../src/core/config';
import { RULES_PATH, tempDir } from '../helpers';

describe('security rules loading', () => {
  it('loads and validates the shipped rules file', () => {
    const rules = loadRules(RULES_PATH);
    expect(rules.global_policy.enforcement_level).toBe('strict');
    expect(rules.sast.default_tool).toBe('semgrep');
    expect(rules.dast.target_policy.allowed_hosts).toEqual([]);
  });

  it('fills defaults for omitted sections', () => {
    const rules = parseRules('version: "2.0"\nglobal_policy: {}\n');
    expect(rules.global_policy.thresholds).toEqual({ critical: 0, high: 0 });
    expect(rules.dast.zap.mode).toBe('baseline');
    expect(rules.sca.trivy.scanners).toEqual(['vuln']);
  });

  it('rejects unknown keys and invalid values', () => {
    expect(() => parseRules('version: "2.0"\nglobal_policy: {}\nunknown_section: {}\n')).toThrow(/unknown_section/);
    expect(() => parseRules('version: "2.0"\nglobal_policy: { enforcement_level: lax }\n')).toThrow(/enforcement_level/);
    expect(() => parseRules('version: "2.0"\nglobal_policy: { thresholds: { high: -1 } }\n')).toThrow(/high/);
  });

  it('rejects scanner options that look like flags', () => {
    expect(() => parseRules('version: "2.0"\nglobal_policy: {}\nsast: { semgrep: { configs: ["--dangerous"] } }\n')).toThrow();
  });

  it('rejects invalid YAML', () => {
    expect(() => parseRules('version: [unclosed')).toThrow(/invalid YAML/);
  });

  it('overlays scan-type thresholds on the global ones', () => {
    const rules = parseRules(`
version: "2.0"
global_policy: { thresholds: { critical: 0, high: 0, medium: 5 } }
sca: { thresholds: { medium: 1 } }
`);
    expect(effectiveThresholds(rules, 'sca')).toEqual({ critical: 0, high: 0, medium: 1 });
    expect(effectiveThresholds(rules, 'sast')).toEqual({ critical: 0, high: 0, medium: 5 });
  });
});

describe('envSecret', () => {
  it('prefers NAME_FILE over NAME and trims the value', () => {
    const file = path.join(tempDir(), 'token');
    writeFileSync(file, 's3cret\n');
    expect(envSecret('TOKEN', { TOKEN_FILE: file, TOKEN: 'other' })).toBe('s3cret');
    expect(envSecret('TOKEN', { TOKEN: ' plain ' })).toBe('plain');
    expect(envSecret('TOKEN', {})).toBeUndefined();
  });
});
