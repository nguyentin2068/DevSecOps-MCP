import { writeFileSync } from 'fs';
import path from 'path';
import { effectiveThresholds, envSecret, loadRules, parseRules, resolveConfigPath } from '../../src/core/config';
import { RULES_PATH, tempDir } from '../helpers';

describe('security rules loading', () => {
  it('loads and validates the shipped rules file', () => {
    const rules = loadRules(RULES_PATH);
    expect(rules.global_policy.enforcement_level).toBe('strict');
    expect(rules.sast.default_tool).toBe('opengrep');
    expect(rules.dast.default_tool).toBe('nuclei');
    expect(rules.base_dir).toBe(path.dirname(RULES_PATH));
    expect(rules.dast.target_policy.allowed_hosts).toEqual([]);
  });

  it('fills defaults for omitted sections', () => {
    const rules = parseRules('version: "2.0"\nglobal_policy: {}\n');
    expect(rules.global_policy.thresholds).toEqual({ critical: 0, high: 0 });
    expect(rules.dast.mode).toBe('baseline');
    expect(rules.dast.nuclei.exclude_tags).toEqual(['dos', 'intrusive']);
    expect(rules.sast.opengrep.taint_intrafile).toBe(true);
    expect(rules.sca.trivy.scanners).toEqual(['vuln']);
  });

  it('rejects unknown keys and invalid values', () => {
    expect(() => parseRules('version: "2.0"\nglobal_policy: {}\nunknown_section: {}\n')).toThrow(/unknown_section/);
    expect(() => parseRules('version: "2.0"\nglobal_policy: { enforcement_level: lax }\n')).toThrow(/enforcement_level/);
    expect(() => parseRules('version: "2.0"\nglobal_policy: { thresholds: { high: -1 } }\n')).toThrow(/high/);
  });

  it('rejects scanner options that look like flags', () => {
    expect(() => parseRules('version: "2.0"\nglobal_policy: {}\nsast: { opengrep: { configs: ["--dangerous"] } }\n')).toThrow();
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

describe('resolveConfigPath', () => {
  const rules = { ...parseRules('version: "2.0"\nglobal_policy: {}\n'), base_dir: '/etc/devsecops' };

  it('expands environment variables and resolves relative paths against the rules file', () => {
    expect(resolveConfigPath('opengrep/baseline.yml', rules, {})).toBe('/etc/devsecops/opengrep/baseline.yml');
    expect(resolveConfigPath('${OPENGREP_RULES_DIR}/python', rules, { OPENGREP_RULES_DIR: '/opt/rules' })).toBe('/opt/rules/python');
    expect(resolveConfigPath('/abs/rules.yml', rules, {})).toBe('/abs/rules.yml');
  });

  it('fails loudly on unset variables', () => {
    expect(() => resolveConfigPath('${NUCLEI_TEMPLATES_DIR}', rules, {})).toThrow(/NUCLEI_TEMPLATES_DIR.*not set/);
  });

  it('rejects removed tools', () => {
    expect(() => parseRules('version: "2.0"\nglobal_policy: {}\nsast: { default_tool: semgrep }\n')).toThrow(/default_tool/);
    expect(() => parseRules('version: "2.0"\nglobal_policy: {}\ndast: { zap: {} }\n')).toThrow(/zap/);
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
