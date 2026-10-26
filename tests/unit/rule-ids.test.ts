import { execFileSync } from 'child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'fs';
import path from 'path';
import YAML from 'yaml';
import { loadRuleIdCatalog, RULE_ID_PATTERN, RuleIdCatalog } from '../../src/core/rule-ids';
import { parseOpengrep } from '../../src/core/scanners/opengrep';
import { tempDir } from '../helpers';

const CONFIG_DIR = path.join(__dirname, '..', '..', 'src', 'config', 'opengrep');
const GENERATOR = path.join(__dirname, '..', '..', 'tools', 'generate-rule-ids.mjs');

describe('RuleIdCatalog.lookup', () => {
  const catalog = new RuleIdCatalog({
    'sast-python-0006': 'python.django.security.injection.sql.sql-injection-using-raw',
    'sast-python-0007': 'python.flask.security.audit.debug-enabled',
    'sast-javascript-0007': 'javascript.express.security.audit.debug-enabled'
  });

  it('maps a check_id prefixed with the install path of the rules', () => {
    expect(catalog.lookup('opt.opengrep-rules.python.django.security.injection.sql.sql-injection-using-raw')).toBe('sast-python-0006');
    expect(catalog.lookup('home.ci.rules.python.flask.security.audit.debug-enabled')).toBe('sast-python-0007');
  });

  it('maps a check_id relative to a language directory or a unique bare id', () => {
    expect(catalog.lookup('django.security.injection.sql.sql-injection-using-raw')).toBe('sast-python-0006');
    expect(catalog.lookup('sql-injection-using-raw')).toBe('sast-python-0006');
  });

  it('does not guess between rules that share a name', () => {
    expect(catalog.lookup('debug-enabled')).toBeUndefined();
  });

  it("keeps a user's rule that reuses an id in another directory unmapped", () => {
    expect(catalog.lookup('myrules.sql-injection-using-raw')).toBeUndefined();
  });

  it('passes project IDs of the bundled rules through', () => {
    expect(catalog.lookup('app.src.config.opengrep.sast-javascript-0003')).toBe('sast-javascript-0003');
  });
});

describe('parseOpengrep with a rule ID catalog', () => {
  it('reports project IDs, keeps the original id and lists unmapped rules', () => {
    const catalog = new RuleIdCatalog({ 'sast-python-0006': 'python.django.security.injection.sql.sql-injection-using-raw' });
    const output = parseOpengrep(
      {
        results: [
          { check_id: 'opt.opengrep-rules.python.django.security.injection.sql.sql-injection-using-raw', path: 'app.py', start: { line: 4 }, extra: { severity: 'ERROR' } },
          { check_id: 'app.src.config.opengrep.sast-python-0003', path: 'app.py', start: { line: 9 }, extra: { severity: 'ERROR' } },
          { check_id: 'custom.my-rule', path: 'app.py', start: { line: 2 }, extra: { severity: 'WARNING' } }
        ]
      },
      '/workspace',
      catalog
    );
    expect(output.findings.map((f) => [f.rule_id, f.original_rule_id])).toEqual([
      ['sast-python-0006', 'opt.opengrep-rules.python.django.security.injection.sql.sql-injection-using-raw'],
      ['sast-python-0003', 'app.src.config.opengrep.sast-python-0003'],
      ['custom.my-rule', undefined]
    ]);
    expect(output.metadata?.['unmapped_rule_ids']).toEqual(['custom.my-rule']);
  });
});

describe('shipped rule IDs', () => {
  const catalog = JSON.parse(readFileSync(path.join(CONFIG_DIR, 'rule-ids.json'), 'utf8')) as { ids: Record<string, string> };
  const bundled = (YAML.parse(readFileSync(path.join(CONFIG_DIR, 'baseline.yml'), 'utf8')) as { rules: Array<{ id: string; languages: string[] }> }).rules;

  it('loads, and every ID follows sast-<language>-<NNNN>', () => {
    expect(() => loadRuleIdCatalog(path.join(CONFIG_DIR, 'rule-ids.json'))).not.toThrow();
    expect(Object.keys(catalog.ids).length).toBeGreaterThan(1000);
    expect(new Set(Object.values(catalog.ids)).size).toBe(Object.keys(catalog.ids).length);
  });

  it('bundled rules have unique project IDs that match their language and do not collide with the catalog', () => {
    const ids = bundled.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const rule of bundled) {
      expect(rule.id).toMatch(RULE_ID_PATTERN);
      expect(catalog.ids[rule.id]).toBeUndefined();
      const language = rule.id.replace(/^sast-|-\d+$/g, '');
      expect(rule.languages[0]).toBe(language);
    }
  });
});

describe('tools/generate-rule-ids.mjs', () => {
  function rulesDir(files: Record<string, string[]>): string {
    const dir = tempDir('ogr-');
    for (const [file, ids] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
      writeFileSync(path.join(dir, file), YAML.stringify({ rules: ids.map((id) => ({ id })) }));
    }
    return dir;
  }
  const run = (args: string[]) => execFileSync(process.execPath, [GENERATOR, ...args], { stdio: 'pipe' });

  it('numbers per language after the bundled rules and keeps existing IDs when rules are added', () => {
    const out = path.join(tempDir('cat-'), 'rule-ids.json');
    const baseline = path.join(tempDir('base-'), 'baseline.yml');
    writeFileSync(baseline, YAML.stringify({ rules: [{ id: 'sast-python-0001' }, { id: 'sast-python-0002' }] }));

    const first = rulesDir({ 'python/flask/a.yaml': ['b-rule', 'a-rule'], 'go/x.yml': ['g'], 'python/flask/a.test.yaml': ['fixture'] });
    run(['--rules-dir', first, '--out', out, '--baseline', baseline]);
    expect(JSON.parse(readFileSync(out, 'utf8')).ids).toEqual({
      'sast-go-0001': 'go.g',
      'sast-python-0003': 'python.flask.a-rule',
      'sast-python-0004': 'python.flask.b-rule'
    });

    // A new rule sorts before the others but gets the next number; nothing is renumbered.
    const second = rulesDir({ 'python/flask/a.yaml': ['b-rule', 'a-rule', '0-new'], 'go/x.yml': ['g'] });
    expect(() => run(['--rules-dir', second, '--out', out, '--baseline', baseline, '--check'])).toThrow();
    run(['--rules-dir', second, '--out', out, '--baseline', baseline]);
    const ids = JSON.parse(readFileSync(out, 'utf8')).ids;
    expect(ids['sast-python-0003']).toBe('python.flask.a-rule');
    expect(ids['sast-python-0005']).toBe('python.flask.0-new');
    run(['--rules-dir', second, '--out', out, '--baseline', baseline, '--check']);
  });
});
