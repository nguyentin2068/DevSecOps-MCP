import { execFileSync } from 'child_process';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import path from 'path';
import { EXIT, main } from '../../src/cli';
import { RULES_PATH, tempDir } from '../helpers';

const REPO_ROOT = path.join(__dirname, '..', '..');

/** Write an executable stub that prints a fixed stdout and exits with a given code. */
function stubScanner(dir: string, name: string, stdout: unknown, code = 0): string {
  const file = path.join(dir, name);
  const payload = path.join(dir, `${name}.json`);
  writeFileSync(payload, typeof stdout === 'string' ? stdout : JSON.stringify(stdout));
  writeFileSync(file, `#!/bin/sh\necho "$@" > "${file}.args"\ncat "${payload}"\nexit ${code}\n`);
  chmodSync(file, 0o755);
  return file;
}

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (t: string) => out.push(t), err: (t: string) => err.push(t) }, out, err };
}

const opengrepHit = {
  version: 'stub',
  results: [{ check_id: 'stub.sqli', path: 'app.js', start: { line: 1 }, extra: { message: 'SQL injection', severity: 'ERROR' } }],
  errors: []
};

describe('devsecops-scan CLI', () => {
  const workspace = tempDir('ws-');
  const reports = tempDir('reports-');
  const bin = tempDir('bin-');
  mkdirSync(path.join(workspace, 'app'));
  writeFileSync(path.join(workspace, 'app', 'app.js'), 'db.query("x" + y)');

  const baseEnv = { SCAN_WORKSPACE_ROOTS: workspace, REPORTS_DIR: reports, SECURITY_RULES_PATH: RULES_PATH, OPENGREP_RULES_DIR: '/opt/opengrep-rules' };
  const appDir = path.join(workspace, 'app');

  it('exits 1 when findings break the policy and stores JSON + SARIF', async () => {
    const env = { ...baseEnv, OPENGREP_PATH: stubScanner(bin, 'opengrep-hit', opengrepHit) };
    const { io, out } = capture();
    const code = await main(['sast', '--target', appDir, '--scan-id', 'sast-cli-hit'], io, env);
    expect(code).toBe(EXIT.POLICY_FAIL);
    expect(out.join('\n')).toMatch(/high=1/);
    expect(out.join('\n')).toMatch(/Policy: FAIL/);
    const stored = JSON.parse(readFileSync(path.join(reports, 'sast-cli-hit', 'result.json'), 'utf8'));
    expect(stored.findings[0].rule_id).toBe('stub.sqli');
    expect(JSON.parse(readFileSync(path.join(reports, 'sast-cli-hit', 'policy.json'), 'utf8')).status).toBe('FAIL');
    // The user-controlled target comes after "--" so it can never be parsed as a flag.
    expect(readFileSync(`${env.OPENGREP_PATH}.args`, 'utf8')).toMatch(new RegExp(`-- ${appDir}\\s*$`));
  });

  it('exits 0 on a clean scan', async () => {
    const env = { ...baseEnv, OPENGREP_PATH: stubScanner(bin, 'opengrep-clean', { results: [], errors: [] }) };
    expect(await main(['sast', '--target', appDir], capture().io, env)).toBe(EXIT.PASS);
  });

  it('exits 0 on a policy failure with --no-fail', async () => {
    const env = { ...baseEnv, OPENGREP_PATH: stubScanner(bin, 'opengrep-nofail', opengrepHit) };
    expect(await main(['sast', '--target', appDir, '--no-fail'], capture().io, env)).toBe(EXIT.PASS);
  });

  it('exits 2 and records a failed scan when the scanner crashes', async () => {
    const env = { ...baseEnv, OPENGREP_PATH: stubScanner(bin, 'opengrep-crash', 'boom', 7) };
    const { io, err } = capture();
    expect(await main(['sast', '--target', appDir, '--scan-id', 'sast-cli-crash'], io, env)).toBe(EXIT.ERROR);
    expect(err.join('\n')).toMatch(/opengrep exited with code 7/);
    expect(JSON.parse(readFileSync(path.join(reports, 'sast-cli-crash', 'result.json'), 'utf8')).status).toBe('failed');
  });

  it('streams the scanner log to stderr with a [tool] prefix and control characters removed', async () => {
    const file = path.join(bin, 'opengrep-log');
    writeFileSync(`${file}.json`, JSON.stringify({ results: [], errors: [] }));
    writeFileSync(file, `#!/bin/sh\necho "$@" > "${file}.args"\nprintf 'Scanning 3 files\\n\\033[31mred\\033[0m line\\r\\nprogress 50%%\\rprogress 100%%\\n' >&2\ncat "${file}.json"\n`);
    chmodSync(file, 0o755);
    const { io, out, err } = capture();
    expect(await main(['sast', '--target', appDir], io, { ...baseEnv, OPENGREP_PATH: file })).toBe(EXIT.PASS);

    expect(err).toContainEqual(expect.stringMatching(/^\[opengrep-log\] \$ .*opengrep-log scan --json /));
    expect(err).toEqual(expect.arrayContaining([
      '[opengrep-log] Scanning 3 files',
      '[opengrep-log] red line',
      '[opengrep-log] progress 50%',
      '[opengrep-log] progress 100%'
    ]));
    expect(err.join('\n')).toMatch(/\[opengrep-log\] exited with 0 after \d+\.\ds/);
    expect(err.join('\n')).not.toContain('\u001b');
    // With logs on, the scanner's own quiet mode is off; stdout keeps only the summary.
    expect(readFileSync(`${file}.args`, 'utf8')).not.toMatch(/--quiet/);
    expect(out.join('\n')).not.toMatch(/Scanning 3 files/);
  });

  it('keeps the scanners quiet and prints no tool log with --quiet', async () => {
    const env = { ...baseEnv, OPENGREP_PATH: stubScanner(bin, 'opengrep-quiet', { results: [], errors: [] }) };
    const { io, err } = capture();
    expect(await main(['sast', '--target', appDir, '--quiet'], io, env)).toBe(EXIT.PASS);
    expect(err).toEqual([]);
    expect(readFileSync(`${env.OPENGREP_PATH}.args`, 'utf8')).toMatch(/--quiet/);
  });

  it('reports the last stderr line of a failing scanner even after a long log', async () => {
    const file = path.join(bin, 'opengrep-noisy');
    writeFileSync(file, `#!/bin/sh\ni=0\nwhile [ $i -lt 2000 ]; do echo "progress line $i ................................" >&2; i=$((i+1)); done\necho "fatal: rule file is invalid" >&2\nexit 7\n`);
    chmodSync(file, 0o755);
    const { io, err } = capture();
    expect(await main(['sast', '--target', appDir, '--quiet'], io, { ...baseEnv, OPENGREP_PATH: file })).toBe(EXIT.ERROR);
    expect(err.join('\n')).toMatch(/opengrep exited with code 7: [\s\S]*fatal: rule file is invalid/);
  });

  describe('language detection', () => {
    const polyglot = tempDir('ws-poly-');
    const polyEnv = { ...baseEnv, SCAN_WORKSPACE_ROOTS: polyglot };
    mkdirSync(path.join(polyglot, 'api'));
    mkdirSync(path.join(polyglot, 'node_modules', 'dep'), { recursive: true });
    writeFileSync(path.join(polyglot, 'api', 'app.py'), 'print(1)');
    writeFileSync(path.join(polyglot, 'api', 'util.py'), 'x = 1');
    writeFileSync(path.join(polyglot, 'web.ts'), 'export {}');
    writeFileSync(path.join(polyglot, 'Dockerfile'), 'FROM scratch');
    writeFileSync(path.join(polyglot, 'notes.txt'), 'not code');
    writeFileSync(path.join(polyglot, 'node_modules', 'dep', 'index.js'), 'module.exports = 1');

    it('detect prints the languages that have rules on stdout and a table on stderr', async () => {
      const out = path.join(tempDir('detect-'), 'languages.json');
      const { io, out: stdout, err } = capture();
      expect(await main(['detect', '--target', polyglot, '--out', out], io, polyEnv)).toBe(EXIT.PASS);
      // node_modules is in sast.opengrep.exclude, so its JavaScript is not counted.
      expect(stdout).toEqual(['dockerfile,python,typescript']);
      expect(err.join('\n')).toMatch(/python\s+2 files/);
      const report = JSON.parse(readFileSync(out, 'utf8'));
      expect(report.languages[0]).toEqual({ name: 'python', files: 2 });
      expect(report.scan_languages).toEqual(['dockerfile', 'python', 'typescript']);
    });

    it('detect lists a language without rules in the table but not on stdout', async () => {
      const rules = path.join(tempDir('rules-'), 'rules.yml');
      writeFileSync(rules, readFileSync(RULES_PATH, 'utf8').replace(/^ {6}python: .*\n/m, ''));
      const { io, out, err } = capture();
      expect(await main(['detect', '--target', polyglot, '--rules', rules], io, polyEnv)).toBe(EXIT.PASS);
      expect(out).toEqual(['dockerfile,typescript']);
      expect(err.join('\n')).toMatch(/python .*no rules configured/);
    });

    it('sast --languages runs only the common configs plus those languages', async () => {
      const env = { ...polyEnv, OPENGREP_PATH: stubScanner(bin, 'opengrep-lang', { results: [], errors: [] }) };
      expect(await main(['sast', '--target', polyglot, '--languages', 'python', '--scan-id', 'sast-lang-py', '--quiet'], capture().io, env)).toBe(EXIT.PASS);
      const args = readFileSync(`${env.OPENGREP_PATH}.args`, 'utf8');
      expect(args).toMatch(/--config \/opt\/opengrep-rules\/python /);
      expect(args).toMatch(/--config \/opt\/opengrep-rules\/generic\/secrets /);
      expect(args).not.toMatch(/opengrep-rules\/(typescript|javascript|dockerfile)/);
      expect(JSON.parse(readFileSync(path.join(reports, 'sast-lang-py', 'result.json'), 'utf8')).metadata.languages).toEqual(['python']);
    });

    it('sast detects the languages itself when --languages is omitted', async () => {
      const env = { ...polyEnv, OPENGREP_PATH: stubScanner(bin, 'opengrep-auto', { results: [], errors: [] }) };
      const { io, err } = capture();
      expect(await main(['sast', '--target', polyglot], io, env)).toBe(EXIT.PASS);
      expect(err).toContain('[sast] languages: dockerfile, python, typescript');
      // typescript also pulls in the JavaScript rules; each config is passed once.
      const configs = readFileSync(`${env.OPENGREP_PATH}.args`, 'utf8').match(/--config \S+/g) ?? [];
      expect(configs.filter((c) => c.endsWith('/javascript'))).toHaveLength(1);
      expect(configs).toContain('--config /opt/opengrep-rules/dockerfile');
    });

    it('sast --languages "" runs only the common configs', async () => {
      const env = { ...polyEnv, OPENGREP_PATH: stubScanner(bin, 'opengrep-none', { results: [], errors: [] }) };
      expect(await main(['sast', '--target', polyglot, '--languages', '', '--quiet'], capture().io, env)).toBe(EXIT.PASS);
      const configs = readFileSync(`${env.OPENGREP_PATH}.args`, 'utf8').match(/--config \S+/g) ?? [];
      expect(configs).toHaveLength(2);
    });

    it('refuses an unknown language and --languages on other scan types', async () => {
      const env = { ...polyEnv, OPENGREP_PATH: path.join(bin, 'must-not-run') };
      const { io, err } = capture();
      expect(await main(['sast', '--target', polyglot, '--languages', 'cobol'], io, env)).toBe(EXIT.ERROR);
      expect(err.join('\n')).toMatch(/No rules configured for language\(s\): cobol/);
      expect(await main(['sca', '--target', polyglot, '--languages', 'python'], capture().io, env)).toBe(EXIT.ERROR);
    });
  });

  it('exits 2 when the scanner prints invalid JSON', async () => {
    const env = { ...baseEnv, OPENGREP_PATH: stubScanner(bin, 'opengrep-garbage', 'not json') };
    expect(await main(['sast', '--target', appDir], capture().io, env)).toBe(EXIT.ERROR);
  });

  it('exits 2 for a target outside the workspace without running the scanner', async () => {
    const env = { ...baseEnv, OPENGREP_PATH: path.join(bin, 'does-not-exist') };
    const { io, err } = capture();
    expect(await main(['sast', '--target', '/etc'], io, env)).toBe(EXIT.ERROR);
    expect(err.join('\n')).toMatch(/outside the allowed workspace/);
  });

  it('refuses DAST targets pointing at the metadata service', async () => {
    const { io, err } = capture();
    expect(await main(['dast', '--target', 'http://169.254.169.254/latest/'], io, baseEnv)).toBe(EXIT.ERROR);
    expect(err.join('\n')).toMatch(/blocked address/);
  });

  it('crawls with katana, keeps only same-origin URLs and runs nuclei with safe flags', async () => {
    // Stub nuclei copies its -l list file (argument 2) next to itself before printing results.
    const nucleiFile = path.join(bin, 'nuclei-stub');
    const finding = JSON.stringify({ 'template-id': 'exposed-env', info: { name: '.env exposed', severity: 'high' }, 'matched-at': 'http://127.0.0.1:3001/.env' });
    writeFileSync(`${nucleiFile}.json`, `${finding}\n`);
    writeFileSync(nucleiFile, `#!/bin/sh\necho "$@" >> "${nucleiFile}.args"\ncat "$2" >> "${nucleiFile}.list"\ncat "${nucleiFile}.json"\n`);
    chmodSync(nucleiFile, 0o755);
    const katana = stubScanner(
      bin,
      'katana-stub',
      [
        { request: { method: 'GET', endpoint: 'http://127.0.0.1:3001/search?q=x' } },
        { request: { method: 'GET', endpoint: 'http://169.254.169.254/latest/meta-data/' } }
      ]
        .map((record) => JSON.stringify(record))
        .join('\n')
    );
    const rules = path.join(tempDir('rules-'), 'rules.yml');
    writeFileSync(rules, readFileSync(RULES_PATH, 'utf8').replace('allowed_cidrs: []', 'allowed_cidrs: ["127.0.0.1/32"]'));
    const env = { ...baseEnv, SECURITY_RULES_PATH: rules, KATANA_PATH: katana, NUCLEI_PATH: nucleiFile, NUCLEI_TEMPLATES_DIR: '/opt/nuclei-templates' };

    const { io, out } = capture();
    expect(await main(['dast', '--target', 'http://127.0.0.1:3001/', '--dast-mode', 'full', '--scan-id', 'dast-cli-stub'], io, env)).toBe(EXIT.POLICY_FAIL);
    expect(out.join('\n')).toMatch(/high=1/);

    // Pass 1 (templates) gets the base URL; pass 2 (fuzzing) gets the crawled URL with parameters.
    expect(readFileSync(`${nucleiFile}.list`, 'utf8')).toBe('http://127.0.0.1:3001/\nhttp://127.0.0.1:3001/search?q=x\n');
    const calls = readFileSync(`${nucleiFile}.args`, 'utf8').trim().split('\n');
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatch(/ -ni /);
    expect(calls[0]).toMatch(/ -dr /);
    expect(calls[0]).toMatch(/-t \/opt\/nuclei-templates/);
    expect(calls[1]).toMatch(/ -dast/);
    expect(readFileSync(`${katana}.args`, 'utf8')).toMatch(/-fs fqdn .*-u http:\/\/127\.0\.0\.1:3001\//);
  });

  it('runs only the template pass on the base URL in baseline mode (no crawl, no fuzzing)', async () => {
    const nucleiFile = path.join(bin, 'nuclei-baseline');
    writeFileSync(nucleiFile, `#!/bin/sh\necho "$@" >> "${nucleiFile}.args"\ncat "$2" >> "${nucleiFile}.list"\n`);
    chmodSync(nucleiFile, 0o755);
    const rules = path.join(tempDir('rules-'), 'rules.yml');
    writeFileSync(rules, readFileSync(RULES_PATH, 'utf8').replace('allowed_cidrs: []', 'allowed_cidrs: ["127.0.0.1/32"]'));
    const env = {
      ...baseEnv,
      SECURITY_RULES_PATH: rules,
      KATANA_PATH: path.join(bin, 'katana-must-not-run'),
      NUCLEI_PATH: nucleiFile,
      NUCLEI_TEMPLATES_DIR: '/opt/nuclei-templates'
    };
    expect(await main(['dast', '--target', 'http://127.0.0.1:3001/app'], capture().io, env)).toBe(EXIT.PASS);
    expect(readFileSync(`${nucleiFile}.list`, 'utf8')).toBe('http://127.0.0.1:3001/app\n');
    expect(readFileSync(`${nucleiFile}.args`, 'utf8')).not.toMatch(/-dast/);
  });

  it('fails clearly when the template directory variable is not set', async () => {
    const rules = path.join(tempDir('rules-'), 'rules.yml');
    writeFileSync(rules, readFileSync(RULES_PATH, 'utf8').replace('allowed_cidrs: []', 'allowed_cidrs: ["127.0.0.1/32"]'));
    const { io, err } = capture();
    expect(await main(['dast', '--target', 'http://127.0.0.1:3001/'], io, { ...baseEnv, SECURITY_RULES_PATH: rules })).toBe(EXIT.ERROR);
    expect(err.join('\n')).toMatch(/NUCLEI_TEMPLATES_DIR.*not set/);
  });

  it('rejects unknown tools, commands and flags', async () => {
    expect(await main(['sast', '--target', appDir, '--tool', 'semgrep'], capture().io, baseEnv)).toBe(EXIT.ERROR);
    expect(await main(['dast', '--target', 'http://example.com/', '--tool', 'zap'], capture().io, baseEnv)).toBe(EXIT.ERROR);
    expect(await main(['iast', '--target', appDir], capture().io, baseEnv)).toBe(EXIT.ERROR);
    expect(await main(['sast', '--bogus'], capture().io, baseEnv)).toBe(EXIT.ERROR);
  });

  it('runs trivy for sca with the target after "--"', async () => {
    const trivy = stubScanner(bin, 'trivy-hit', {
      Results: [{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [{ VulnerabilityID: 'CVE-1', PkgName: 'x', InstalledVersion: '1', Severity: 'CRITICAL' }] }]
    });
    const env = { ...baseEnv, TRIVY_PATH: trivy };
    expect(await main(['sca', '--tool', 'trivy', '--target', appDir], capture().io, env)).toBe(EXIT.POLICY_FAIL);
    expect(readFileSync(`${trivy}.args`, 'utf8')).toMatch(/^fs --format json .*-- /);
  });

  it('treats osv-scanner exit 128 (no lockfiles) as a clean scan', async () => {
    const env = { ...baseEnv, OSV_SCANNER_PATH: stubScanner(bin, 'osv-empty', '', 128) };
    expect(await main(['sca', '--target', appDir], capture().io, env)).toBe(EXIT.PASS);
  });

  it('gates and reports across several stored scans', async () => {
    const env = { ...baseEnv, OPENGREP_PATH: stubScanner(bin, 'opengrep-gate', { results: [] }) };
    await main(['sast', '--target', appDir, '--scan-id', 'sast-cli-clean'], capture().io, env);

    expect(await main(['gate', '--scan-id', 'sast-cli-clean'], capture().io, baseEnv)).toBe(EXIT.PASS);
    const gate = capture();
    expect(await main(['gate', '--scan-id', 'sast-cli-clean', '--scan-id', 'sast-cli-hit'], gate.io, baseEnv)).toBe(EXIT.POLICY_FAIL);
    expect(gate.out.join('\n')).toMatch(/sast-cli-hit\] high: 1/);

    const report = capture();
    expect(await main(['report', '--scan-id', 'sast-cli-hit', '--format', 'markdown'], report.io, baseEnv)).toBe(EXIT.PASS);
    expect(report.out.join('\n')).toMatch(/# Security Scan Report[\s\S]*stub.sqli/);

    expect(await main(['gate', '--scan-id', '../../etc/passwd'], capture().io, baseEnv)).toBe(EXIT.ERROR);
  });
});

const OPENGREP = process.env['OPENGREP_PATH'] || 'opengrep';
let opengrepAvailable = false;
try {
  execFileSync(OPENGREP, ['--version'], { stdio: 'ignore', timeout: 60000 });
  opengrepAvailable = true;
} catch {
  opengrepAvailable = false;
}

// Real end-to-end run with the bundled offline ruleset; skipped when opengrep is not installed.
(opengrepAvailable ? describe : describe.skip)('devsecops-scan CLI with real opengrep', () => {
  const rules = path.join(tempDir('rules-'), 'rules.yml');
  writeFileSync(
    rules,
    readFileSync(RULES_PATH, 'utf8')
      .replace('- opengrep/baseline.yml', `- ${path.join(REPO_ROOT, 'src/config/opengrep/baseline.yml')}`)
      .replace(/\s+- \$\{OPENGREP_RULES_DIR\}\/[a-z/]+/g, '')
  );
  const env = { SCAN_WORKSPACE_ROOTS: REPO_ROOT, REPORTS_DIR: tempDir('reports-'), SECURITY_RULES_PATH: rules, OPENGREP_PATH: OPENGREP };

  it('fails the gate on the vulnerable samples', async () => {
    const { io, out } = capture();
    expect(await main(['sast', '--target', path.join(REPO_ROOT, 'test-samples')], io, env)).toBe(EXIT.POLICY_FAIL);
    expect(out.join('\n')).toMatch(/Policy: FAIL/);
  }, 120000);

  it('passes on code without findings', async () => {
    expect(await main(['sast', '--target', path.join(REPO_ROOT, 'src', 'core')], capture().io, env)).toBe(EXIT.PASS);
  }, 120000);
});

describe('devsecops-scan triage and defectdojo', () => {
  const reports = tempDir('reports-triage-');
  const out = tempDir('triage-out-');
  const env = { REPORTS_DIR: reports, SECURITY_RULES_PATH: RULES_PATH, SCAN_WORKSPACE_ROOTS: out };
  const dep = { rule_id: 'CVE-2021-23337', title: 'lodash', severity: 'high', location: { package: 'lodash', version: '4.17.4' }, cve: ['CVE-2021-23337'] };

  beforeAll(() => {
    for (const [scanId, tool] of [['sca-osv-cli-1', 'osv-scanner'], ['sca-trivy-cli-1', 'trivy']] as const) {
      mkdirSync(path.join(reports, scanId));
      const findings = [{ ...dep, id: `${tool}-lodash` }];
      const result = { schema_version: 1, scan_id: scanId, scan_type: 'sca', tool, status: 'completed', target: out, started_at: '2026-01-01T00:00:00Z', finished_at: '2026-01-01T00:01:00Z', duration_ms: 1, summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 }, findings, metadata: {} };
      writeFileSync(path.join(reports, scanId, 'result.json'), JSON.stringify(result));
    }
  });

  it('correlates without AI and writes the JSON and markdown reports', async () => {
    const { io, out: stdout } = capture();
    const json = path.join(out, 'triage.json');
    const md = path.join(out, 'triage.md');
    expect(await main(['triage', '--scan-id', 'sca-osv-cli-1', '--scan-id', 'sca-trivy-cli-1', '--no-ai', '--out', json, '--md', md], io, env)).toBe(EXIT.PASS);
    expect(stdout.join('\n')).toMatch(/2 findings in 1 groups \(1 reported more than once\)/);
    const report = JSON.parse(readFileSync(json, 'utf8'));
    expect(report.model).toBeNull();
    expect(report.groups[0].tools).toEqual(['osv-scanner', 'trivy']);
    expect(readFileSync(md, 'utf8')).toMatch(/^# Correlation and AI triage/);
  });

  it('requires an API key for AI triage, and DefectDojo settings for the import', async () => {
    const { io, err } = capture();
    expect(await main(['triage', '--scan-id', 'sca-osv-cli-1'], io, env)).toBe(EXIT.ERROR);
    expect(err.join('\n')).toMatch(/ANTHROPIC_API_KEY .*--no-ai/);

    const dd = capture();
    expect(await main(['defectdojo', '--scan-id', 'sca-osv-cli-1', '--product', 'p', '--engagement', 'e'], dd.io, env)).toBe(EXIT.ERROR);
    expect(dd.err.join('\n')).toMatch(/DEFECTDOJO_URL and DEFECTDOJO_API_KEY/);
    const missing = capture();
    expect(await main(['defectdojo', '--scan-id', 'sca-osv-cli-1'], missing.io, { ...env, DEFECTDOJO_URL: 'https://dojo.example.com', DEFECTDOJO_API_KEY: 'k' })).toBe(EXIT.ERROR);
    expect(missing.err.join('\n')).toMatch(/--product and --engagement are required/);
  });
});
