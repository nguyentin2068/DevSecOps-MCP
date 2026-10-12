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

const semgrepHit = {
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

  const baseEnv = { SCAN_WORKSPACE_ROOTS: workspace, REPORTS_DIR: reports, SECURITY_RULES_PATH: RULES_PATH };
  const appDir = path.join(workspace, 'app');

  it('exits 1 when findings break the policy and stores JSON + SARIF', async () => {
    const env = { ...baseEnv, SEMGREP_PATH: stubScanner(bin, 'semgrep-hit', semgrepHit) };
    const { io, out } = capture();
    const code = await main(['sast', '--target', appDir, '--scan-id', 'sast-cli-hit'], io, env);
    expect(code).toBe(EXIT.POLICY_FAIL);
    expect(out.join('\n')).toMatch(/high=1/);
    expect(out.join('\n')).toMatch(/Policy: FAIL/);
    const stored = JSON.parse(readFileSync(path.join(reports, 'sast-cli-hit', 'result.json'), 'utf8'));
    expect(stored.findings[0].rule_id).toBe('stub.sqli');
    expect(JSON.parse(readFileSync(path.join(reports, 'sast-cli-hit', 'policy.json'), 'utf8')).status).toBe('FAIL');
    // The user-controlled target comes after "--" so it can never be parsed as a flag.
    expect(readFileSync(`${env.SEMGREP_PATH}.args`, 'utf8')).toMatch(new RegExp(`-- ${appDir}\\s*$`));
  });

  it('exits 0 on a clean scan', async () => {
    const env = { ...baseEnv, SEMGREP_PATH: stubScanner(bin, 'semgrep-clean', { results: [], errors: [] }) };
    expect(await main(['sast', '--target', appDir], capture().io, env)).toBe(EXIT.PASS);
  });

  it('exits 0 on a policy failure with --no-fail', async () => {
    const env = { ...baseEnv, SEMGREP_PATH: stubScanner(bin, 'semgrep-nofail', semgrepHit) };
    expect(await main(['sast', '--target', appDir, '--no-fail'], capture().io, env)).toBe(EXIT.PASS);
  });

  it('exits 2 and records a failed scan when the scanner crashes', async () => {
    const env = { ...baseEnv, SEMGREP_PATH: stubScanner(bin, 'semgrep-crash', 'boom', 7) };
    const { io, err } = capture();
    expect(await main(['sast', '--target', appDir, '--scan-id', 'sast-cli-crash'], io, env)).toBe(EXIT.ERROR);
    expect(err.join('\n')).toMatch(/semgrep exited with code 7/);
    expect(JSON.parse(readFileSync(path.join(reports, 'sast-cli-crash', 'result.json'), 'utf8')).status).toBe('failed');
  });

  it('exits 2 when the scanner prints invalid JSON', async () => {
    const env = { ...baseEnv, SEMGREP_PATH: stubScanner(bin, 'semgrep-garbage', 'not json') };
    expect(await main(['sast', '--target', appDir], capture().io, env)).toBe(EXIT.ERROR);
  });

  it('exits 2 for a target outside the workspace without running the scanner', async () => {
    const env = { ...baseEnv, SEMGREP_PATH: path.join(bin, 'does-not-exist') };
    const { io, err } = capture();
    expect(await main(['sast', '--target', '/etc'], io, env)).toBe(EXIT.ERROR);
    expect(err.join('\n')).toMatch(/outside the allowed workspace/);
  });

  it('refuses DAST targets pointing at the metadata service', async () => {
    const { io, err } = capture();
    expect(await main(['dast', '--target', 'http://169.254.169.254/latest/'], io, baseEnv)).toBe(EXIT.ERROR);
    expect(err.join('\n')).toMatch(/blocked address/);
  });

  it('rejects unknown tools, commands and flags', async () => {
    expect(await main(['sast', '--target', appDir, '--tool', 'snyk'], capture().io, baseEnv)).toBe(EXIT.ERROR);
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
    const env = { ...baseEnv, SEMGREP_PATH: stubScanner(bin, 'semgrep-gate', { results: [] }) };
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

let semgrepAvailable = false;
try {
  execFileSync('semgrep', ['--disable-version-check', '--version'], { stdio: 'ignore', timeout: 30000 });
  semgrepAvailable = true;
} catch {
  semgrepAvailable = false;
}

// Real end-to-end run with the bundled offline ruleset; skipped when semgrep is not installed.
(semgrepAvailable ? describe : describe.skip)('devsecops-scan CLI with real semgrep', () => {
  const rules = path.join(tempDir('rules-'), 'rules.yml');
  writeFileSync(
    rules,
    readFileSync(RULES_PATH, 'utf8')
      .replace('- p/security-audit', `- ${path.join(REPO_ROOT, 'src/config/semgrep/baseline.yml')}`)
      .replace(/\s+- p\/secrets/, '')
      .replace(/\s+- p\/owasp-top-ten/, '')
  );
  const env = { SCAN_WORKSPACE_ROOTS: REPO_ROOT, REPORTS_DIR: tempDir('reports-'), SECURITY_RULES_PATH: rules };

  it('fails the gate on the vulnerable samples', async () => {
    const { io, out } = capture();
    expect(await main(['sast', '--target', path.join(REPO_ROOT, 'test-samples')], io, env)).toBe(EXIT.POLICY_FAIL);
    expect(out.join('\n')).toMatch(/Policy: FAIL/);
  }, 120000);

  it('passes on code without findings', async () => {
    expect(await main(['sast', '--target', path.join(REPO_ROOT, 'src', 'core')], capture().io, env)).toBe(EXIT.PASS);
  }, 120000);
});
