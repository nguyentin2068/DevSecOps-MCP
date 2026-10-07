import { parseOsv } from '../../src/core/scanners/osv-scanner';
import { parseKatana } from '../../src/core/scanners/katana';
import { nucleiArgs, parseNuclei } from '../../src/core/scanners/nuclei';
import { parseOpengrep } from '../../src/core/scanners/opengrep';
import { parseTrivy } from '../../src/core/scanners/trivy';
import { toSarif } from '../../src/core/sarif';
import { scanResult } from '../helpers';

describe('parseOpengrep', () => {
  it('maps severities, relative paths and metadata', () => {
    const out = parseOpengrep(
      {
        version: '1.179.0',
        results: [
          {
            check_id: 'rules.sql-injection',
            path: '/ws/app/db.js',
            start: { line: 12 },
            extra: { message: 'SQL injection\nmore detail', severity: 'ERROR', metadata: { cwe: 'CWE-89', references: ['https://owasp.org'] } }
          },
          { check_id: 'rules.weak-hash', path: 'lib/hash.py', start: { line: 3 }, extra: { severity: 'WARNING' } },
          { check_id: 'rules.note', path: 'x.js', extra: { severity: 'INFO' } },
          { check_id: 'rules.odd', path: 'y.js', extra: { severity: 'SOMETHING' } }
        ],
        errors: [{ message: 'partial parse' }]
      },
      '/ws'
    );
    expect(out.findings.map((f) => f.severity)).toEqual(['high', 'medium', 'low', 'medium']);
    expect(out.findings[0]).toMatchObject({
      rule_id: 'rules.sql-injection',
      title: 'SQL injection',
      location: { path: 'app/db.js', line: 12 },
      cwe: ['CWE-89'],
      references: ['https://owasp.org']
    });
    expect(out.findings[1]?.title).toBe('weak-hash');
    expect(out.metadata).toMatchObject({ scanner_version: '1.179.0', scanner_errors: ['partial parse'] });
  });
});

describe('parseTrivy', () => {
  const report = {
    ArtifactName: '.',
    Results: [
      {
        Target: 'package-lock.json',
        Type: 'npm',
        Vulnerabilities: [
          { VulnerabilityID: 'CVE-2021-23337', PkgName: 'lodash', InstalledVersion: '4.17.4', FixedVersion: '4.17.21', Severity: 'HIGH', Title: 'Command injection', CweIDs: ['CWE-77'], PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2021-23337' },
          { VulnerabilityID: 'GHSA-xxxx', PkgName: 'ms', InstalledVersion: '2.0.0', Severity: 'UNKNOWN' },
          { VulnerabilityID: 'CVE-2021-23337', PkgName: 'lodash', InstalledVersion: '4.17.4', Severity: 'HIGH' }
        ]
      },
      {
        Target: 'config/.env',
        Class: 'secret',
        Secrets: [{ RuleID: 'aws-access-key-id', Category: 'AWS', Severity: 'CRITICAL', Title: 'AWS Access Key ID', StartLine: 3, Match: 'AKIAIOSFODNN7EXAMPLE', Code: { Lines: [{ Content: 'AKIAIOSFODNN7EXAMPLE' }] } }]
      },
      {
        Target: 'Dockerfile',
        Class: 'config',
        Misconfigurations: [
          { ID: 'DS002', AVDID: 'AVD-DS-0002', Title: 'Image user should not be root', Severity: 'HIGH', Status: 'FAIL', Resolution: 'Add USER', CauseMetadata: { StartLine: 1 } },
          { ID: 'DS001', Title: 'passing check', Severity: 'LOW', Status: 'PASS' }
        ]
      }
    ]
  };

  it('maps vulnerabilities, secrets and failed misconfigurations, deduplicating repeats', () => {
    const out = parseTrivy(report as never);
    expect(out.findings).toHaveLength(4);
    expect(out.findings[0]).toMatchObject({
      rule_id: 'CVE-2021-23337',
      severity: 'high',
      location: { path: 'package-lock.json', package: 'lodash', version: '4.17.4', ecosystem: 'npm' },
      fix: 'Upgrade lodash to 4.17.21',
      cve: ['CVE-2021-23337'],
      cwe: ['CWE-77']
    });
    expect(out.findings[1]?.severity).toBe('medium');
    expect(out.findings[2]).toMatchObject({ rule_id: 'secret:aws-access-key-id', severity: 'critical', location: { path: 'config/.env', line: 3 } });
    expect(out.findings[3]).toMatchObject({ rule_id: 'AVD-DS-0002', severity: 'high', fix: 'Add USER' });
  });

  it('never copies the secret value into the report', () => {
    const serialized = JSON.stringify(parseTrivy(report as never));
    expect(serialized).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });
});

describe('parseOsv', () => {
  it('emits one finding per alias group with CVSS-based severity and fix versions', () => {
    const out = parseOsv(
      {
        results: [
          {
            source: { path: '/ws/package-lock.json', type: 'lockfile' },
            packages: [
              {
                package: { name: 'lodash', version: '4.17.4', ecosystem: 'npm' },
                vulnerabilities: [
                  {
                    id: 'GHSA-35jh-r3h4-6jhm',
                    summary: 'Command Injection in lodash',
                    aliases: ['CVE-2021-23337'],
                    database_specific: { severity: 'HIGH', cwe_ids: ['CWE-77'] },
                    affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }]
                  },
                  { id: 'GHSA-p6mc-m468-83gw', summary: 'Prototype pollution', database_specific: { severity: 'MODERATE' } }
                ],
                groups: [
                  { ids: ['GHSA-35jh-r3h4-6jhm'], aliases: ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm'], max_severity: '9.8' },
                  { ids: ['GHSA-p6mc-m468-83gw'], aliases: [] }
                ]
              }
            ]
          }
        ]
      },
      '/ws'
    );
    expect(out.findings).toHaveLength(2);
    expect(out.findings[0]).toMatchObject({
      rule_id: 'GHSA-35jh-r3h4-6jhm',
      severity: 'critical',
      location: { path: 'package-lock.json', package: 'lodash', version: '4.17.4', ecosystem: 'npm' },
      fix: 'Upgrade lodash to 4.17.21',
      cve: ['CVE-2021-23337'],
      cwe: ['CWE-77']
    });
    expect(out.findings[1]?.severity).toBe('medium');
  });

  it('handles output without groups', () => {
    const out = parseOsv(
      { results: [{ source: { path: 'go.mod' }, packages: [{ package: { name: 'x', version: '1', ecosystem: 'Go' }, vulnerabilities: [{ id: 'GO-1' }] }] }] },
      '/ws'
    );
    expect(out.findings[0]).toMatchObject({ rule_id: 'GO-1', severity: 'medium' });
  });
});

describe('parseNuclei', () => {
  const line = (overrides: Record<string, unknown>) =>
    JSON.stringify({
      'template-id': 'CVE-2021-41773',
      info: {
        name: 'Apache 2.4.49 - Path Traversal',
        severity: 'critical',
        description: 'Path traversal and file disclosure.\n',
        remediation: 'Upgrade to 2.4.51',
        reference: ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773', 'not-a-url'],
        classification: { 'cve-id': ['cve-2021-41773'], 'cwe-id': ['cwe-22'] }
      },
      type: 'http',
      host: 'http://app:8080',
      'matched-at': 'http://app:8080/cgi-bin/.%2e/etc/passwd',
      'extracted-results': ['root:x:0:0'],
      'curl-command': 'curl -H "Authorization: Bearer secret"',
      ...overrides
    });

  it('maps template metadata, normalizes CVE/CWE ids and drops raw evidence', () => {
    const out = parseNuclei(
      [
        line({}),
        line({}),
        line({ 'template-id': 'http-missing-security-headers', 'matcher-name': 'content-security-policy', info: { name: 'Missing headers', severity: 'info' } }),
        line({ 'template-id': 'dast-xss', 'fuzzing_parameter': 'q', 'fuzzing_method': 'get', info: { name: 'Reflected XSS', severity: 'medium' } }),
        line({ 'template-id': 'odd', info: { name: 'Odd', severity: 'unknown' } }),
        'not json',
        ''
      ].join('\n')
    );
    expect(out.findings.map((f) => f.severity)).toEqual(['critical', 'info', 'medium', 'medium']);
    expect(out.findings[0]).toMatchObject({
      rule_id: 'CVE-2021-41773',
      title: 'Apache 2.4.49 - Path Traversal',
      location: { url: 'http://app:8080/cgi-bin/.%2e/etc/passwd', method: 'GET' },
      description: 'Path traversal and file disclosure.',
      fix: 'Upgrade to 2.4.51',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'],
      cve: ['CVE-2021-41773'],
      cwe: ['CWE-22']
    });
    expect(out.findings[1]?.title).toBe('Missing headers [content-security-policy]');
    expect(out.findings[2]?.location).toMatchObject({ parameter: 'q', method: 'GET' });
    expect(out.metadata).toEqual({ malformed_lines: 1 });
    const serialized = JSON.stringify(out);
    expect(serialized).not.toContain('root:x:0:0');
    expect(serialized).not.toContain('Bearer secret');
  });

  it('builds safe arguments: no OAST, no redirects, HTTP templates only, no raw output', () => {
    const base = {
      bin: 'nuclei',
      templates: ['/opt/nuclei-templates'],
      severities: [],
      includeTags: [],
      excludeTags: ['dos', 'intrusive'],
      excludeTemplateIds: [],
      rateLimit: 50,
      concurrency: 10,
      requestTimeoutSeconds: 10,
      timeoutSeconds: 600
    };
    const args = nucleiArgs('/tmp/list.txt', base, false);
    for (const flag of ['-ni', '-dr', '-or', '-ot', '-duc', '-jsonl']) expect(args).toContain(flag);
    expect(args.slice(args.indexOf('-pt'), args.indexOf('-pt') + 2)).toEqual(['-pt', 'http']);
    expect(args.slice(args.indexOf('-etags'), args.indexOf('-etags') + 2)).toEqual(['-etags', 'dos,intrusive']);
    expect(args).not.toContain('-dast');
    expect(args).not.toContain('-code');
    expect(nucleiArgs('/tmp/list.txt', base, true)).toContain('-dast');
    expect(() => nucleiArgs('/tmp/list.txt', { ...base, templates: ['-code'] }, false)).toThrow(/must not start with "-"/);
  });
});

describe('parseKatana', () => {
  it('keeps same-origin GET endpoints only, drops fragments, de-duplicates and caps', () => {
    const target = new URL('http://app.staging:8080/');
    const rec = (endpoint: string, method = 'GET') => JSON.stringify({ request: { method, endpoint } });
    const output = [
      rec('http://app.staging:8080/search?q=1'),
      rec('http://app.staging:8080/search?q=1#top'),
      rec('http://app.staging:8080/login', 'POST'),
      rec('http://evil.example/steal'),
      rec('https://app.staging:8080/other-scheme'),
      rec('http://app.staging:9090/other-port'),
      rec('http://169.254.169.254/latest/meta-data/'),
      'garbage',
      rec('http://app.staging:8080/about')
    ].join('\n');
    expect(parseKatana(output, target, 100)).toEqual([
      'http://app.staging:8080/',
      'http://app.staging:8080/search?q=1',
      'http://app.staging:8080/about'
    ]);
    expect(parseKatana(output, target, 2)).toHaveLength(2);
  });
});

describe('toSarif', () => {
  it('produces a SARIF 2.1.0 run with rules, levels and locations', () => {
    const result = scanResult({
      findings: [
        { id: 'f1', rule_id: 'r1', title: 'Bad thing', severity: 'critical', location: { path: 'a.js', line: 3 }, cwe: ['CWE-1'] },
        { id: 'f2', rule_id: 'r1', title: 'Bad thing', severity: 'low', location: { url: 'http://app/' } }
      ]
    });
    const sarif = toSarif(result) as { version: string; runs: Array<{ tool: { driver: { rules: unknown[] } }; results: Array<Record<string, unknown>> }> };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0]?.results[0]).toMatchObject({
      ruleId: 'r1',
      level: 'error',
      locations: [{ physicalLocation: { artifactLocation: { uri: 'a.js' }, region: { startLine: 3 } } }]
    });
    expect(sarif.runs[0]?.results[1]).toMatchObject({ level: 'note', locations: [{ physicalLocation: { artifactLocation: { uri: 'http://app/' } } }] });
  });
});
