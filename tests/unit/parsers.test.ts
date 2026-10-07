import { parseOsv } from '../../src/core/scanners/osv-scanner';
import { parseSemgrep } from '../../src/core/scanners/semgrep';
import { parseReportTask, parseSonarIssues } from '../../src/core/scanners/sonarqube';
import { parseTrivy } from '../../src/core/scanners/trivy';
import { parseZapAlerts } from '../../src/core/scanners/zap';
import { toSarif } from '../../src/core/sarif';
import { scanResult } from '../helpers';

describe('parseSemgrep', () => {
  it('maps severities, relative paths and metadata', () => {
    const out = parseSemgrep(
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

describe('parseZapAlerts', () => {
  it('maps risk codes, skips false positives and deduplicates instances', () => {
    const alert = { pluginId: '40012', alertRef: '40012', name: 'Cross Site Scripting (Reflected)', riskcode: '3', confidence: 'Medium', url: 'http://app/search?q=x', method: 'GET', param: 'q', solution: 'Encode output', cweid: '79', reference: 'https://owasp.org/xss https://cwe.mitre.org/79' };
    const out = parseZapAlerts([
      alert,
      { ...alert },
      { pluginId: '10038', name: 'CSP Header Not Set', riskcode: '2', confidence: 'High', url: 'http://app/' },
      { pluginId: '10096', name: 'Timestamp Disclosure', riskcode: '0', confidence: 'Low', url: 'http://app/', cweid: '-1' },
      { pluginId: '1', name: 'Dismissed', riskcode: '3', confidence: 'False Positive', url: 'http://app/' }
    ]);
    expect(out.findings.map((f) => f.severity)).toEqual(['high', 'medium', 'info']);
    expect(out.findings[0]).toMatchObject({
      rule_id: '40012',
      location: { url: 'http://app/search?q=x', method: 'GET', parameter: 'q' },
      fix: 'Encode output',
      cwe: ['CWE-79'],
      references: ['https://owasp.org/xss', 'https://cwe.mitre.org/79']
    });
    expect(out.findings[2]?.cwe).toBeUndefined();
    expect(out.metadata).toEqual({ false_positives_skipped: 1 });
  });
});

describe('SonarQube parsing', () => {
  it('prefers security impacts over legacy severities and strips the project prefix', () => {
    const findings = parseSonarIssues(
      [
        { key: 'A1', rule: 'javascript:S2068', severity: 'MAJOR', component: 'my-app:src/db.js', line: 4, message: 'Hard-coded password', impacts: [{ softwareQuality: 'SECURITY', severity: 'BLOCKER' }] },
        { key: 'A2', rule: 'java:S3649', severity: 'CRITICAL', component: 'my-app:Main.java', message: 'SQL injection' }
      ],
      'my-app'
    );
    expect(findings).toEqual([
      { id: 'A1', rule_id: 'javascript:S2068', title: 'Hard-coded password', severity: 'critical', location: { path: 'src/db.js', line: 4 } },
      { id: 'A2', rule_id: 'java:S3649', title: 'SQL injection', severity: 'high', location: { path: 'Main.java', line: 0 } }
    ]);
  });

  it('reads the compute engine task id from report-task.txt', () => {
    expect(parseReportTask('projectKey=x\nceTaskId=AY123\nceTaskUrl=http://s/api/ce/task?id=AY123\n')['ceTaskId']).toBe('AY123');
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
