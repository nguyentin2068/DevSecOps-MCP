import { Finding, ScanResult, Severity } from './types';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note'
};

// GitHub/Jenkins-compatible numeric "security-severity" (CVSS-like) per bucket.
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '2.0',
  info: '0.0'
};

function artifactUri(finding: Finding): string | undefined {
  return finding.location.path || finding.location.url || undefined;
}

function message(finding: Finding): string {
  const pkg = finding.location.package
    ? ` (${finding.location.package}${finding.location.version ? `@${finding.location.version}` : ''})`
    : '';
  return `${finding.title}${pkg}${finding.fix ? `. Fix: ${finding.fix}` : ''}`;
}

/** Convert a normalized scan result to SARIF 2.1.0 so Jenkins (Warnings NG) and IDEs can render it. */
export function toSarif(result: ScanResult): Record<string, unknown> {
  const rules = new Map<string, Record<string, unknown>>();
  for (const finding of result.findings) {
    if (rules.has(finding.rule_id)) continue;
    rules.set(finding.rule_id, {
      id: finding.rule_id,
      name: finding.rule_id,
      shortDescription: { text: finding.title.slice(0, 1024) },
      ...(finding.description ? { fullDescription: { text: finding.description.slice(0, 4096) } } : {}),
      ...(finding.references?.[0] ? { helpUri: finding.references[0] } : {}),
      properties: {
        'security-severity': SECURITY_SEVERITY[finding.severity],
        tags: ['security', result.scan_type, ...(finding.cwe ?? [])]
      }
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: result.tool, informationUri: 'https://github.com/nguyentin2068/DevSecOps-MCP', rules: Array.from(rules.values()) } },
        invocations: [
          {
            executionSuccessful: result.status === 'completed',
            ...(result.error ? { toolExecutionNotifications: [{ level: 'error', message: { text: result.error } }] } : {})
          }
        ],
        automationDetails: { id: `${result.scan_type}/${result.scan_id}` },
        results: result.findings.map((finding) => {
          const uri = artifactUri(finding);
          return {
            ruleId: finding.rule_id,
            level: LEVEL[finding.severity],
            message: { text: message(finding) },
            partialFingerprints: { findingId: finding.id },
            properties: { severity: finding.severity, ...(finding.cve ? { cve: finding.cve } : {}) },
            ...(uri
              ? {
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: { uri },
                        ...(finding.location.line && finding.location.line > 0
                          ? { region: { startLine: finding.location.line } }
                          : {})
                      }
                    }
                  ]
                }
              : {})
          };
        })
      }
    ]
  };
}
