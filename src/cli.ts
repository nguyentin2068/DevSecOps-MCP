#!/usr/bin/env node
import { writeFileSync } from 'fs';
import { parseArgs } from 'util';
import { defaultRulesPath, loadRules } from './core/config';
import { ValidationError } from './core/guards';
import { errorMessage } from './core/logger';
import { evaluatePolicy, PolicyDecision } from './core/policy';
import { renderReport, ReportFormat } from './core/report';
import { ReportStore } from './core/report-store';
import { runScan } from './core/scan-runner';
import { SCAN_TYPES, ScanResult, ScanType } from './core/types';

/** Exit codes: 0 = policy PASS/WARN, 1 = policy FAIL, 2 = scanner/usage/config error. */
export const EXIT = { PASS: 0, POLICY_FAIL: 1, ERROR: 2 } as const;

const USAGE = `Usage:
  devsecops-scan <sast|sca|container|dast> --target <path|image|url> [options]
  devsecops-scan gate   --scan-id <id> [--scan-id <id> ...] [options]
  devsecops-scan report --scan-id <id> [--scan-id <id> ...] [--format markdown|json|sarif] [--out file]

Scan options:
  --target <value>        sast/sca: directory inside the workspace; container: image ref; dast: URL
  --tool <name>           sast: opengrep, sca: osv-scanner|trivy, container: trivy, dast: nuclei
  --scan-id <id>          explicit id ([a-z0-9_-], 3-128 chars); generated when omitted
  --dast-mode <mode>      baseline|full: full adds nuclei's fuzzing (DAST) templates; test environments only
  --no-fail               always exit 0 on a policy FAIL (scanner errors still exit 2)

Common options:
  --rules <file>          policy file (default: $SECURITY_RULES_PATH or src/config/security-rules.yml)
  --reports-dir <dir>     results directory (default: $REPORTS_DIR or ./security-reports)

Exit codes: 0 pass/warn, 1 policy fail, 2 scanner, usage or configuration error.`;

interface Io {
  out: (text: string) => void;
  err: (text: string) => void;
}

const defaultIo: Io = {
  out: (text) => process.stdout.write(`${text}\n`),
  err: (text) => process.stderr.write(`${text}\n`)
};

function printDecision(io: Io, decision: PolicyDecision): void {
  io.out(`Policy: ${decision.status} (enforcement: ${decision.enforcement_level})`);
  for (const reason of decision.reasons) io.out(`  - ${reason}`);
}

function decisionExit(decision: PolicyDecision, noFail: boolean): number {
  return decision.status === 'FAIL' && !noFail ? EXIT.POLICY_FAIL : EXIT.PASS;
}

export async function main(argv: string[], io: Io = defaultIo, env: NodeJS.ProcessEnv = process.env): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        target: { type: 'string' },
        tool: { type: 'string' },
        'scan-id': { type: 'string', multiple: true },
        'dast-mode': { type: 'string' },
        'no-fail': { type: 'boolean', default: false },
        rules: { type: 'string' },
        'reports-dir': { type: 'string' },
        format: { type: 'string', default: 'markdown' },
        out: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false }
      }
    });
  } catch (error) {
    io.err(`${errorMessage(error)}\n\n${USAGE}`);
    return EXIT.ERROR;
  }

  const { values, positionals } = parsed;
  const command = positionals[0];
  if (values.help || !command) {
    io.err(USAGE);
    return values.help ? EXIT.PASS : EXIT.ERROR;
  }

  try {
    const rules = loadRules(values.rules ?? defaultRulesPath(env));
    const store = values['reports-dir'] ? new ReportStore(values['reports-dir']) : ReportStore.fromEnv(env);
    const scanIds = values['scan-id'] ?? [];

    if ((SCAN_TYPES as readonly string[]).includes(command)) {
      if (!values.target) throw new ValidationError('--target is required');
      if (scanIds.length > 1) throw new ValidationError('a scan accepts at most one --scan-id');
      const dastMode = values['dast-mode'];
      if (dastMode !== undefined && dastMode !== 'baseline' && dastMode !== 'full') {
        throw new ValidationError('--dast-mode must be baseline or full');
      }

      const outcome = await runScan(
        {
          scanType: command as ScanType,
          target: values.target,
          ...(values.tool ? { tool: values.tool } : {}),
          ...(scanIds[0] ? { scanId: scanIds[0] } : {}),
          ...(dastMode ? { dastMode } : {})
        },
        { rules, store, env }
      );

      const { result, decision, reportDir } = outcome;
      const s = result.summary;
      io.out(`Scan ${result.scan_id} (${result.scan_type}/${result.tool}): ${result.status}`);
      io.out(`  critical=${s.critical} high=${s.high} medium=${s.medium} low=${s.low} info=${s.info} total=${s.total}`);
      io.out(`  results: ${reportDir}`);
      printDecision(io, decision);

      if (result.status === 'failed') {
        io.err(`Scanner error: ${result.error}`);
        return EXIT.ERROR;
      }
      return decisionExit(decision, values['no-fail']);
    }

    if (command === 'gate' || command === 'report') {
      if (scanIds.length === 0) throw new ValidationError('at least one --scan-id is required');
      const results: ScanResult[] = [];
      for (const id of scanIds) results.push(await store.get(id));
      const decision = evaluatePolicy(results, rules);

      if (command === 'gate') {
        printDecision(io, decision);
        return decisionExit(decision, values['no-fail']);
      }

      const format = values.format as ReportFormat;
      if (!['markdown', 'json', 'sarif'].includes(format)) throw new ValidationError('--format must be markdown, json or sarif');
      const report = renderReport(results, decision, format);
      if (values.out) {
        writeFileSync(values.out, report);
        io.out(`Report written to ${values.out}`);
      } else {
        io.out(report);
      }
      return EXIT.PASS;
    }

    throw new ValidationError(`Unknown command: ${command}`);
  } catch (error) {
    io.err(`Error: ${errorMessage(error)}`);
    if (error instanceof ValidationError && /Unknown command|required|must be/.test(error.message)) io.err(`\n${USAGE}`);
    return EXIT.ERROR;
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      process.stderr.write(`Fatal: ${errorMessage(error)}\n`);
      process.exitCode = EXIT.ERROR;
    }
  );
}
