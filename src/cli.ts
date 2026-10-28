#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'fs';
import { parseArgs } from 'util';
import Anthropic from '@anthropic-ai/sdk';
import { defaultRulesPath, envSecret, loadRules, resolveConfigPath } from './core/config';
import { correlate } from './core/correlate';
import { DefectDojoClient, ImportsRecord, importToDefectDojo } from './core/defectdojo';
import { triageInDefectDojo } from './core/dojo-triage';
import { resolveWorkspacePath, ValidationError, workspaceRootsFromEnv } from './core/guards';
import { detectLanguages } from './core/languages';
import { errorMessage } from './core/logger';
import { evaluatePolicy, PolicyDecision } from './core/policy';
import { renderReport, ReportFormat } from './core/report';
import { ReportStore } from './core/report-store';
import { readRuleIdKeys } from './core/rule-ids';
import { computeRuleStats, renderRuleStatsMarkdown } from './core/rule-stats';
import { languageDetectOptions, runScan, scannableLanguages } from './core/scan-runner';
import { claudeTriageModel, renderTriageMarkdown, runTriage, TriageReport } from './core/triage';
import { SCAN_TYPES, ScanResult, ScanType } from './core/types';

/** Exit codes: 0 = policy PASS/WARN, 1 = policy FAIL, 2 = scanner/usage/config error. */
export const EXIT = { PASS: 0, POLICY_FAIL: 1, ERROR: 2 } as const;

const USAGE = `Usage:
  devsecops-scan detect --target <dir> [--format list|json] [--out file]
  devsecops-scan <sast|sca|container|dast> --target <path|image|url> [options]
  devsecops-scan gate   --scan-id <id> [--scan-id <id> ...] [options]
  devsecops-scan report --scan-id <id> [--scan-id <id> ...] [--format markdown|json|sarif] [--out file]
  devsecops-scan correlate --scan-id <id> [...] [--out triage.json] [--md triage.md]
  devsecops-scan defectdojo --scan-id <id> [...] --product <name> --engagement <name> [options]
  devsecops-scan triage --scan-id <id> [...] [--defectdojo imports.json] [--out triage.json] [--md triage.md]
  devsecops-scan rule-stats --product <name> [--format markdown|json] [--out file] [--min-reviewed n]

Scan options:
  --target <value>        sast/sca: directory inside the workspace; container: image ref; dast: URL
  --tool <name>           sast: opengrep, sca: osv-scanner|trivy, container: trivy, dast: nuclei
  --scan-id <id>          explicit id ([a-z0-9_-], 3-128 chars); generated when omitted
  --languages <list>      sast: comma-separated languages to scan (from "detect"), "all", or "" for
                          common rules only; omitted = detect them from the target
  --dast-mode <mode>      baseline|full: full adds nuclei's fuzzing (DAST) templates; test environments only
  --no-fail               always exit 0 on a policy FAIL (scanner errors still exit 2)
  --quiet                 do not stream the scanners' own logs to stderr (run them in quiet mode)

Detect options:
  --format <fmt>          list (default): comma-separated languages that have rules, for --languages;
                          json: full detection. A summary table always goes to stderr.
  --out <file>            also write the full detection as JSON to this file

Correlate / triage options (AI triage is advisory and needs ANTHROPIC_API_KEY):
  --out <file>            write the report (JSON)            --md <file>   write a markdown summary
  --defectdojo <file>     triage in DefectDojo: read the imports record written by "defectdojo
                          --imports-out", skip findings people already decided or the AI already
                          triaged, write verdicts back as tags and notes (needs DEFECTDOJO_* too)
  --retriage              DefectDojo mode: triage findings that already have an AI verdict again
  --no-ai                 triage: correlation only (same as "correlate")

DefectDojo options (needs DEFECTDOJO_URL and DEFECTDOJO_API_KEY):
  --product <name>        product (created if missing)      --product-type <name>  default: DevSecOps
  --engagement <name>     engagement (created if missing)   --triage <file>        correlation report: corr-* tags
  --imports-out <file>    record the imported tests (for "triage --defectdojo")
  --branch, --commit, --build-id, --scm-uri <value>         recorded on the imported tests
  rule-stats: --min-reviewed <n> reviewed findings before a rule is called noisy (default 5)

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
        languages: { type: 'string' },
        'no-fail': { type: 'boolean', default: false },
        'no-ai': { type: 'boolean', default: false },
        md: { type: 'string' },
        triage: { type: 'string' },
        defectdojo: { type: 'string' },
        retriage: { type: 'boolean', default: false },
        'imports-out': { type: 'string' },
        'min-reviewed': { type: 'string' },
        product: { type: 'string' },
        'product-type': { type: 'string' },
        engagement: { type: 'string' },
        branch: { type: 'string' },
        commit: { type: 'string' },
        'build-id': { type: 'string' },
        'scm-uri': { type: 'string' },
        quiet: { type: 'boolean', default: false },
        rules: { type: 'string' },
        'reports-dir': { type: 'string' },
        format: { type: 'string' },
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

    if (command === 'detect') {
      if (!values.target) throw new ValidationError('--target is required');
      const format = values.format ?? 'list';
      if (format !== 'list' && format !== 'json') throw new ValidationError('--format must be list or json for detect');
      const target = await resolveWorkspacePath(values.target, workspaceRootsFromEnv(env));
      const detection = await detectLanguages(target, languageDetectOptions(rules));
      const scan = scannableLanguages(detection, rules);
      const report = { target, ...detection, scan_languages: scan };

      io.err(`Languages in ${target} (${detection.files_scanned} files${detection.truncated ? ', walk truncated' : ''}):`);
      if (detection.languages.length === 0) io.err('  none detected');
      for (const { name, files } of detection.languages) {
        io.err(`  ${name.padEnd(12)} ${String(files).padStart(7)} files${scan.includes(name) ? '' : '  (no rules configured, not scanned)'}`);
      }
      io.err(`SAST languages: ${scan.length ? scan.join(',') : 'none (common rules only)'}`);

      if (values.out) writeFileSync(values.out, `${JSON.stringify(report, null, 2)}\n`);
      io.out(format === 'json' ? JSON.stringify(report, null, 2) : scan.join(','));
      return EXIT.PASS;
    }

    if ((SCAN_TYPES as readonly string[]).includes(command)) {
      if (!values.target) throw new ValidationError('--target is required');
      if (scanIds.length > 1) throw new ValidationError('a scan accepts at most one --scan-id');
      if (values.languages !== undefined && command !== 'sast') throw new ValidationError('--languages applies to sast only');
      const languages = values.languages?.split(',').map((language) => language.trim().toLowerCase()).filter(Boolean);
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
          ...(dastMode ? { dastMode } : {}),
          ...(languages ? { languages } : {})
        },
        // Scanner logs go to stderr with a [tool] prefix; stdout keeps only the CLI's own summary.
        { rules, store, env, ...(values.quiet ? {} : { toolLog: io.err }) }
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

      const format = (values.format ?? 'markdown') as ReportFormat;
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

    const dojoClient = (): DefectDojoClient => {
      const baseUrl = env['DEFECTDOJO_URL'];
      const apiKey = envSecret('DEFECTDOJO_API_KEY', env);
      if (!baseUrl || !apiKey) throw new ValidationError('DEFECTDOJO_URL and DEFECTDOJO_API_KEY (or DEFECTDOJO_API_KEY_FILE) are required');
      return new DefectDojoClient({ baseUrl, apiKey });
    };

    if (command === 'triage' || command === 'correlate') {
      if (scanIds.length === 0) throw new ValidationError('at least one --scan-id is required');
      const aiOff = command === 'correlate' || values['no-ai'];
      if (values.defectdojo && aiOff) throw new ValidationError('--defectdojo needs AI triage; drop --no-ai');
      const results: ScanResult[] = [];
      for (const id of scanIds) results.push(await store.get(id));
      const groups = correlate(results);
      const config = rules.triage;

      let model;
      if (!aiOff) {
        const apiKey = envSecret('ANTHROPIC_API_KEY', env);
        if (!apiKey) throw new ValidationError('ANTHROPIC_API_KEY (or ANTHROPIC_API_KEY_FILE) is required for AI triage; pass --no-ai for correlation only');
        model = claudeTriageModel({ model: config.model, effort: config.effort, timeoutSeconds: config.timeout_seconds, client: new Anthropic({ apiKey }) });
      }
      let report: TriageReport;
      if (values.defectdojo && model) {
        const imports = JSON.parse(readFileSync(values.defectdojo, 'utf8')) as ImportsRecord;
        if (imports.schema_version !== 1 || !Array.isArray(imports.imports)) throw new ValidationError(`${values.defectdojo} is not an imports record`);
        const outcome = await triageInDefectDojo(dojoClient(), groups, imports, { model, modelName: config.model, config, scanIds, retriage: values.retriage });
        report = outcome.report;
        const skipped = (status: string) => report.groups.filter((group) => group.triage_status === status).length;
        io.out(
          `DefectDojo: skipped ${skipped('human_decided')} groups decided by people and ${skipped('previously_triaged')} already triaged; ` +
            `tags updated on ${outcome.findings_tagged} findings, ${outcome.notes_added} notes added`
        );
      } else {
        report = await runTriage(groups, { ...(model ? { model, modelName: config.model } : {}), config, scanIds });
      }

      if (values.out) writeFileSync(values.out, `${JSON.stringify(report, null, 2)}\n`);
      if (values.md) writeFileSync(values.md, renderTriageMarkdown(report));
      const s = report.summary;
      io.out(`Correlation: ${s.findings} findings in ${s.groups} groups (${s.correlated_groups} reported more than once)`);
      io.out(
        report.model
          ? `AI triage (${report.model}, advisory): ${s.triaged} triaged - true positive ${s.verdicts.true_positive}, false positive ${s.verdicts.false_positive}, needs review ${s.verdicts.needs_review}; ${s.not_triaged} not triaged`
          : 'AI triage: off (correlation only)'
      );
      for (const error of report.errors) io.err(`Triage error: ${error}`);
      // The report is written either way; exit 2 lets CI mark the stage unstable.
      return report.errors.length ? EXIT.ERROR : EXIT.PASS;
    }

    if (command === 'defectdojo') {
      if (scanIds.length === 0) throw new ValidationError('at least one --scan-id is required');
      if (!values.product || !values.engagement) throw new ValidationError('--product and --engagement are required');
      const client = dojoClient();
      const results: ScanResult[] = [];
      for (const id of scanIds) results.push(await store.get(id));
      let report: TriageReport | undefined;
      if (values.triage) {
        report = JSON.parse(readFileSync(values.triage, 'utf8')) as TriageReport;
        if (report.schema_version !== 1 || !Array.isArray(report.groups)) throw new ValidationError(`${values.triage} is not a triage report`);
      }
      const context = {
        productName: values.product,
        productTypeName: values['product-type'] ?? 'DevSecOps',
        engagementName: values.engagement,
        ...(values.branch ? { branch: values.branch } : {}),
        ...(values.commit ? { commit: values.commit } : {}),
        ...(values['build-id'] ? { buildId: values['build-id'] } : {}),
        ...(values['scm-uri'] ? { scmUri: values['scm-uri'] } : {})
      };
      const outcomes = await importToDefectDojo(client, results, context, report);
      if (values['imports-out']) {
        const record: ImportsRecord = { schema_version: 1, product: context.productName, engagement: context.engagementName, imports: outcomes };
        writeFileSync(values['imports-out'], `${JSON.stringify(record, null, 2)}\n`);
      }
      for (const outcome of outcomes) {
        io.out(
          outcome.status === 'imported'
            ? `DefectDojo: ${outcome.test_title} -> test ${outcome.test_id}: ${outcome.findings} findings, tags updated on ${outcome.tags_updated}`
            : `DefectDojo: ${outcome.test_title} skipped (${outcome.reason})`
        );
      }
      return EXIT.PASS;
    }

    if (command === 'rule-stats') {
      if (!values.product) throw new ValidationError('--product is required');
      const minReviewed = values['min-reviewed'] === undefined ? 5 : Number(values['min-reviewed']);
      if (!Number.isInteger(minReviewed) || minReviewed < 1) throw new ValidationError('--min-reviewed must be a positive integer');
      const format = values.format ?? 'markdown';
      if (format !== 'markdown' && format !== 'json') throw new ValidationError('--format must be markdown or json for rule-stats');
      const findings = await dojoClient().listFindings(`product_name=${encodeURIComponent(values.product)}`);
      const originals = rules.sast.opengrep.rule_ids ? readRuleIdKeys(resolveConfigPath(rules.sast.opengrep.rule_ids, rules, env)) : undefined;
      const stats = computeRuleStats(findings, { minReviewed, ...(originals ? { originals } : {}) });
      const rendered = format === 'json' ? `${JSON.stringify({ product: values.product, findings: findings.length, rules: stats }, null, 2)}\n` : renderRuleStatsMarkdown(values.product, stats, minReviewed);
      if (values.out) {
        writeFileSync(values.out, rendered);
        io.out(`Rule statistics for ${findings.length} findings in ${stats.length} rules written to ${values.out}`);
      } else {
        io.out(rendered);
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
