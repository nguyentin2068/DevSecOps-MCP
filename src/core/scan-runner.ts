import { resolveConfigPath, SecurityRules } from './config';
import {
  assertSafeDastTarget,
  resolveWorkspacePath,
  Resolver,
  validateImageRef,
  ValidationError,
  workspaceRootsFromEnv
} from './guards';
import { detectLanguages, LanguageDetection } from './languages';
import { errorMessage, logger } from './logger';
import { evaluatePolicy, PolicyDecision } from './policy';
import { ToolLog } from './process';
import { assertScanId, newScanId, ReportStore } from './report-store';
import { runKatana } from './scanners/katana';
import { runNuclei } from './scanners/nuclei';
import { runOpengrep } from './scanners/opengrep';
import { runOsvScanner } from './scanners/osv-scanner';
import { runTrivyFilesystem, runTrivyImage } from './scanners/trivy';
import { emptySummary, ScannerOutput, ScanResult, ScanType, summarize, TOOLS_BY_SCAN_TYPE } from './types';

/** Registry references (p/..., r/..., s/...) and URLs are passed to Opengrep unchanged. */
const REGISTRY_CONFIG = /^(?:[prs]\/|https?:\/\/)/;

export interface ScanRequest {
  scanType: ScanType;
  target: string;
  tool?: string;
  scanId?: string;
  /** Overrides dast.mode from the rules (full adds the nuclei fuzzing pass). */
  dastMode?: 'baseline' | 'full';
  /**
   * sast only: languages whose rule sets (sast.opengrep.language_configs) to run, or ['all'].
   * Omitted = detect them from the target's files. An empty list runs only the common configs.
   */
  languages?: string[];
}

export interface ScanContext {
  rules: SecurityRules;
  store: ReportStore;
  env?: NodeJS.ProcessEnv;
  workspaceRoots?: string[];
  resolver?: Resolver;
  /** Receives the scanners' own logs line by line; omitted = scanners run in their quiet modes. */
  toolLog?: ToolLog;
}

export interface ScanOutcome {
  result: ScanResult;
  decision: PolicyDecision;
  reportDir: string;
}

function resolveTool(request: ScanRequest, rules: SecurityRules): string {
  const tool = request.tool ?? rules[request.scanType].default_tool;
  if (!TOOLS_BY_SCAN_TYPE[request.scanType].includes(tool)) {
    throw new ValidationError(
      `Tool "${tool}" is not supported for ${request.scanType}; use one of: ${TOOLS_BY_SCAN_TYPE[request.scanType].join(', ')}`
    );
  }
  return tool;
}

/** Languages that have rule sets in the policy, in a stable order. */
export function scannableLanguages(detection: LanguageDetection, rules: SecurityRules): string[] {
  return detection.languages.map((language) => language.name).filter((name) => name in rules.sast.opengrep.language_configs).sort();
}

export function languageDetectOptions(rules: SecurityRules): { excludeDirs: string[] } {
  return { excludeDirs: rules.sast.opengrep.exclude };
}

async function sastLanguages(requested: string[] | undefined, target: string, rules: SecurityRules): Promise<string[]> {
  const known = Object.keys(rules.sast.opengrep.language_configs).sort();
  if (requested === undefined) {
    return scannableLanguages(await detectLanguages(target, languageDetectOptions(rules)), rules);
  }
  if (requested.includes('all')) return known;
  const unknown = requested.filter((language) => !known.includes(language));
  if (unknown.length) {
    throw new ValidationError(
      `No rules configured for language(s): ${unknown.join(', ')}. Known: ${known.join(', ') || '(none)'} (sast.opengrep.language_configs)`
    );
  }
  return Array.from(new Set(requested)).sort();
}

/** Validate the target and build the scanner call. Validation errors surface before anything runs. */
async function prepare(request: ScanRequest, tool: string, ctx: ScanContext): Promise<{ target: string; run: () => Promise<ScannerOutput> }> {
  const env = ctx.env ?? process.env;
  const { rules } = ctx;
  const log = ctx.toolLog;

  if (request.scanType === 'dast') {
    const url = await assertSafeDastTarget(request.target, rules.dast.target_policy, ctx.resolver);
    const { crawl, nuclei } = rules.dast;
    const templates = nuclei.templates.map((entry) => resolveConfigPath(entry, rules, env));
    return {
      target: url.toString(),
      run: async () => {
        const mode = request.dastMode ?? rules.dast.mode;
        // full: crawl (same-origin URLs only) to find parameters for the fuzzing pass.
        const crawled =
          mode === 'full' && crawl.enabled
            ? await runKatana(url, {
                bin: env['KATANA_PATH'] || 'katana',
                maxDepth: crawl.max_depth,
                maxDurationSeconds: crawl.max_duration_seconds,
                maxUrls: crawl.max_urls,
                jsCrawl: crawl.js_crawl,
                rateLimit: nuclei.rate_limit,
                requestTimeoutSeconds: nuclei.request_timeout_seconds,
                env,
                log
              })
            : [];
        const output = await runNuclei(
          { templateTargets: [url.toString()], fuzzTargets: mode === 'full' ? (crawled.length ? crawled : [url.toString()]) : [] },
          {
            bin: env['NUCLEI_PATH'] || 'nuclei',
            templates,
            severities: nuclei.severities,
            includeTags: nuclei.include_tags,
            excludeTags: nuclei.exclude_tags,
            excludeTemplateIds: nuclei.exclude_template_ids,
            rateLimit: nuclei.rate_limit,
            concurrency: nuclei.concurrency,
            requestTimeoutSeconds: nuclei.request_timeout_seconds,
            timeoutSeconds: nuclei.timeout_seconds,
            env,
            log
          }
        );
        return {
          findings: output.findings,
          metadata: { ...output.metadata, mode: request.dastMode ?? rules.dast.mode, crawled_urls: crawled.length }
        };
      }
    };
  }

  if (request.scanType === 'container') {
    const image = validateImageRef(request.target);
    const trivy = rules.container.trivy;
    return {
      target: image,
      run: () =>
        runTrivyImage(image, {
          bin: env['TRIVY_PATH'] || 'trivy',
          timeoutSeconds: trivy.timeout_seconds,
          scanners: trivy.scanners,
          ignoreUnfixed: trivy.ignore_unfixed,
          log,
          ...(env['TRIVY_CACHE_DIR'] ? { cacheDir: env['TRIVY_CACHE_DIR'] } : {})
        })
    };
  }

  const target = await resolveWorkspacePath(request.target, ctx.workspaceRoots ?? workspaceRootsFromEnv(env));

  if (request.scanType === 'sast') {
    const opengrep = rules.sast.opengrep;
    const languages = await sastLanguages(request.languages, target, rules);
    // Opengrep runs with cwd=target, so local rule paths are made absolute here, relative to the rules file.
    const entries = [...opengrep.configs, ...languages.flatMap((language) => opengrep.language_configs[language] ?? [])];
    const configs = Array.from(
      new Set(entries.map((config) => (REGISTRY_CONFIG.test(config) ? config : resolveConfigPath(config, rules, env))))
    );
    logger.info('SAST languages', { languages, configs: configs.length });
    log?.(`[sast] languages: ${languages.length ? languages.join(', ') : 'none (common rules only)'}`);
    return {
      target,
      run: async () => {
        const output = await runOpengrep(target, {
          bin: env['OPENGREP_PATH'] || 'opengrep',
          configs,
          exclude: opengrep.exclude,
          timeoutSeconds: opengrep.timeout_seconds,
          taintIntrafile: opengrep.taint_intrafile,
          env,
          log
        });
        return { ...output, metadata: { ...output.metadata, languages } };
      }
    };
  }

  if (request.scanType === 'sca' && tool === 'trivy') {
    const trivy = rules.sca.trivy;
    return {
      target,
      run: () =>
        runTrivyFilesystem(target, {
          bin: env['TRIVY_PATH'] || 'trivy',
          timeoutSeconds: trivy.timeout_seconds,
          scanners: trivy.scanners,
          ignoreUnfixed: trivy.ignore_unfixed,
          log,
          ...(env['TRIVY_CACHE_DIR'] ? { cacheDir: env['TRIVY_CACHE_DIR'] } : {})
        })
    };
  }

  return {
    target,
    run: () =>
      runOsvScanner(target, {
        bin: env['OSV_SCANNER_PATH'] || 'osv-scanner',
        timeoutSeconds: rules.sca.osv_scanner.timeout_seconds,
        log
      })
  };
}

/**
 * Run one scanner, persist JSON + SARIF under the reports directory and evaluate the policy.
 * Scanner failures are recorded as a failed result (which the policy treats as a violation);
 * invalid input throws ValidationError before anything is executed or written.
 */
export async function runScan(request: ScanRequest, ctx: ScanContext): Promise<ScanOutcome> {
  const tool = resolveTool(request, ctx.rules);
  const scanId = request.scanId ? assertScanId(request.scanId) : newScanId(request.scanType, tool);
  const { target, run } = await prepare(request, tool, ctx);

  const started = new Date();
  logger.info('Scan started', { scan_id: scanId, scan_type: request.scanType, tool, target });

  let output: ScannerOutput | undefined;
  let error: string | undefined;
  try {
    output = await run();
  } catch (err) {
    error = errorMessage(err);
    logger.error('Scan failed', { scan_id: scanId, tool, error });
  }

  const finished = new Date();
  const findings = output?.findings ?? [];
  const result: ScanResult = {
    schema_version: 1,
    scan_id: scanId,
    scan_type: request.scanType,
    tool,
    status: error === undefined ? 'completed' : 'failed',
    target,
    started_at: started.toISOString(),
    finished_at: finished.toISOString(),
    duration_ms: finished.getTime() - started.getTime(),
    summary: error === undefined ? summarize(findings) : emptySummary(),
    findings,
    metadata: output?.metadata ?? {},
    ...(error !== undefined ? { error } : {})
  };

  const reportDir = await ctx.store.save(result);
  const decision = evaluatePolicy([result], ctx.rules);
  await ctx.store.savePolicy(scanId, decision);
  logger.info('Scan finished', { scan_id: scanId, status: result.status, policy: decision.status, summary: result.summary });

  return { result, decision, reportDir };
}
