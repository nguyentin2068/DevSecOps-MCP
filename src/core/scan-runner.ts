import path from 'path';
import { envSecret, SecurityRules } from './config';
import {
  assertSafeDastTarget,
  resolveWorkspacePath,
  Resolver,
  validateImageRef,
  validateProjectKey,
  ValidationError,
  workspaceRootsFromEnv
} from './guards';
import { errorMessage, logger } from './logger';
import { evaluatePolicy, PolicyDecision } from './policy';
import { assertScanId, newScanId, ReportStore } from './report-store';
import { runOsvScanner } from './scanners/osv-scanner';
import { runSemgrep } from './scanners/semgrep';
import { runSonarQube } from './scanners/sonarqube';
import { runTrivyFilesystem, runTrivyImage } from './scanners/trivy';
import { runZap } from './scanners/zap';
import { emptySummary, ScannerOutput, ScanResult, ScanType, summarize, TOOLS_BY_SCAN_TYPE } from './types';

/** Semgrep registry references (p/..., r/..., s/...), URLs and "auto" are passed through unchanged. */
const REGISTRY_CONFIG = /^(?:[prs]\/|https?:\/\/|auto$)/;

export interface ScanRequest {
  scanType: ScanType;
  target: string;
  tool?: string;
  scanId?: string;
  /** SonarQube project key (sast/sonarqube only). */
  projectKey?: string;
  /** Overrides dast.zap.mode from the rules. */
  zapMode?: 'baseline' | 'full';
}

export interface ScanContext {
  rules: SecurityRules;
  store: ReportStore;
  env?: NodeJS.ProcessEnv;
  workspaceRoots?: string[];
  resolver?: Resolver;
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

/** Validate the target and build the scanner call. Validation errors surface before anything runs. */
async function prepare(request: ScanRequest, tool: string, ctx: ScanContext): Promise<{ target: string; run: () => Promise<ScannerOutput> }> {
  const env = ctx.env ?? process.env;
  const { rules } = ctx;

  if (request.scanType === 'dast') {
    const url = await assertSafeDastTarget(request.target, rules.dast.target_policy, ctx.resolver);
    const zap = rules.dast.zap;
    return {
      target: url.toString(),
      run: () =>
        runZap(url.toString(), {
          baseUrl: env['ZAP_URL'] || 'http://localhost:8080',
          apiKey: envSecret('ZAP_API_KEY', env) ?? '',
          mode: request.zapMode ?? zap.mode,
          spiderMaxMinutes: zap.spider_max_minutes,
          passiveWaitMinutes: zap.passive_wait_minutes,
          activeMaxMinutes: zap.active_max_minutes,
          maxAlerts: zap.max_alerts
        })
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
          ...(env['TRIVY_CACHE_DIR'] ? { cacheDir: env['TRIVY_CACHE_DIR'] } : {})
        })
    };
  }

  const target = await resolveWorkspacePath(request.target, ctx.workspaceRoots ?? workspaceRootsFromEnv(env));

  if (request.scanType === 'sast' && tool === 'semgrep') {
    const semgrep = rules.sast.semgrep;
    // Semgrep runs with cwd=target, so local rule paths are resolved against the caller's cwd first.
    const configs = semgrep.configs.map((config) => (REGISTRY_CONFIG.test(config) ? config : path.resolve(config)));
    return {
      target,
      run: () =>
        runSemgrep(target, {
          bin: env['SEMGREP_PATH'] || 'semgrep',
          configs,
          exclude: semgrep.exclude,
          timeoutSeconds: semgrep.timeout_seconds
        })
    };
  }

  if (request.scanType === 'sast' && tool === 'sonarqube') {
    if (!request.projectKey) throw new ValidationError('--project-key is required for SonarQube scans');
    const projectKey = validateProjectKey(request.projectKey);
    const sonar = rules.sast.sonarqube;
    return {
      target,
      run: () =>
        runSonarQube(target, {
          scannerBin: env['SONAR_SCANNER_PATH'] || 'sonar-scanner',
          hostUrl: env['SONAR_HOST_URL'] || 'http://localhost:9000',
          token: envSecret('SONAR_TOKEN', env) ?? '',
          projectKey,
          exclusions: sonar.exclusions,
          timeoutSeconds: sonar.timeout_seconds
        })
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
          ...(env['TRIVY_CACHE_DIR'] ? { cacheDir: env['TRIVY_CACHE_DIR'] } : {})
        })
    };
  }

  return {
    target,
    run: () =>
      runOsvScanner(target, {
        bin: env['OSV_SCANNER_PATH'] || 'osv-scanner',
        timeoutSeconds: rules.sca.osv_scanner.timeout_seconds
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
