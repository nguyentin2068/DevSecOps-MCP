import { existsSync, readFileSync } from 'fs';
import path from 'path';
import Joi from 'joi';
import YAML from 'yaml';
import { DastTargetPolicy } from './guards';
import { ScanType, Severity } from './types';

export type Thresholds = Partial<Record<Severity, number | null>>;

interface ScanPolicy {
  default_tool: string;
  thresholds?: Thresholds;
}

interface TrivyOptions {
  timeout_seconds: number;
  scanners: string[];
  ignore_unfixed: boolean;
}

export interface SecurityRules {
  version: string;
  global_policy: {
    enforcement_level: 'strict' | 'permissive';
    thresholds: Thresholds;
  };
  sast: ScanPolicy & {
    require_sonar_quality_gate: boolean;
    semgrep: { timeout_seconds: number; configs: string[]; exclude: string[] };
    sonarqube: { timeout_seconds: number; exclusions: string[] };
  };
  sca: ScanPolicy & {
    osv_scanner: { timeout_seconds: number };
    trivy: TrivyOptions;
  };
  container: ScanPolicy & { trivy: TrivyOptions };
  dast: ScanPolicy & {
    zap: {
      mode: 'baseline' | 'full';
      spider_max_minutes: number;
      passive_wait_minutes: number;
      active_max_minutes: number;
      max_alerts: number;
    };
    target_policy: DastTargetPolicy;
  };
}

const threshold = Joi.number().integer().min(0).allow(null);
const thresholds = Joi.object({
  critical: threshold,
  high: threshold,
  medium: threshold,
  low: threshold,
  info: threshold
});
const timeout = Joi.number().integer().min(10).max(24 * 3600);
const optionList = Joi.array().items(Joi.string().pattern(/^[^-]/).max(512));
const trivy = Joi.object({
  timeout_seconds: timeout.default(900),
  scanners: Joi.array().items(Joi.string().valid('vuln', 'secret', 'misconfig', 'license')).min(1).default(['vuln']),
  ignore_unfixed: Joi.boolean().default(false)
}).default();

const schema = Joi.object<SecurityRules>({
  version: Joi.string().required(),
  global_policy: Joi.object({
    enforcement_level: Joi.string().valid('strict', 'permissive').default('strict'),
    thresholds: thresholds.default({ critical: 0, high: 0 })
  }).required(),
  sast: Joi.object({
    default_tool: Joi.string().valid('semgrep', 'sonarqube').default('semgrep'),
    thresholds,
    require_sonar_quality_gate: Joi.boolean().default(true),
    semgrep: Joi.object({
      timeout_seconds: timeout.default(900),
      configs: optionList.min(1).default(['p/security-audit']),
      exclude: optionList.default([])
    }).default(),
    sonarqube: Joi.object({
      timeout_seconds: timeout.default(1800),
      exclusions: Joi.array().items(Joi.string().max(512)).default([])
    }).default()
  }).default(),
  sca: Joi.object({
    default_tool: Joi.string().valid('osv-scanner', 'trivy').default('osv-scanner'),
    thresholds,
    osv_scanner: Joi.object({ timeout_seconds: timeout.default(900) }).default(),
    trivy
  }).default(),
  container: Joi.object({
    default_tool: Joi.string().valid('trivy').default('trivy'),
    thresholds,
    trivy
  }).default(),
  dast: Joi.object({
    default_tool: Joi.string().valid('zap').default('zap'),
    thresholds,
    zap: Joi.object({
      mode: Joi.string().valid('baseline', 'full').default('baseline'),
      spider_max_minutes: Joi.number().integer().min(1).max(240).default(10),
      passive_wait_minutes: Joi.number().integer().min(1).max(240).default(10),
      active_max_minutes: Joi.number().integer().min(1).max(1440).default(60),
      max_alerts: Joi.number().integer().min(1).max(100000).default(5000)
    }).default(),
    target_policy: Joi.object({
      allowed_hosts: Joi.array()
        .items(Joi.alternatives().try(Joi.string().hostname(), Joi.string().pattern(/^\*\.[A-Za-z0-9.-]+$/)))
        .default([]),
      allowed_cidrs: Joi.array().items(Joi.string().pattern(/^[0-9a-fA-F:.]+(\/\d{1,3})?$/)).default([])
    }).default()
  }).default()
});

/** Walk up from this file to the directory holding package.json (works from src/ and dist/). */
export function packageRoot(start: string = __dirname): string {
  let dir = start;
  while (!existsSync(path.join(dir, 'package.json'))) {
    const parent = path.dirname(dir);
    if (parent === dir) return process.cwd();
    dir = parent;
  }
  return dir;
}

export function defaultRulesPath(env: NodeJS.ProcessEnv = process.env): string {
  return env['SECURITY_RULES_PATH'] || path.join(packageRoot(), 'src', 'config', 'security-rules.yml');
}

export function parseRules(source: string, origin = 'security rules'): SecurityRules {
  let raw: unknown;
  try {
    raw = YAML.parse(source);
  } catch (error) {
    throw new Error(`${origin}: invalid YAML: ${error instanceof Error ? error.message : String(error)}`);
  }
  const { error, value } = schema.validate(raw, { abortEarly: false, allowUnknown: false });
  if (error) {
    throw new Error(`${origin}: ${error.details.map((detail) => detail.message).join('; ')}`);
  }
  return value;
}

export function loadRules(rulesPath: string = defaultRulesPath()): SecurityRules {
  return parseRules(readFileSync(rulesPath, 'utf8'), rulesPath);
}

/**
 * Read a secret from NAME or, preferably, from the file named by NAME_FILE
 * (Docker/Kubernetes secret mounts). Surrounding whitespace is trimmed.
 */
export function envSecret(name: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const file = env[`${name}_FILE`];
  if (file) return readFileSync(file, 'utf8').trim();
  const value = env[name];
  return value ? value.trim() : undefined;
}

/** Global thresholds overlaid with the scan type's own thresholds; null/absent means unlimited. */
export function effectiveThresholds(rules: SecurityRules, scanType: ScanType): Thresholds {
  return { ...rules.global_policy.thresholds, ...(rules[scanType].thresholds ?? {}) };
}
