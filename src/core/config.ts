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
    opengrep: { timeout_seconds: number; taint_intrafile: boolean; configs: string[]; exclude: string[] };
  };
  sca: ScanPolicy & {
    osv_scanner: { timeout_seconds: number };
    trivy: TrivyOptions;
  };
  container: ScanPolicy & { trivy: TrivyOptions };
  dast: ScanPolicy & {
    mode: 'baseline' | 'full';
    crawl: { enabled: boolean; max_depth: number; max_duration_seconds: number; max_urls: number; js_crawl: boolean };
    nuclei: {
      timeout_seconds: number;
      templates: string[];
      severities: Severity[];
      include_tags: string[];
      exclude_tags: string[];
      exclude_template_ids: string[];
      rate_limit: number;
      concurrency: number;
      request_timeout_seconds: number;
    };
    target_policy: DastTargetPolicy;
  };
  /** Directory of the rules file; relative scanner config paths resolve against it. */
  base_dir?: string;
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
const tag = Joi.string().pattern(/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/).max(128);
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
    default_tool: Joi.string().valid('opengrep').default('opengrep'),
    thresholds,
    opengrep: Joi.object({
      timeout_seconds: timeout.default(900),
      taint_intrafile: Joi.boolean().default(true),
      configs: optionList.min(1).default(['opengrep/baseline.yml']),
      exclude: optionList.default([])
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
    default_tool: Joi.string().valid('nuclei').default('nuclei'),
    thresholds,
    mode: Joi.string().valid('baseline', 'full').default('baseline'),
    crawl: Joi.object({
      enabled: Joi.boolean().default(true),
      max_depth: Joi.number().integer().min(1).max(10).default(3),
      max_duration_seconds: Joi.number().integer().min(10).max(3600).default(300),
      max_urls: Joi.number().integer().min(1).max(10000).default(500),
      js_crawl: Joi.boolean().default(false)
    }).default(),
    nuclei: Joi.object({
      timeout_seconds: timeout.default(1800),
      templates: optionList.min(1).default(['${NUCLEI_TEMPLATES_DIR}']),
      severities: Joi.array().items(Joi.string().valid('critical', 'high', 'medium', 'low', 'info')).default([]),
      include_tags: Joi.array().items(tag).default([]),
      exclude_tags: Joi.array().items(tag).default(['dos', 'intrusive']),
      exclude_template_ids: Joi.array().items(tag).default([]),
      rate_limit: Joi.number().integer().min(1).max(1000).default(150),
      concurrency: Joi.number().integer().min(1).max(100).default(25),
      request_timeout_seconds: Joi.number().integer().min(1).max(120).default(10)
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

export function parseRules(source: string, origin = 'security rules', baseDir?: string): SecurityRules {
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
  return baseDir ? { ...value, base_dir: baseDir } : value;
}

export function loadRules(rulesPath: string = defaultRulesPath()): SecurityRules {
  return parseRules(readFileSync(rulesPath, 'utf8'), rulesPath, path.dirname(path.resolve(rulesPath)));
}

/**
 * Resolve a scanner config entry from the rules file: expand ${VAR} from the environment
 * (e.g. ${OPENGREP_RULES_DIR}, which the scanner image sets) and resolve relative paths
 * against the directory of the rules file. Unset variables are an error, not an empty string.
 */
export function resolveConfigPath(entry: string, rules: SecurityRules, env: NodeJS.ProcessEnv = process.env): string {
  const expanded = entry.replace(/\$\{([A-Z_][A-Z0-9_]*)\}/g, (_match, name: string) => {
    const value = env[name];
    if (!value) throw new Error(`Rules file references \${${name}}, which is not set`);
    return value;
  });
  return path.resolve(rules.base_dir ?? process.cwd(), expanded);
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
