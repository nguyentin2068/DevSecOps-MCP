import { logger } from '../logger';
import { Finding, ScannerOutput, Severity } from '../types';

export interface ZapOptions {
  baseUrl: string;
  apiKey: string;
  mode: 'baseline' | 'full';
  spiderMaxMinutes: number;
  passiveWaitMinutes: number;
  activeMaxMinutes: number;
  maxAlerts: number;
  pollIntervalMs?: number;
  fetchImpl?: typeof fetch;
}

interface ZapAlert {
  pluginId?: string;
  alertRef?: string;
  alert?: string;
  name?: string;
  risk?: string;
  riskcode?: string;
  confidence?: string;
  url?: string;
  method?: string;
  param?: string;
  description?: string;
  solution?: string;
  reference?: string;
  cweid?: string;
  wascid?: string;
}

// ZAP risk codes: 3 High, 2 Medium, 1 Low, 0 Informational.
const RISK_MAP: Record<string, Severity> = { '3': 'high', '2': 'medium', '1': 'low', '0': 'info' };
const RISK_NAME_MAP: Record<string, Severity> = { high: 'high', medium: 'medium', low: 'low', informational: 'info' };

export function parseZapAlerts(alerts: ZapAlert[]): ScannerOutput {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  let falsePositives = 0;

  for (const alert of alerts) {
    // Confidence "False Positive" means a user has already triaged the alert in ZAP.
    if (alert.confidence === 'False Positive' || alert.confidence === '0') {
      falsePositives++;
      continue;
    }
    const ruleId = alert.alertRef || alert.pluginId || 'zap';
    const method = alert.method || 'GET';
    const id = `${ruleId}:${method}:${alert.url ?? ''}:${alert.param ?? ''}`;
    if (seen.has(id)) continue;
    seen.add(id);

    const severity =
      RISK_MAP[alert.riskcode ?? ''] ?? RISK_NAME_MAP[(alert.risk ?? '').toLowerCase()] ?? 'medium';
    const finding: Finding = {
      id,
      rule_id: ruleId,
      title: alert.name || alert.alert || ruleId,
      severity,
      location: { url: alert.url ?? '', method }
    };
    if (alert.param) finding.location.parameter = alert.param;
    if (alert.description) finding.description = alert.description;
    if (alert.solution) finding.fix = alert.solution;
    if (alert.cweid && alert.cweid !== '-1' && alert.cweid !== '0') finding.cwe = [`CWE-${alert.cweid}`];
    const references = (alert.reference ?? '').split(/\s+/).filter((ref) => /^https?:\/\//.test(ref));
    if (references.length) finding.references = references.slice(0, 10);
    findings.push(finding);
  }

  return { findings, metadata: { false_positives_skipped: falsePositives } };
}

export class ZapClient {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly baseUrl: string, private readonly apiKey: string, fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? fetch;
  }

  async call<T>(path: string, params: Record<string, string | number | boolean> = {}): Promise<T> {
    const url = new URL(path, this.baseUrl);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, String(value));
    // The API key travels in a header so it never shows up in URLs or access logs.
    const response = await this.fetchImpl(url, {
      headers: { 'X-ZAP-API-Key': this.apiKey, Accept: 'application/json' },
      signal: AbortSignal.timeout(60_000)
    });
    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`ZAP API ${path} returned HTTP ${response.status}: ${body.slice(0, 300)}`);
    }
    return (await response.json()) as T;
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function pollUntil(check: () => Promise<boolean>, maxMs: number, intervalMs: number): Promise<boolean> {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    if (await check()) return true;
    await sleep(intervalMs);
  }
  return false;
}

/**
 * Baseline: new session, spider, wait for the passive scanner, collect alerts.
 * Full: same plus an active scan. The ZAP daemon is shared state, so DAST runs against one
 * daemon must be serialized (the Jenkinsfile uses a lock for this).
 */
export async function runZap(targetUrl: string, options: ZapOptions): Promise<ScannerOutput> {
  if (!options.apiKey) throw new Error('ZAP_API_KEY is required');
  const zap = new ZapClient(options.baseUrl, options.apiKey, options.fetchImpl);
  const interval = options.pollIntervalMs ?? 5000;
  const metadata: Record<string, unknown> = { mode: options.mode };

  const version = await zap.call<{ version: string }>('/JSON/core/view/version/');
  metadata['zap_version'] = version.version;
  await zap.call('/JSON/core/action/newSession/', { overwrite: true });

  // Seed the site tree, then spider only below the target URL.
  await zap.call('/JSON/core/action/accessUrl/', { url: targetUrl, followRedirects: false });
  const spider = await zap.call<{ scan: string }>('/JSON/spider/action/scan/', {
    url: targetUrl,
    recurse: true,
    subtreeOnly: true
  });
  const spiderDone = await pollUntil(
    async () => Number((await zap.call<{ status: string }>('/JSON/spider/view/status/', { scanId: spider.scan })).status) >= 100,
    options.spiderMaxMinutes * 60_000,
    interval
  );
  if (!spiderDone) {
    logger.warn('ZAP spider hit its time limit, continuing with partial coverage', { targetUrl });
    await zap.call('/JSON/spider/action/stop/', { scanId: spider.scan });
  }
  metadata['spider_completed'] = spiderDone;

  if (options.mode === 'full') {
    const active = await zap.call<{ scan: string }>('/JSON/ascan/action/scan/', { url: targetUrl, recurse: true });
    const activeDone = await pollUntil(
      async () => Number((await zap.call<{ status: string }>('/JSON/ascan/view/status/', { scanId: active.scan })).status) >= 100,
      options.activeMaxMinutes * 60_000,
      interval
    );
    if (!activeDone) {
      logger.warn('ZAP active scan hit its time limit, stopping it', { targetUrl });
      await zap.call('/JSON/ascan/action/stop/', { scanId: active.scan });
    }
    metadata['active_scan_completed'] = activeDone;
  }

  const passiveDone = await pollUntil(
    async () => Number((await zap.call<{ recordsToScan: string }>('/JSON/pscan/view/recordsToScan/')).recordsToScan) === 0,
    options.passiveWaitMinutes * 60_000,
    interval
  );
  metadata['passive_scan_completed'] = passiveDone;

  const alerts: ZapAlert[] = [];
  const pageSize = 500;
  while (alerts.length < options.maxAlerts) {
    const page = await zap.call<{ alerts: ZapAlert[] }>('/JSON/alert/view/alerts/', {
      baseurl: targetUrl,
      start: alerts.length,
      count: Math.min(pageSize, options.maxAlerts - alerts.length)
    });
    alerts.push(...page.alerts);
    if (page.alerts.length < pageSize) break;
  }
  metadata['alerts_truncated'] = alerts.length >= options.maxAlerts;

  const parsed = parseZapAlerts(alerts);
  return { findings: parsed.findings, metadata: { ...metadata, ...parsed.metadata } };
}
