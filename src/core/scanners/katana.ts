import { runCommand, stderrTail } from '../process';

export interface KatanaOptions {
  bin: string;
  maxDepth: number;
  maxDurationSeconds: number;
  maxUrls: number;
  jsCrawl: boolean;
  rateLimit: number;
  requestTimeoutSeconds: number;
  env?: NodeJS.ProcessEnv;
}

interface KatanaRecord {
  request?: { method?: string; endpoint?: string };
}

function origin(url: URL): string {
  return `${url.protocol}//${url.host}`;
}

/**
 * Turn katana's JSONL output into the list of URLs to scan: only GET endpoints on the
 * target's own origin (scheme + host + port), fragments dropped, de-duplicated, capped.
 * The target itself is always first, so a crawl that finds nothing still scans it.
 */
export function parseKatana(output: string, target: URL, maxUrls: number): string[] {
  const allowed = origin(target);
  const urls = new Set<string>([target.toString()]);

  for (const line of output.split('\n')) {
    if (urls.size >= maxUrls) break;
    const trimmed = line.trim();
    if (!trimmed) continue;
    let record: KatanaRecord;
    try {
      record = JSON.parse(trimmed) as KatanaRecord;
    } catch {
      continue;
    }
    const endpoint = record.request?.endpoint;
    const method = (record.request?.method ?? 'GET').toUpperCase();
    if (!endpoint || method !== 'GET') continue;
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      continue;
    }
    // The crawler may follow links off-site; only the vetted origin is ever handed to nuclei.
    if (origin(url) !== allowed) continue;
    url.hash = '';
    urls.add(url.toString());
  }
  return Array.from(urls);
}

/** Crawl the target with katana (standard crawler, no headless browser) and return in-scope URLs. */
export async function runKatana(target: URL, options: KatanaOptions): Promise<string[]> {
  const args = [
    '-jsonl',
    '-silent',
    '-nc',
    '-or',
    '-ob',
    '-duc',
    '-d', String(options.maxDepth),
    '-ct', `${options.maxDurationSeconds}s`,
    '-fs', 'fqdn',
    '-rl', String(options.rateLimit),
    '-timeout', String(options.requestTimeoutSeconds),
    '-kf', 'all'
  ];
  if (options.jsCrawl) args.push('-jc');
  args.push('-u', target.toString());

  // katana's own crawl-duration is the soft limit; this timeout is the hard stop.
  const { code, stdout, stderr } = await runCommand(options.bin, args, {
    timeoutMs: (options.maxDurationSeconds + 60) * 1000,
    ...(options.env ? { env: options.env } : {})
  });
  if (code !== 0) {
    throw new Error(`katana exited with code ${code}: ${stderrTail(stderr || stdout)}`);
  }
  return parseKatana(stdout, target, options.maxUrls);
}
