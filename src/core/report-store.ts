import { randomBytes } from 'crypto';
import { mkdirSync, promises as fs, realpathSync } from 'fs';
import path from 'path';
import { isWithin, ValidationError } from './guards';
import { PolicyDecision } from './policy';
import { toSarif } from './sarif';
import { ScanResult, ScanType } from './types';

/** Lowercase letters, digits, "_" and "-" only: no dots or separators, so no traversal. */
export const SCAN_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{2,127}$/;

const RESULT_FILE = 'result.json';
const SARIF_FILE = 'result.sarif';
const POLICY_FILE = 'policy.json';
const MAX_RESULT_BYTES = 50 * 1024 * 1024;

export function assertScanId(scanId: string): string {
  if (typeof scanId !== 'string' || !SCAN_ID_PATTERN.test(scanId)) {
    throw new ValidationError(`Invalid scan id: ${JSON.stringify(scanId)}`);
  }
  return scanId;
}

export function newScanId(scanType: ScanType, tool: string, now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\..*$/, '').toLowerCase();
  return `${scanType}-${tool}-${stamp}-${randomBytes(3).toString('hex')}`;
}

export interface ScanListing {
  scan_id: string;
  scan_type: ScanType;
  tool: string;
  status: ScanResult['status'];
  target: string;
  finished_at: string;
  summary: ScanResult['summary'];
}

/**
 * Results live in <baseDir>/<scan_id>/{result.json,result.sarif,policy.json}.
 * Reads accept only validated scan ids and re-check the real path stays inside baseDir,
 * so neither "../" nor a planted symlink can escape the reports directory.
 */
export class ReportStore {
  readonly baseDir: string;

  constructor(baseDir: string) {
    mkdirSync(baseDir, { recursive: true });
    this.baseDir = realpathSync(baseDir);
  }

  static fromEnv(env: NodeJS.ProcessEnv = process.env): ReportStore {
    return new ReportStore(path.resolve(env['REPORTS_DIR'] || 'security-reports'));
  }

  private async scanDir(scanId: string): Promise<string> {
    const dir = path.join(this.baseDir, assertScanId(scanId));
    let real: string;
    try {
      real = await fs.realpath(dir);
    } catch {
      throw new ValidationError(`Scan not found: ${scanId}`);
    }
    if (!isWithin(this.baseDir, real) || real === this.baseDir) {
      throw new ValidationError(`Scan not found: ${scanId}`);
    }
    return real;
  }

  private async readFileInside(scanId: string, file: string): Promise<string> {
    const dir = await this.scanDir(scanId);
    const target = path.join(dir, file);
    let real: string;
    try {
      real = await fs.realpath(target);
    } catch {
      throw new ValidationError(`${file} not found for scan ${scanId}`);
    }
    if (!isWithin(dir, real)) throw new ValidationError(`Scan not found: ${scanId}`);
    const stat = await fs.stat(real);
    if (!stat.isFile() || stat.size > MAX_RESULT_BYTES) {
      throw new ValidationError(`${file} for scan ${scanId} is not a readable result file`);
    }
    return fs.readFile(real, 'utf8');
  }

  async save(result: ScanResult): Promise<string> {
    const dir = path.join(this.baseDir, assertScanId(result.scan_id));
    try {
      await fs.mkdir(dir);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
        throw new ValidationError(`Scan id already exists: ${result.scan_id}`);
      }
      throw error;
    }
    await fs.writeFile(path.join(dir, RESULT_FILE), JSON.stringify(result, null, 2));
    await fs.writeFile(path.join(dir, SARIF_FILE), JSON.stringify(toSarif(result), null, 2));
    return dir;
  }

  async savePolicy(scanId: string, decision: PolicyDecision): Promise<void> {
    const dir = await this.scanDir(scanId);
    await fs.writeFile(path.join(dir, POLICY_FILE), JSON.stringify(decision, null, 2));
  }

  async get(scanId: string): Promise<ScanResult> {
    const raw = await this.readFileInside(scanId, RESULT_FILE);
    try {
      return JSON.parse(raw) as ScanResult;
    } catch {
      throw new ValidationError(`Result for scan ${scanId} is not valid JSON`);
    }
  }

  async getSarif(scanId: string): Promise<string> {
    return this.readFileInside(scanId, SARIF_FILE);
  }

  async list(filter: { scanType?: ScanType; limit?: number } = {}): Promise<ScanListing[]> {
    const entries = await fs.readdir(this.baseDir, { withFileTypes: true });
    const listings: ScanListing[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory() || !SCAN_ID_PATTERN.test(entry.name)) continue;
      try {
        const result = await this.get(entry.name);
        if (filter.scanType && result.scan_type !== filter.scanType) continue;
        listings.push({
          scan_id: result.scan_id,
          scan_type: result.scan_type,
          tool: result.tool,
          status: result.status,
          target: result.target,
          finished_at: result.finished_at,
          summary: result.summary
        });
      } catch {
        // Skip directories that are not (or not yet) complete scan results.
      }
    }
    listings.sort((a, b) => b.finished_at.localeCompare(a.finished_at));
    return listings.slice(0, filter.limit ?? 50);
  }
}
