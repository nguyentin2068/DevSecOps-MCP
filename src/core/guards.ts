import { promises as dns } from 'dns';
import { realpathSync, promises as fs } from 'fs';
import net from 'net';
import path from 'path';

export class ValidationError extends Error {
  override name = 'ValidationError';
}

/** True when `candidate` is `base` itself or inside it. Both must be absolute, normalized paths. */
export function isWithin(base: string, candidate: string): boolean {
  const relative = path.relative(base, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function rejectFlagLike(value: string, what: string): void {
  if (value.startsWith('-')) {
    throw new ValidationError(`${what} must not start with "-"`);
  }
  if (value.includes('\0')) {
    throw new ValidationError(`${what} contains a NUL byte`);
  }
}

/** Workspace roots that scans may read from: SCAN_WORKSPACE_ROOTS (path-delimited) or the cwd. */
export function workspaceRootsFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  const configured = env['SCAN_WORKSPACE_ROOTS'];
  const roots = configured ? configured.split(path.delimiter).filter(Boolean) : [process.cwd()];
  return roots.map((root) => realpathSync(path.resolve(root)));
}

/**
 * Resolve a scan target to a real absolute path inside one of the allowed roots.
 * Symlinks are resolved before the check so a link cannot point outside the workspace.
 */
export async function resolveWorkspacePath(target: string, roots: string[]): Promise<string> {
  if (!target) throw new ValidationError('Target path is required');
  rejectFlagLike(target, 'Target path');

  let real: string;
  try {
    real = await fs.realpath(path.resolve(target));
  } catch {
    throw new ValidationError(`Target path does not exist: ${target}`);
  }

  if (!roots.some((root) => isWithin(root, real))) {
    throw new ValidationError(`Target path is outside the allowed workspace: ${target}`);
  }
  return real;
}

// name[:tag][@digest], optionally prefixed by registry[:port]/
const IMAGE_REF = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$/;

export function validateImageRef(ref: string): string {
  rejectFlagLike(ref, 'Image reference');
  if (ref.length > 255 || !IMAGE_REF.test(ref)) {
    throw new ValidationError(`Invalid container image reference: ${ref}`);
  }
  return ref;
}

const PROJECT_KEY = /^[A-Za-z0-9_.:-]{1,400}$/;

export function validateProjectKey(key: string): string {
  rejectFlagLike(key, 'Project key');
  if (!PROJECT_KEY.test(key) || /^\d+$/.test(key)) {
    throw new ValidationError(`Invalid SonarQube project key: ${key}`);
  }
  return key;
}

/** Scanner options taken from config (rulesets, exclude globs) must not smuggle extra flags. */
export function validateOptionValue(value: string, what: string): string {
  rejectFlagLike(value, what);
  return value;
}

export interface DastTargetPolicy {
  allowed_hosts: string[];
  allowed_cidrs: string[];
}

export type Resolver = (hostname: string) => Promise<string[]>;

const defaultResolver: Resolver = async (hostname) => {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
};

// Never scanned unless explicitly allowlisted: loopback, link-local (cloud metadata lives at
// 169.254.169.254 and fd00:ec2::254), "this network", multicast and reserved ranges.
const BLOCKED = new net.BlockList();
BLOCKED.addSubnet('0.0.0.0', 8, 'ipv4');
BLOCKED.addSubnet('127.0.0.0', 8, 'ipv4');
BLOCKED.addSubnet('169.254.0.0', 16, 'ipv4');
BLOCKED.addSubnet('100.100.100.200', 32, 'ipv4');
BLOCKED.addSubnet('224.0.0.0', 4, 'ipv4');
BLOCKED.addSubnet('240.0.0.0', 4, 'ipv4');
BLOCKED.addAddress('::', 'ipv6');
BLOCKED.addAddress('::1', 'ipv6');
BLOCKED.addSubnet('fe80::', 10, 'ipv6');
BLOCKED.addSubnet('ff00::', 8, 'ipv6');
BLOCKED.addAddress('fd00:ec2::254', 'ipv6');

function ipFamily(address: string): 'ipv4' | 'ipv6' {
  return net.isIPv6(address) ? 'ipv6' : 'ipv4';
}

/** Map IPv4-mapped IPv6 addresses (::ffff:127.0.0.1) back to IPv4 so they hit the IPv4 rules. */
function normalizeAddress(address: string): string {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  return mapped?.[1] ?? address;
}

function buildAllowList(cidrs: string[]): net.BlockList {
  const list = new net.BlockList();
  for (const cidr of cidrs) {
    const [base, bits] = cidr.split('/');
    if (!base || !net.isIP(base)) {
      throw new ValidationError(`Invalid CIDR in DAST allowlist: ${cidr}`);
    }
    const family = ipFamily(base);
    const prefix = bits === undefined ? (family === 'ipv4' ? 32 : 128) : Number(bits);
    list.addSubnet(base, prefix, family);
  }
  return list;
}

function hostMatches(hostname: string, pattern: string): boolean {
  const host = hostname.toLowerCase();
  const p = pattern.toLowerCase();
  if (p.startsWith('*.')) return host.endsWith(p.slice(1));
  return host === p;
}

/**
 * SSRF guard for DAST targets. Only http(s) URLs without embedded credentials are accepted.
 * If an allowlist is configured the target must match it (host name or every resolved IP).
 * Without an allowlist, targets resolving to loopback, link-local/metadata or reserved
 * addresses are refused. Explicit allowlist entries are the only way to scan those.
 */
export async function assertSafeDastTarget(
  rawUrl: string,
  policy: DastTargetPolicy,
  resolve: Resolver = defaultResolver
): Promise<URL> {
  rejectFlagLike(rawUrl, 'Target URL');
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ValidationError(`Invalid target URL: ${rawUrl}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ValidationError(`Target URL must use http or https: ${rawUrl}`);
  }
  if (url.username || url.password) {
    throw new ValidationError('Target URL must not contain credentials');
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const addresses = net.isIP(hostname) ? [hostname] : await resolve(hostname).catch(() => {
    throw new ValidationError(`Target host cannot be resolved: ${hostname}`);
  });
  if (addresses.length === 0) {
    throw new ValidationError(`Target host cannot be resolved: ${hostname}`);
  }

  const allowedCidrs = buildAllowList(policy.allowed_cidrs);
  const hostAllowed = policy.allowed_hosts.some((pattern) => hostMatches(hostname, pattern));
  const normalized = addresses.map(normalizeAddress);
  const ipsAllowed = normalized.every((ip) => allowedCidrs.check(ip, ipFamily(ip)));
  const hasAllowlist = policy.allowed_hosts.length > 0 || policy.allowed_cidrs.length > 0;

  if (hostAllowed || (policy.allowed_cidrs.length > 0 && ipsAllowed)) {
    return url;
  }
  if (hasAllowlist) {
    throw new ValidationError(`Target ${hostname} is not in the DAST allowlist`);
  }
  const blocked = normalized.find((ip) => BLOCKED.check(ip, ipFamily(ip)));
  if (blocked) {
    throw new ValidationError(
      `Target ${hostname} resolves to a blocked address (${blocked}); add it to dast.target_policy to allow it`
    );
  }
  return url;
}
