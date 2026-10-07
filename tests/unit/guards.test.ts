import { mkdirSync, realpathSync, symlinkSync, writeFileSync } from 'fs';
import path from 'path';
import {
  assertSafeDastTarget,
  resolveWorkspacePath,
  validateImageRef,
  validateProjectKey,
  ValidationError
} from '../../src/core/guards';
import { tempDir } from '../helpers';

describe('resolveWorkspacePath', () => {
  const root = realpathSync(tempDir());
  const outside = realpathSync(tempDir());
  mkdirSync(path.join(root, 'app'));
  writeFileSync(path.join(outside, 'secret.txt'), 'x');
  symlinkSync(outside, path.join(root, 'escape'));

  it('accepts paths inside the workspace', async () => {
    await expect(resolveWorkspacePath(path.join(root, 'app'), [root])).resolves.toBe(path.join(root, 'app'));
    await expect(resolveWorkspacePath(root, [root])).resolves.toBe(root);
  });

  it('rejects traversal outside the workspace', async () => {
    await expect(resolveWorkspacePath(path.join(root, '..', '..', 'etc'), [root])).rejects.toThrow(/outside the allowed workspace/);
    await expect(resolveWorkspacePath('/etc/passwd', [root])).rejects.toThrow(ValidationError);
  });

  it('rejects symlinks that point outside the workspace', async () => {
    await expect(resolveWorkspacePath(path.join(root, 'escape'), [root])).rejects.toThrow(/outside the allowed workspace/);
  });

  it('rejects flag-like and missing targets', async () => {
    await expect(resolveWorkspacePath('--config=/etc/passwd', [root])).rejects.toThrow(/must not start with "-"/);
    await expect(resolveWorkspacePath(path.join(root, 'nope'), [root])).rejects.toThrow(/does not exist/);
  });
});

describe('assertSafeDastTarget', () => {
  const open = { allowed_hosts: [], allowed_cidrs: [] };
  const resolveTo = (...ips: string[]) => async () => ips;

  it.each([
    'http://169.254.169.254/latest/meta-data/',
    'http://127.0.0.1:8080/',
    'http://localhost/',
    'http://[::1]/',
    'http://[::ffff:127.0.0.1]/',
    'http://0.0.0.0/',
    'http://[fd00:ec2::254]/'
  ])('refuses %s without an explicit allowlist', async (url) => {
    await expect(assertSafeDastTarget(url, open, resolveTo('127.0.0.1'))).rejects.toThrow(/blocked address/);
  });

  it('refuses a public-looking host that resolves to the metadata service (DNS trick)', async () => {
    await expect(assertSafeDastTarget('http://metadata.attacker.example/', open, resolveTo('169.254.169.254'))).rejects.toThrow(/blocked address/);
  });

  it('accepts a public or private application address', async () => {
    await expect(assertSafeDastTarget('https://staging.example.com/', open, resolveTo('10.0.12.5'))).resolves.toBeInstanceOf(URL);
  });

  it('rejects non-http schemes and embedded credentials', async () => {
    await expect(assertSafeDastTarget('file:///etc/passwd', open)).rejects.toThrow(/http or https/);
    await expect(assertSafeDastTarget('gopher://x/', open)).rejects.toThrow(/http or https/);
    await expect(assertSafeDastTarget('http://user:pw@example.com/', open, resolveTo('93.184.216.34'))).rejects.toThrow(/credentials/);
    await expect(assertSafeDastTarget('not a url', open)).rejects.toThrow(/Invalid target URL/);
  });

  it('only allows allowlisted targets once an allowlist is configured', async () => {
    const policy = { allowed_hosts: ['*.staging.internal'], allowed_cidrs: ['10.20.0.0/16'] };
    await expect(assertSafeDastTarget('http://app.staging.internal/', policy, resolveTo('10.99.0.1'))).resolves.toBeInstanceOf(URL);
    await expect(assertSafeDastTarget('http://other.example.com/', policy, resolveTo('10.20.3.4'))).resolves.toBeInstanceOf(URL);
    await expect(assertSafeDastTarget('http://other.example.com/', policy, resolveTo('93.184.216.34'))).rejects.toThrow(/not in the DAST allowlist/);
  });

  it('allows loopback only when explicitly allowlisted', async () => {
    const policy = { allowed_hosts: [], allowed_cidrs: ['127.0.0.1/32'] };
    await expect(assertSafeDastTarget('http://127.0.0.1:3001/', policy)).resolves.toBeInstanceOf(URL);
  });

  it('rejects hosts that do not resolve', async () => {
    const failing = async () => {
      throw new Error('ENOTFOUND');
    };
    await expect(assertSafeDastTarget('http://nope.invalid/', open, failing)).rejects.toThrow(/cannot be resolved/);
  });
});

describe('identifier validators', () => {
  it('accepts normal image references and rejects injection attempts', () => {
    expect(validateImageRef('nginx:1.27')).toBe('nginx:1.27');
    expect(validateImageRef('registry.example.com:5000/team/app:1.2.3')).toBeTruthy();
    expect(validateImageRef(`ghcr.io/org/app@sha256:${'a'.repeat(64)}`)).toBeTruthy();
    expect(() => validateImageRef('--input=/etc/shadow')).toThrow(ValidationError);
    expect(() => validateImageRef('app; rm -rf /')).toThrow(ValidationError);
    expect(() => validateImageRef('App:Latest')).toThrow(ValidationError);
  });

  it('validates SonarQube project keys', () => {
    expect(validateProjectKey('org:my-app_1.0')).toBe('org:my-app_1.0');
    expect(() => validateProjectKey('-Dsonar.host.url=http://evil')).toThrow(ValidationError);
    expect(() => validateProjectKey('12345')).toThrow(ValidationError);
    expect(() => validateProjectKey('a b')).toThrow(ValidationError);
  });
});
