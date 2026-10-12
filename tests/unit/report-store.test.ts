import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'fs';
import path from 'path';
import { ValidationError } from '../../src/core/guards';
import { assertScanId, newScanId, ReportStore } from '../../src/core/report-store';
import { findings, scanResult, tempDir } from '../helpers';

describe('ReportStore', () => {
  it('saves JSON and SARIF and reads them back', async () => {
    const store = new ReportStore(tempDir());
    const result = scanResult({ scan_id: 'sast-opengrep-0001', findings: findings({ high: 1 }) });
    const dir = await store.save(result);
    expect(existsSync(path.join(dir, 'result.json'))).toBe(true);
    expect(JSON.parse(readFileSync(path.join(dir, 'result.sarif'), 'utf8')).version).toBe('2.1.0');
    await expect(store.get('sast-opengrep-0001')).resolves.toMatchObject({ scan_id: 'sast-opengrep-0001', summary: { high: 1 } });
  });

  it('refuses to overwrite an existing scan id', async () => {
    const store = new ReportStore(tempDir());
    await store.save(scanResult({ scan_id: 'sast-dup-0001' }));
    await expect(store.save(scanResult({ scan_id: 'sast-dup-0001' }))).rejects.toThrow(/already exists/);
  });

  it.each(['../../etc/passwd', '..', 'a/b', 'A-UPPER', 'x', '.hidden', 'id with space', '/abs', 'scan\0id'])(
    'rejects invalid scan id %j',
    async (id) => {
      const store = new ReportStore(tempDir());
      await expect(store.get(id)).rejects.toThrow(ValidationError);
    }
  );

  it('does not follow a symlinked scan directory out of the reports dir', async () => {
    const base = tempDir();
    const outside = tempDir();
    mkdirSync(path.join(outside, 'loot'));
    writeFileSync(path.join(outside, 'loot', 'result.json'), JSON.stringify(scanResult()));
    symlinkSync(path.join(outside, 'loot'), path.join(base, 'sast-link-0001'));
    const store = new ReportStore(base);
    await expect(store.get('sast-link-0001')).rejects.toThrow(/not found/);
  });

  it('does not follow a symlinked result file', async () => {
    const base = tempDir();
    mkdirSync(path.join(base, 'sast-file-0001'));
    symlinkSync('/etc/passwd', path.join(base, 'sast-file-0001', 'result.json'));
    const store = new ReportStore(base);
    await expect(store.get('sast-file-0001')).rejects.toThrow(ValidationError);
  });

  it('lists scans newest first and filters by type', async () => {
    const store = new ReportStore(tempDir());
    await store.save(scanResult({ scan_id: 'sast-a-0001', finished_at: '2026-01-01T00:00:00Z' }));
    await store.save(scanResult({ scan_id: 'sca-b-0001', scan_type: 'sca', tool: 'trivy', finished_at: '2026-01-02T00:00:00Z' }));
    mkdirSync(path.join(store.baseDir, 'incomplete-0001'));
    expect((await store.list()).map((s) => s.scan_id)).toEqual(['sca-b-0001', 'sast-a-0001']);
    expect((await store.list({ scanType: 'sast' })).map((s) => s.scan_id)).toEqual(['sast-a-0001']);
    expect(await store.list({ limit: 1 })).toHaveLength(1);
  });

  it('generates ids that pass validation', () => {
    expect(assertScanId(newScanId('dast', 'nuclei'))).toMatch(/^dast-nuclei-\d{8}t\d{6}-[0-9a-f]{6}$/);
  });
});
