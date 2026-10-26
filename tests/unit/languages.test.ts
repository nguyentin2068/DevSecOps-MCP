import { mkdirSync, symlinkSync, writeFileSync } from 'fs';
import path from 'path';
import { detectLanguages, languageOf } from '../../src/core/languages';
import { tempDir } from '../helpers';

describe('languageOf', () => {
  it.each([
    ['app.py', 'python'],
    ['Main.JAVA', 'java'],
    ['index.tsx', 'typescript'],
    ['server.mjs', 'javascript'],
    ['Dockerfile', 'dockerfile'],
    ['Dockerfile.prod', 'dockerfile'],
    ['api.dockerfile', 'dockerfile'],
    ['main.tf', 'terraform'],
    ['README.md', undefined],
    ['Makefile', undefined]
  ])('%s -> %s', (file, language) => {
    expect(languageOf(file)).toBe(language);
  });
});

describe('detectLanguages', () => {
  it('counts files per language, skips excluded and VCS directories and does not follow symlinks', async () => {
    const root = tempDir('langs-');
    const outside = tempDir('langs-outside-');
    writeFileSync(path.join(outside, 'secret.go'), 'package main');
    mkdirSync(path.join(root, 'src', 'pkg'), { recursive: true });
    mkdirSync(path.join(root, 'vendor'));
    mkdirSync(path.join(root, '.git'));
    writeFileSync(path.join(root, 'src', 'a.py'), '');
    writeFileSync(path.join(root, 'src', 'pkg', 'b.py'), '');
    writeFileSync(path.join(root, 'src', 'c.js'), '');
    writeFileSync(path.join(root, 'vendor', 'd.php'), '');
    writeFileSync(path.join(root, '.git', 'e.rb'), '');
    symlinkSync(outside, path.join(root, 'linked'));

    const detection = await detectLanguages(root, { excludeDirs: ['vendor'] });
    expect(detection.languages).toEqual([
      { name: 'python', files: 2 },
      { name: 'javascript', files: 1 }
    ]);
    expect(detection.files_scanned).toBe(3);
    expect(detection.truncated).toBe(false);
  });

  it('stops at maxFiles and reports the walk as truncated', async () => {
    const root = tempDir('langs-max-');
    for (let i = 0; i < 5; i++) writeFileSync(path.join(root, `f${i}.go`), '');
    const detection = await detectLanguages(root, { maxFiles: 3 });
    expect(detection.truncated).toBe(true);
    expect(detection.files_scanned).toBe(3);
  });
});
