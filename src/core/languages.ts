import { promises as fs } from 'fs';
import path from 'path';

/**
 * File extensions per language. The names match the directories of opengrep-rules and the
 * keys of sast.opengrep.language_configs in the rules file. A language is detected when at
 * least one file has one of its extensions.
 */
const EXTENSIONS: Record<string, string[]> = {
  bash: ['.sh', '.bash'],
  c: ['.c', '.h'],
  clojure: ['.clj', '.cljs', '.cljc'],
  csharp: ['.cs'],
  elixir: ['.ex', '.exs'],
  go: ['.go'],
  html: ['.html', '.htm'],
  java: ['.java'],
  javascript: ['.js', '.jsx', '.mjs', '.cjs'],
  json: ['.json'],
  kotlin: ['.kt', '.kts'],
  ocaml: ['.ml', '.mli'],
  php: ['.php', '.phtml'],
  python: ['.py', '.pyw'],
  ruby: ['.rb'],
  rust: ['.rs'],
  scala: ['.scala', '.sc'],
  solidity: ['.sol'],
  swift: ['.swift'],
  terraform: ['.tf'],
  typescript: ['.ts', '.tsx', '.mts', '.cts'],
  yaml: ['.yml', '.yaml']
};

const LANGUAGE_BY_EXTENSION = new Map(
  Object.entries(EXTENSIONS).flatMap(([language, extensions]) => extensions.map((ext) => [ext, language] as const))
);

/** Directories that never hold the project's own source. */
const ALWAYS_SKIPPED = new Set(['.git', '.hg', '.svn']);

const DEFAULT_MAX_FILES = 200_000;

export interface DetectedLanguage {
  name: string;
  files: number;
}

export interface LanguageDetection {
  /** Languages found, most files first. */
  languages: DetectedLanguage[];
  files_scanned: number;
  /** True when the walk stopped at maxFiles; languages may then be incomplete. */
  truncated: boolean;
}

export interface DetectOptions {
  /** Directory names to skip anywhere in the tree (e.g. node_modules, vendor). */
  excludeDirs?: string[];
  maxFiles?: number;
}

export function languageOf(fileName: string): string | undefined {
  const lower = fileName.toLowerCase();
  if (lower === 'dockerfile' || lower.startsWith('dockerfile.') || lower.endsWith('.dockerfile')) return 'dockerfile';
  return LANGUAGE_BY_EXTENSION.get(path.extname(lower));
}

/**
 * Count source files per language under root. Symbolic links are not followed, so the walk
 * stays inside the (already validated) target directory.
 */
export async function detectLanguages(root: string, options: DetectOptions = {}): Promise<LanguageDetection> {
  const skip = new Set([...ALWAYS_SKIPPED, ...(options.excludeDirs ?? [])]);
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const counts = new Map<string, number>();
  let scanned = 0;
  let truncated = false;

  const pending = [root];
  while (pending.length > 0 && !truncated) {
    const dir = pending.pop() as string;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable directory: skip it rather than fail the pre-check
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!skip.has(entry.name)) pending.push(path.join(dir, entry.name));
        continue;
      }
      if (!entry.isFile()) continue;
      if (++scanned > maxFiles) {
        scanned = maxFiles;
        truncated = true;
        break;
      }
      const language = languageOf(entry.name);
      if (language) counts.set(language, (counts.get(language) ?? 0) + 1);
    }
  }

  const languages = Array.from(counts, ([name, files]) => ({ name, files })).sort(
    (a, b) => b.files - a.files || a.name.localeCompare(b.name)
  );
  return { languages, files_scanned: scanned, truncated };
}
