/**
 * CA-001: Language Detection
 * Detects programming languages in a repository with percentage breakdown
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { createLogger } from '../../../utils/logger.js';
import { safePath } from '../../../utils/safePath.js';
import type { LanguageDetection } from '../types.js';

const logger = createLogger('language-detector');

// Language definitions with file extensions and patterns
const LANGUAGE_DEFINITIONS: Record<string, {
  extensions: string[];
  filenames?: string[];
  shebangs?: string[];
}> = {
  // Web languages
  JavaScript: { extensions: ['.js', '.mjs', '.cjs'], shebangs: ['node', 'nodejs'] },
  TypeScript: { extensions: ['.ts', '.tsx', '.mts', '.cts'] },
  HTML: { extensions: ['.html', '.htm', '.xhtml'] },
  CSS: { extensions: ['.css'] },
  SCSS: { extensions: ['.scss', '.sass'] },
  Less: { extensions: ['.less'] },
  Vue: { extensions: ['.vue'] },
  Svelte: { extensions: ['.svelte'] },

  // Backend languages
  Python: { extensions: ['.py', '.pyw', '.pyi'], shebangs: ['python', 'python3'] },
  Java: { extensions: ['.java'] },
  Kotlin: { extensions: ['.kt', '.kts'] },
  Go: { extensions: ['.go'] },
  Rust: { extensions: ['.rs'] },
  Ruby: { extensions: ['.rb', '.rake'], shebangs: ['ruby'], filenames: ['Gemfile', 'Rakefile'] },
  PHP: { extensions: ['.php', '.phtml'] },
  CSharp: { extensions: ['.cs'] },
  FSharp: { extensions: ['.fs', '.fsi', '.fsx'] },
  Scala: { extensions: ['.scala', '.sc'] },
  Swift: { extensions: ['.swift'] },
  Perl: { extensions: ['.pl', '.pm'], shebangs: ['perl'] },

  // Systems languages
  C: { extensions: ['.c', '.h'] },
  CPlusPlus: { extensions: ['.cpp', '.cc', '.cxx', '.hpp', '.hxx', '.h++'] },
  ObjectiveC: { extensions: ['.m', '.mm'] },
  Assembly: { extensions: ['.asm', '.s'] },

  // Shell/scripting
  Shell: { extensions: ['.sh', '.bash', '.zsh'], shebangs: ['bash', 'sh', 'zsh'] },
  PowerShell: { extensions: ['.ps1', '.psm1', '.psd1'] },
  Batch: { extensions: ['.bat', '.cmd'] },

  // Data/config
  JSON: { extensions: ['.json', '.jsonc'], filenames: ['package.json', 'tsconfig.json'] },
  YAML: { extensions: ['.yaml', '.yml'] },
  TOML: { extensions: ['.toml'] },
  XML: { extensions: ['.xml'] },
  Markdown: { extensions: ['.md', '.markdown'] },
  SQL: { extensions: ['.sql'] },

  // Other
  Elixir: { extensions: ['.ex', '.exs'] },
  Erlang: { extensions: ['.erl', '.hrl'] },
  Clojure: { extensions: ['.clj', '.cljs', '.cljc'] },
  Haskell: { extensions: ['.hs', '.lhs'] },
  Lua: { extensions: ['.lua'] },
  R: { extensions: ['.r', '.R'] },
  Julia: { extensions: ['.jl'] },
  Dart: { extensions: ['.dart'] },
  Groovy: { extensions: ['.groovy', '.gvy', '.gy', '.gsh'] },
  Solidity: { extensions: ['.sol'] },
};

// Patterns to exclude from analysis
const EXCLUDE_PATTERNS = [
  /node_modules/,
  /vendor/,
  /\.git/,
  /dist/,
  /build/,
  /\.next/,
  /\.nuxt/,
  /coverage/,
  /__pycache__/,
  /\.venv/,
  /venv/,
  /target/,
  /\.idea/,
  /\.vscode/,
  /\.DS_Store/,
  /\.min\.(js|css)$/,
  /\.bundle\.(js|css)$/,
  /\.map$/,
];

interface FileInfo {
  path: string;
  extension: string;
  language?: string;
  lineCount: number;
}

/**
 * Count lines in a file
 */
async function countLines(filePath: string): Promise<number> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return content.split('\n').length;
  } catch {
    return 0;
  }
}

/**
 * Check if path should be excluded
 */
function shouldExclude(filePath: string): boolean {
  return EXCLUDE_PATTERNS.some(pattern => pattern.test(filePath));
}

/**
 * Determine language from file extension
 */
function getLanguageFromExtension(ext: string): string | undefined {
  for (const [language, def] of Object.entries(LANGUAGE_DEFINITIONS)) {
    if (def.extensions.includes(ext.toLowerCase())) {
      return language;
    }
  }
  return undefined;
}

/**
 * Determine language from filename
 */
function getLanguageFromFilename(filename: string): string | undefined {
  for (const [language, def] of Object.entries(LANGUAGE_DEFINITIONS)) {
    if (def.filenames?.includes(filename)) {
      return language;
    }
  }
  return undefined;
}

/**
 * Recursively scan directory for files
 */
async function scanDirectory(
  dirPath: string,
  files: FileInfo[] = [],
  maxFiles: number = 10000
): Promise<FileInfo[]> {
  if (files.length >= maxFiles) {
    return files;
  }

  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      if (files.length >= maxFiles) {
        break;
      }

      const fullPath = safePath(dirPath, entry.name);

      if (shouldExclude(fullPath)) {
        continue;
      }

      if (entry.isDirectory()) {
        await scanDirectory(fullPath, files, maxFiles);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        const language = getLanguageFromExtension(ext) ||
                        getLanguageFromFilename(entry.name);

        if (language) {
          const lineCount = await countLines(fullPath);
          files.push({
            path: fullPath,
            extension: ext,
            language,
            lineCount,
          });
        }
      }
    }
  } catch (error) {
    logger.debug({ error, dirPath }, 'Error scanning directory');
  }

  return files;
}

/**
 * Detect programming languages in a repository
 */
export async function detectLanguages(
  repoPath: string,
  maxFiles: number = 10000
): Promise<LanguageDetection[]> {
  logger.info({ repoPath }, 'Starting language detection');

  const startTime = Date.now();
  const files = await scanDirectory(repoPath, [], maxFiles);

  // Aggregate by language
  const languageStats = new Map<string, {
    fileCount: number;
    linesOfCode: number;
    extensions: Set<string>;
  }>();

  let totalLines = 0;

  for (const file of files) {
    if (!file.language) continue;

    totalLines += file.lineCount;

    const stats = languageStats.get(file.language) || {
      fileCount: 0,
      linesOfCode: 0,
      extensions: new Set<string>(),
    };

    stats.fileCount++;
    stats.linesOfCode += file.lineCount;
    stats.extensions.add(file.extension);

    languageStats.set(file.language, stats);
  }

  // Convert to LanguageDetection array
  const detections: LanguageDetection[] = [];

  for (const [language, stats] of languageStats.entries()) {
    detections.push({
      language,
      percentage: totalLines > 0 ? Math.round((stats.linesOfCode / totalLines) * 10000) / 100 : 0,
      fileCount: stats.fileCount,
      linesOfCode: stats.linesOfCode,
      extensions: Array.from(stats.extensions),
    });
  }

  // Sort by percentage (descending)
  detections.sort((a, b) => b.percentage - a.percentage);

  logger.info(
    {
      repoPath,
      totalFiles: files.length,
      totalLines,
      languageCount: detections.length,
      durationMs: Date.now() - startTime,
    },
    'Language detection completed'
  );

  return detections;
}

/**
 * Check if repository is polyglot (multiple main languages)
 */
export function isPolyglot(languages: LanguageDetection[], threshold: number = 20): boolean {
  const mainLanguages = languages.filter(l => l.percentage >= threshold);
  return mainLanguages.length > 1;
}

/**
 * Get primary language
 */
export function getPrimaryLanguage(languages: LanguageDetection[]): LanguageDetection | undefined {
  return languages[0];
}

/**
 * Get languages by type (web, backend, etc.)
 */
export function getLanguagesByType(languages: LanguageDetection[]): {
  web: LanguageDetection[];
  backend: LanguageDetection[];
  systems: LanguageDetection[];
  scripting: LanguageDetection[];
  data: LanguageDetection[];
} {
  const webLangs = ['JavaScript', 'TypeScript', 'HTML', 'CSS', 'SCSS', 'Less', 'Vue', 'Svelte'];
  const backendLangs = ['Python', 'Java', 'Kotlin', 'Go', 'Rust', 'Ruby', 'PHP', 'CSharp', 'FSharp', 'Scala', 'Swift', 'Perl', 'Elixir', 'Erlang', 'Clojure', 'Haskell'];
  const systemsLangs = ['C', 'CPlusPlus', 'ObjectiveC', 'Assembly', 'Rust'];
  const scriptingLangs = ['Shell', 'PowerShell', 'Batch', 'Lua', 'Ruby', 'Python', 'Perl'];
  const dataLangs = ['JSON', 'YAML', 'TOML', 'XML', 'SQL', 'Markdown'];

  return {
    web: languages.filter(l => webLangs.includes(l.language)),
    backend: languages.filter(l => backendLangs.includes(l.language)),
    systems: languages.filter(l => systemsLangs.includes(l.language)),
    scripting: languages.filter(l => scriptingLangs.includes(l.language)),
    data: languages.filter(l => dataLangs.includes(l.language)),
  };
}

export const SUPPORTED_LANGUAGES = Object.keys(LANGUAGE_DEFINITIONS);
