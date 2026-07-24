import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';

const execAsync = promisify(exec);
const logger = createLogger('language-detector');

const SCAN_TARGET = '/scan-target';

/** Extension-to-language mapping */
const EXT_MAP: Record<string, string> = {
  '.py': 'python',
  '.pyw': 'python',
  '.pyx': 'python',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.mts': 'typescript',
  '.go': 'go',
  '.java': 'java',
  '.kt': 'kotlin',
  '.kts': 'kotlin',
  '.rb': 'ruby',
  '.rs': 'rust',
  '.c': 'c',
  '.h': 'c',
  '.cpp': 'cpp',
  '.cc': 'cpp',
  '.hpp': 'cpp',
  '.cs': 'csharp',
  '.php': 'php',
  '.swift': 'swift',
  '.scala': 'scala',
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
  '.sql': 'sql',
  '.tf': 'terraform',
  '.hcl': 'terraform',
  '.yml': 'yaml',
  '.yaml': 'yaml',
  '.json': 'json',
  '.xml': 'xml',
  '.html': 'html',
  '.htm': 'html',
  '.css': 'css',
  '.scss': 'css',
  '.sass': 'css',
  '.less': 'css',
};

/** Filename-to-language for special files */
const FILENAME_MAP: Record<string, string> = {
  'Dockerfile': 'docker',
  'docker-compose.yml': 'docker',
  'docker-compose.yaml': 'docker',
  'Containerfile': 'docker',
  'Makefile': 'make',
  'CMakeLists.txt': 'cmake',
  'Gemfile': 'ruby',
  'Rakefile': 'ruby',
  'build.gradle': 'java',
  'pom.xml': 'java',
  'Cargo.toml': 'rust',
  'go.mod': 'go',
  'go.sum': 'go',
  'package.json': 'javascript',
  'tsconfig.json': 'typescript',
  'requirements.txt': 'python',
  'setup.py': 'python',
  'pyproject.toml': 'python',
  'Pipfile': 'python',
};

export interface LanguageBreakdown {
  /** Language name -> percentage (0-100) */
  languages: Record<string, number>;
  /** Language name -> file count */
  fileCounts: Record<string, number>;
  /** Total files analyzed */
  totalFiles: number;
  /** Recommended scanners based on detected languages */
  recommendedScanners: string[];
}

/** Language -> scanners that are relevant for it */
const LANGUAGE_SCANNERS: Record<string, string[]> = {
  python:     ['bandit', 'opengrep', 'gitleaks', 'mutmut', 'scancode'],
  javascript: ['eslint-security', 'opengrep', 'trivy', 'gitleaks', 'stryker', 'scancode'],
  typescript: ['eslint-security', 'opengrep', 'trivy', 'gitleaks', 'stryker', 'scancode'],
  go:         ['gosec', 'opengrep', 'trivy', 'gitleaks', 'scancode'],
  java:       ['pmd', 'opengrep', 'trivy', 'gitleaks', 'pitest', 'scancode'],
  kotlin:     ['pmd', 'opengrep', 'trivy', 'gitleaks', 'pitest', 'scancode'],
  ruby:       ['opengrep', 'trivy', 'gitleaks', 'scancode'],
  rust:       ['opengrep', 'trivy', 'gitleaks', 'scancode'],
  c:          ['opengrep', 'trivy', 'gitleaks', 'aflpp', 'scancode'],
  cpp:        ['opengrep', 'trivy', 'gitleaks', 'aflpp', 'scancode'],
  csharp:     ['opengrep', 'trivy', 'gitleaks', 'scancode'],
  php:        ['opengrep', 'trivy', 'gitleaks', 'scancode'],
  docker:     ['checkov', 'trivy', 'dockle', 'gitleaks'],
  terraform:  ['checkov', 'conftest', 'opa', 'gitleaks'],
  yaml:       ['checkov', 'conftest'],
  html:       ['pa11y', 'nuclei'],
  sql:        ['opengrep', 'gitleaks'],
  shell:      ['opengrep', 'gitleaks'],
};

/** Scanners that should always run regardless of language */
const UNIVERSAL_SCANNERS = ['gitleaks', 'trivy', 'syft', 'package-validator'];

/**
 * Detect programming languages in the scan target directory.
 * Uses `find` + extension counting for speed.
 */
export async function detectLanguages(targetDir?: string): Promise<LanguageBreakdown> {
  const dir = targetDir || SCAN_TARGET;
  const fileCounts: Record<string, number> = {};
  let totalFiles = 0;

  try {
    // Get all source files (excluding .git, node_modules, vendor, etc.)
    const { stdout } = await execAsync(
      `find ${dir} -type f ` +
      `-not -path '*/.git/*' ` +
      `-not -path '*/node_modules/*' ` +
      `-not -path '*/vendor/*' ` +
      `-not -path '*/__pycache__/*' ` +
      `-not -path '*/.venv/*' ` +
      `-not -path '*/dist/*' ` +
      `-not -path '*/build/*' ` +
      `-not -path '*/.next/*' ` +
      `| head -10000`,
      { timeout: 15000 }
    );

    const files = stdout.trim().split('\n').filter(Boolean);

    for (const filePath of files) {
      const filename = filePath.split('/').pop() || '';

      // Check exact filename first
      if (FILENAME_MAP[filename]) {
        const lang = FILENAME_MAP[filename];
        fileCounts[lang] = (fileCounts[lang] || 0) + 1;
        totalFiles++;
        continue;
      }

      // Check extension
      const extMatch = filename.match(/(\.[^.]+)$/);
      if (extMatch && EXT_MAP[extMatch[1].toLowerCase()]) {
        const lang = EXT_MAP[extMatch[1].toLowerCase()];
        fileCounts[lang] = (fileCounts[lang] || 0) + 1;
        totalFiles++;
      }
    }
  } catch (error) {
    logger.warn({ error, dir }, 'Language detection failed — defaulting to standard profile');
    return {
      languages: {},
      fileCounts: {},
      totalFiles: 0,
      recommendedScanners: [],
    };
  }

  // Calculate percentages
  const languages: Record<string, number> = {};
  for (const [lang, count] of Object.entries(fileCounts)) {
    languages[lang] = totalFiles > 0 ? Math.round((count / totalFiles) * 100) : 0;
  }

  // Sort by percentage descending
  const sorted = Object.entries(languages).sort((a, b) => b[1] - a[1]);
  const sortedLanguages: Record<string, number> = {};
  for (const [lang, pct] of sorted) {
    sortedLanguages[lang] = pct;
  }

  // Build recommended scanners from detected languages
  const scannerSet = new Set<string>(UNIVERSAL_SCANNERS);
  for (const [lang, pct] of sorted) {
    // Only recommend scanners for languages comprising >= 2% of the codebase
    if (pct >= 2 && LANGUAGE_SCANNERS[lang]) {
      for (const scanner of LANGUAGE_SCANNERS[lang]) {
        scannerSet.add(scanner);
      }
    }
  }

  const recommendedScanners = [...scannerSet];

  logger.info(
    { totalFiles, topLanguages: sorted.slice(0, 5), recommendedScanners: recommendedScanners.length },
    'Language detection complete'
  );

  return {
    languages: sortedLanguages,
    fileCounts,
    totalFiles,
    recommendedScanners,
  };
}
