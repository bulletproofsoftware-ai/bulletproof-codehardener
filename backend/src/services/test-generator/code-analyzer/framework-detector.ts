/**
 * CA-002: Framework Detection
 * Detects web frameworks, libraries, and tools with confidence scores
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { createLogger } from '../../../utils/logger.js';
import { safePath } from '../../../utils/safePath.js';
import type { FrameworkDetection, LanguageDetection } from '../types.js';

const logger = createLogger('framework-detector');

// Framework definitions with detection patterns
interface FrameworkDefinition {
  name: string;
  type: 'web' | 'api' | 'cli' | 'library' | 'mobile' | 'other';
  languages: string[];
  indicators: FrameworkIndicator[];
}

interface FrameworkIndicator {
  type: 'package' | 'file' | 'import' | 'config';
  pattern: string | RegExp;
  weight: number; // 0-1
  versionPattern?: RegExp;
}

const FRAMEWORK_DEFINITIONS: FrameworkDefinition[] = [
  // JavaScript/TypeScript Web Frameworks
  {
    name: 'Express',
    type: 'api',
    languages: ['JavaScript', 'TypeScript'],
    indicators: [
      { type: 'package', pattern: 'express', weight: 1.0 },
      { type: 'import', pattern: /require\(['"]express['"]\)|from\s+['"]express['"]/, weight: 0.9 },
      { type: 'import', pattern: /app\s*=\s*express\(\)/, weight: 0.8 },
    ],
  },
  {
    name: 'Fastify',
    type: 'api',
    languages: ['JavaScript', 'TypeScript'],
    indicators: [
      { type: 'package', pattern: 'fastify', weight: 1.0 },
      { type: 'import', pattern: /require\(['"]fastify['"]\)|from\s+['"]fastify['"]/, weight: 0.9 },
    ],
  },
  {
    name: 'NestJS',
    type: 'api',
    languages: ['TypeScript'],
    indicators: [
      { type: 'package', pattern: '@nestjs/core', weight: 1.0 },
      { type: 'file', pattern: 'nest-cli.json', weight: 0.9 },
      { type: 'import', pattern: /@nestjs\//, weight: 0.8 },
    ],
  },
  {
    name: 'Koa',
    type: 'api',
    languages: ['JavaScript', 'TypeScript'],
    indicators: [
      { type: 'package', pattern: 'koa', weight: 1.0 },
      { type: 'import', pattern: /require\(['"]koa['"]\)|from\s+['"]koa['"]/, weight: 0.9 },
    ],
  },
  {
    name: 'Hapi',
    type: 'api',
    languages: ['JavaScript', 'TypeScript'],
    indicators: [
      { type: 'package', pattern: '@hapi/hapi', weight: 1.0 },
      { type: 'import', pattern: /@hapi\/hapi/, weight: 0.9 },
    ],
  },

  // JavaScript/TypeScript Frontend Frameworks
  {
    name: 'React',
    type: 'web',
    languages: ['JavaScript', 'TypeScript'],
    indicators: [
      { type: 'package', pattern: 'react', weight: 1.0 },
      { type: 'import', pattern: /from\s+['"]react['"]/, weight: 0.9 },
      { type: 'import', pattern: /import\s+React/, weight: 0.8 },
    ],
  },
  {
    name: 'Next.js',
    type: 'web',
    languages: ['JavaScript', 'TypeScript'],
    indicators: [
      { type: 'package', pattern: 'next', weight: 1.0 },
      { type: 'file', pattern: 'next.config.js', weight: 0.95 },
      { type: 'file', pattern: 'next.config.mjs', weight: 0.95 },
      { type: 'file', pattern: 'next.config.ts', weight: 0.95 },
    ],
  },
  {
    name: 'Vue.js',
    type: 'web',
    languages: ['JavaScript', 'TypeScript', 'Vue'],
    indicators: [
      { type: 'package', pattern: 'vue', weight: 1.0 },
      { type: 'file', pattern: /\.vue$/, weight: 0.9 },
      { type: 'import', pattern: /from\s+['"]vue['"]/, weight: 0.8 },
    ],
  },
  {
    name: 'Nuxt',
    type: 'web',
    languages: ['JavaScript', 'TypeScript', 'Vue'],
    indicators: [
      { type: 'package', pattern: 'nuxt', weight: 1.0 },
      { type: 'file', pattern: 'nuxt.config.js', weight: 0.95 },
      { type: 'file', pattern: 'nuxt.config.ts', weight: 0.95 },
    ],
  },
  {
    name: 'Angular',
    type: 'web',
    languages: ['TypeScript'],
    indicators: [
      { type: 'package', pattern: '@angular/core', weight: 1.0 },
      { type: 'file', pattern: 'angular.json', weight: 0.95 },
      { type: 'import', pattern: /@angular\//, weight: 0.8 },
    ],
  },
  {
    name: 'Svelte',
    type: 'web',
    languages: ['JavaScript', 'TypeScript', 'Svelte'],
    indicators: [
      { type: 'package', pattern: 'svelte', weight: 1.0 },
      { type: 'file', pattern: 'svelte.config.js', weight: 0.95 },
      { type: 'file', pattern: /\.svelte$/, weight: 0.9 },
    ],
  },

  // Python Frameworks
  {
    name: 'Django',
    type: 'web',
    languages: ['Python'],
    indicators: [
      { type: 'package', pattern: 'Django', weight: 1.0 },
      { type: 'package', pattern: 'django', weight: 1.0 },
      { type: 'file', pattern: 'manage.py', weight: 0.7 },
      { type: 'file', pattern: 'settings.py', weight: 0.5 },
      { type: 'import', pattern: /from\s+django/, weight: 0.9 },
    ],
  },
  {
    name: 'Flask',
    type: 'api',
    languages: ['Python'],
    indicators: [
      { type: 'package', pattern: 'Flask', weight: 1.0 },
      { type: 'package', pattern: 'flask', weight: 1.0 },
      { type: 'import', pattern: /from\s+flask\s+import/, weight: 0.9 },
    ],
  },
  {
    name: 'FastAPI',
    type: 'api',
    languages: ['Python'],
    indicators: [
      { type: 'package', pattern: 'fastapi', weight: 1.0 },
      { type: 'import', pattern: /from\s+fastapi\s+import/, weight: 0.9 },
    ],
  },
  {
    name: 'Tornado',
    type: 'api',
    languages: ['Python'],
    indicators: [
      { type: 'package', pattern: 'tornado', weight: 1.0 },
      { type: 'import', pattern: /import\s+tornado/, weight: 0.9 },
    ],
  },

  // Go Frameworks
  {
    name: 'Gin',
    type: 'api',
    languages: ['Go'],
    indicators: [
      { type: 'package', pattern: 'github.com/gin-gonic/gin', weight: 1.0 },
      { type: 'import', pattern: /gin-gonic\/gin/, weight: 0.9 },
    ],
  },
  {
    name: 'Echo',
    type: 'api',
    languages: ['Go'],
    indicators: [
      { type: 'package', pattern: 'github.com/labstack/echo', weight: 1.0 },
      { type: 'import', pattern: /labstack\/echo/, weight: 0.9 },
    ],
  },
  {
    name: 'Fiber',
    type: 'api',
    languages: ['Go'],
    indicators: [
      { type: 'package', pattern: 'github.com/gofiber/fiber', weight: 1.0 },
      { type: 'import', pattern: /gofiber\/fiber/, weight: 0.9 },
    ],
  },
  {
    name: 'Chi',
    type: 'api',
    languages: ['Go'],
    indicators: [
      { type: 'package', pattern: 'github.com/go-chi/chi', weight: 1.0 },
      { type: 'import', pattern: /go-chi\/chi/, weight: 0.9 },
    ],
  },

  // Java Frameworks
  {
    name: 'Spring Boot',
    type: 'web',
    languages: ['Java', 'Kotlin'],
    indicators: [
      { type: 'package', pattern: 'spring-boot', weight: 1.0 },
      { type: 'file', pattern: 'application.properties', weight: 0.6 },
      { type: 'file', pattern: 'application.yml', weight: 0.6 },
      { type: 'import', pattern: /org\.springframework\.boot/, weight: 0.9 },
    ],
  },
  {
    name: 'Micronaut',
    type: 'api',
    languages: ['Java', 'Kotlin', 'Groovy'],
    indicators: [
      { type: 'package', pattern: 'io.micronaut', weight: 1.0 },
      { type: 'import', pattern: /io\.micronaut/, weight: 0.9 },
    ],
  },
  {
    name: 'Quarkus',
    type: 'api',
    languages: ['Java', 'Kotlin'],
    indicators: [
      { type: 'package', pattern: 'io.quarkus', weight: 1.0 },
      { type: 'import', pattern: /io\.quarkus/, weight: 0.9 },
    ],
  },

  // Ruby Frameworks
  {
    name: 'Rails',
    type: 'web',
    languages: ['Ruby'],
    indicators: [
      { type: 'package', pattern: 'rails', weight: 1.0 },
      { type: 'file', pattern: 'Gemfile', weight: 0.5 },
      { type: 'file', pattern: 'config/routes.rb', weight: 0.9 },
    ],
  },
  {
    name: 'Sinatra',
    type: 'api',
    languages: ['Ruby'],
    indicators: [
      { type: 'package', pattern: 'sinatra', weight: 1.0 },
      { type: 'import', pattern: /require\s+['"]sinatra['"]/, weight: 0.9 },
    ],
  },

  // PHP Frameworks
  {
    name: 'Laravel',
    type: 'web',
    languages: ['PHP'],
    indicators: [
      { type: 'package', pattern: 'laravel/framework', weight: 1.0 },
      { type: 'file', pattern: 'artisan', weight: 0.8 },
      { type: 'file', pattern: 'config/app.php', weight: 0.7 },
    ],
  },
  {
    name: 'Symfony',
    type: 'web',
    languages: ['PHP'],
    indicators: [
      { type: 'package', pattern: 'symfony/framework-bundle', weight: 1.0 },
      { type: 'file', pattern: 'bin/console', weight: 0.7 },
    ],
  },

  // Rust Frameworks
  {
    name: 'Actix-web',
    type: 'api',
    languages: ['Rust'],
    indicators: [
      { type: 'package', pattern: 'actix-web', weight: 1.0 },
      { type: 'import', pattern: /actix_web/, weight: 0.9 },
    ],
  },
  {
    name: 'Rocket',
    type: 'api',
    languages: ['Rust'],
    indicators: [
      { type: 'package', pattern: 'rocket', weight: 1.0 },
      { type: 'import', pattern: /rocket::/, weight: 0.9 },
    ],
  },
  {
    name: 'Axum',
    type: 'api',
    languages: ['Rust'],
    indicators: [
      { type: 'package', pattern: 'axum', weight: 1.0 },
      { type: 'import', pattern: /axum::/, weight: 0.9 },
    ],
  },

  // Mobile Frameworks
  {
    name: 'React Native',
    type: 'mobile',
    languages: ['JavaScript', 'TypeScript'],
    indicators: [
      { type: 'package', pattern: 'react-native', weight: 1.0 },
      { type: 'file', pattern: 'metro.config.js', weight: 0.8 },
    ],
  },
  {
    name: 'Flutter',
    type: 'mobile',
    languages: ['Dart'],
    indicators: [
      { type: 'file', pattern: 'pubspec.yaml', weight: 0.7 },
      { type: 'package', pattern: 'flutter', weight: 1.0 },
    ],
  },
];

/**
 * Read package.json dependencies
 */
async function readPackageJson(repoPath: string): Promise<Record<string, string>> {
  try {
    const pkgPath = safePath(repoPath, 'package.json');
    const content = await fs.readFile(pkgPath, 'utf-8');
    const pkg = JSON.parse(content);
    return {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
    };
  } catch {
    return {};
  }
}

/**
 * Read requirements.txt dependencies
 */
async function readRequirementsTxt(repoPath: string): Promise<string[]> {
  try {
    const reqPath = safePath(repoPath, 'requirements.txt');
    const content = await fs.readFile(reqPath, 'utf-8');
    return content.split('\n')
      .map(line => line.split('==')[0].split('>=')[0].split('<=')[0].trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Read go.mod dependencies
 */
async function readGoMod(repoPath: string): Promise<string[]> {
  try {
    const modPath = safePath(repoPath, 'go.mod');
    const content = await fs.readFile(modPath, 'utf-8');
    const deps: string[] = [];
    const lines = content.split('\n');
    for (const line of lines) {
      const match = line.match(/^\s*([a-zA-Z0-9./-]+)\s+v/);
      if (match) {
        deps.push(match[1]);
      }
    }
    return deps;
  } catch {
    return [];
  }
}

/**
 * Read Gemfile dependencies
 */
async function readGemfile(repoPath: string): Promise<string[]> {
  try {
    const gemPath = safePath(repoPath, 'Gemfile');
    const content = await fs.readFile(gemPath, 'utf-8');
    const deps: string[] = [];
    const lines = content.split('\n');
    for (const line of lines) {
      const match = line.match(/gem\s+['"]([^'"]+)['"]/);
      if (match) {
        deps.push(match[1]);
      }
    }
    return deps;
  } catch {
    return [];
  }
}

/**
 * Read composer.json dependencies (PHP)
 */
async function readComposerJson(repoPath: string): Promise<string[]> {
  try {
    const composerPath = safePath(repoPath, 'composer.json');
    const content = await fs.readFile(composerPath, 'utf-8');
    const pkg = JSON.parse(content);
    return [
      ...Object.keys(pkg.require || {}),
      ...Object.keys(pkg['require-dev'] || {}),
    ];
  } catch {
    return [];
  }
}

/**
 * Read Cargo.toml dependencies (Rust)
 */
async function readCargoToml(repoPath: string): Promise<string[]> {
  try {
    const cargoPath = safePath(repoPath, 'Cargo.toml');
    const content = await fs.readFile(cargoPath, 'utf-8');
    const deps: string[] = [];
    const lines = content.split('\n');
    let inDeps = false;
    for (const line of lines) {
      if (line.match(/^\[.*dependencies.*\]/)) {
        inDeps = true;
        continue;
      }
      if (line.startsWith('[') && inDeps) {
        inDeps = false;
        continue;
      }
      if (inDeps) {
        const match = line.match(/^([a-zA-Z0-9_-]+)\s*=/);
        if (match) {
          deps.push(match[1]);
        }
      }
    }
    return deps;
  } catch {
    return [];
  }
}

/**
 * Check if file exists
 */
async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Search for pattern in source files
 */
async function searchInFiles(
  repoPath: string,
  pattern: RegExp,
  extensions: string[]
): Promise<boolean> {
  const maxFiles = 100;
  let filesChecked = 0;

  async function search(dirPath: string): Promise<boolean> {
    if (filesChecked >= maxFiles) return false;

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        if (filesChecked >= maxFiles) return false;

        const fullPath = safePath(dirPath, entry.name);

        // Skip common non-source directories
        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'vendor', 'dist', 'build'].includes(entry.name)) {
            continue;
          }
          if (await search(fullPath)) return true;
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name);
          if (extensions.includes(ext)) {
            filesChecked++;
            try {
              const content = await fs.readFile(fullPath, 'utf-8');
              if (pattern.test(content)) {
                return true;
              }
            } catch {
              // Skip files we can't read
            }
          }
        }
      }
    } catch {
      // Skip directories we can't access
    }

    return false;
  }

  return search(repoPath);
}

/**
 * Detect frameworks in a repository
 */
export async function detectFrameworks(
  repoPath: string,
  languages: LanguageDetection[]
): Promise<FrameworkDetection[]> {
  logger.info({ repoPath, languageCount: languages.length }, 'Starting framework detection');

  const startTime = Date.now();
  const detectedLanguages = new Set(languages.map(l => l.language));
  const detections: FrameworkDetection[] = [];

  // Read all dependency manifests
  const [npmDeps, pyDeps, goDeps, rubyDeps, phpDeps, rustDeps] = await Promise.all([
    readPackageJson(repoPath),
    readRequirementsTxt(repoPath),
    readGoMod(repoPath),
    readGemfile(repoPath),
    readComposerJson(repoPath),
    readCargoToml(repoPath),
  ]);

  // All dependencies as array
  const allDeps = new Set([
    ...Object.keys(npmDeps),
    ...pyDeps,
    ...goDeps,
    ...rubyDeps,
    ...phpDeps,
    ...rustDeps,
  ]);

  // Check each framework
  for (const framework of FRAMEWORK_DEFINITIONS) {
    // Skip if none of the framework's languages are detected
    if (!framework.languages.some(l => detectedLanguages.has(l))) {
      continue;
    }

    let totalWeight = 0;
    const matchedIndicators: string[] = [];

    for (const indicator of framework.indicators) {
      let matched = false;

      switch (indicator.type) {
        case 'package':
          if (typeof indicator.pattern === 'string' && allDeps.has(indicator.pattern)) {
            matched = true;
          }
          break;

        case 'file':
          if (typeof indicator.pattern === 'string') {
            matched = await fileExists(safePath(repoPath, indicator.pattern));
          } else if (indicator.pattern instanceof RegExp) {
            // For regex patterns on files, we check if any matching file exists
            // This is simplified - in production you'd scan the directory
            matched = false;
          }
          break;

        case 'import':
          if (indicator.pattern instanceof RegExp) {
            const extensions = ['.js', '.ts', '.tsx', '.jsx', '.py', '.go', '.rb', '.php', '.rs'];
            matched = await searchInFiles(repoPath, indicator.pattern, extensions);
          }
          break;
      }

      if (matched) {
        totalWeight += indicator.weight;
        const patternStr = indicator.pattern instanceof RegExp
          ? indicator.pattern.source
          : indicator.pattern;
        matchedIndicators.push(`${indicator.type}:${patternStr}`);
      }
    }

    // Calculate confidence (normalize to 0-1)
    const maxPossibleWeight = framework.indicators.reduce((sum, i) => sum + i.weight, 0);
    const confidence = maxPossibleWeight > 0 ? Math.min(totalWeight / maxPossibleWeight, 1) : 0;

    // Only include frameworks with some confidence
    if (confidence >= 0.3) {
      // Try to get version from npm dependencies
      let version: string | undefined;
      for (const indicator of framework.indicators) {
        if (indicator.type === 'package' && typeof indicator.pattern === 'string') {
          version = npmDeps[indicator.pattern];
          if (version) break;
        }
      }

      detections.push({
        framework: framework.name,
        type: framework.type,
        confidence: Math.round(confidence * 100) / 100,
        version,
        indicators: matchedIndicators,
      });
    }
  }

  // Sort by confidence (descending)
  detections.sort((a, b) => b.confidence - a.confidence);

  logger.info(
    {
      repoPath,
      frameworkCount: detections.length,
      frameworks: detections.map(f => f.framework),
      durationMs: Date.now() - startTime,
    },
    'Framework detection completed'
  );

  return detections;
}

/**
 * Get primary framework
 */
export function getPrimaryFramework(frameworks: FrameworkDetection[]): FrameworkDetection | undefined {
  return frameworks[0];
}

/**
 * Check if using specific framework
 */
export function usesFramework(frameworks: FrameworkDetection[], name: string): boolean {
  return frameworks.some(f => f.framework.toLowerCase() === name.toLowerCase());
}
