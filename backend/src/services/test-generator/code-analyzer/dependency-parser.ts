/**
 * CA-007: Dependency Parsing
 * Parses project dependencies from manifest files
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { createLogger } from '../../../utils/logger.js';
import { safePath } from '../../../utils/safePath.js';
import type { Dependency } from '../types.js';

const logger = createLogger('dependency-parser');

// Manifest file patterns by ecosystem
const MANIFEST_FILES: Record<Dependency['ecosystem'], string[]> = {
  npm: ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
  pip: ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py', 'setup.cfg'],
  go: ['go.mod', 'go.sum'],
  maven: ['pom.xml', 'build.gradle', 'build.gradle.kts'],
  gem: ['Gemfile', 'Gemfile.lock', '*.gemspec'],
  cargo: ['Cargo.toml', 'Cargo.lock'],
  composer: ['composer.json', 'composer.lock'],
  nuget: ['*.csproj', 'packages.config', 'Directory.Build.props'],
};

interface ManifestFile {
  path: string;
  relativePath: string;
  content: string;
  ecosystem: Dependency['ecosystem'];
}

/**
 * Find manifest files in repository
 */
async function findManifestFiles(repoPath: string): Promise<ManifestFile[]> {
  const manifests: ManifestFile[] = [];

  async function scan(dirPath: string, depth: number = 0): Promise<void> {
    // Limit recursion depth
    if (depth > 5) return;

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = safePath(dirPath, entry.name);
        const relativePath = path.relative(repoPath, fullPath);

        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'vendor', 'dist', 'build', '__pycache__', 'venv', '.venv', 'target'].includes(entry.name)) {
            continue;
          }
          await scan(fullPath, depth + 1);
        } else if (entry.isFile()) {
          // Check each ecosystem for matching manifest
          for (const [ecosystem, patterns] of Object.entries(MANIFEST_FILES)) {
            for (const pattern of patterns) {
              if (pattern.includes('*')) {
                // Glob pattern
                const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace('\\*', '.*');
                const regex = new RegExp('^' + escaped + '$');
                if (regex.test(entry.name)) {
                  try {
                    const content = await fs.readFile(fullPath, 'utf-8');
                    manifests.push({
                      path: fullPath,
                      relativePath,
                      content,
                      ecosystem: ecosystem as Dependency['ecosystem'],
                    });
                  } catch {
                    // Skip unreadable files
                  }
                  break;
                }
              } else if (entry.name === pattern) {
                try {
                  const content = await fs.readFile(fullPath, 'utf-8');
                  manifests.push({
                    path: fullPath,
                    relativePath,
                    content,
                    ecosystem: ecosystem as Dependency['ecosystem'],
                  });
                } catch {
                  // Skip unreadable files
                }
                break;
              }
            }
          }
        }
      }
    } catch {
      // Skip inaccessible directories
    }
  }

  await scan(repoPath);
  return manifests;
}

/**
 * Parse package.json
 */
function parsePackageJson(content: string, manifestPath: string): Dependency[] {
  const deps: Dependency[] = [];

  try {
    const pkg = JSON.parse(content);

    // Production dependencies
    if (pkg.dependencies) {
      for (const [name, version] of Object.entries(pkg.dependencies)) {
        deps.push({
          name,
          version: String(version).replace(/^[^\d]*/, ''),
          manifest: manifestPath,
          type: 'direct',
          ecosystem: 'npm',
        });
      }
    }

    // Dev dependencies
    if (pkg.devDependencies) {
      for (const [name, version] of Object.entries(pkg.devDependencies)) {
        deps.push({
          name,
          version: String(version).replace(/^[^\d]*/, ''),
          manifest: manifestPath,
          type: 'dev',
          ecosystem: 'npm',
        });
      }
    }

    // Peer dependencies
    if (pkg.peerDependencies) {
      for (const [name, version] of Object.entries(pkg.peerDependencies)) {
        deps.push({
          name,
          version: String(version).replace(/^[^\d]*/, ''),
          manifest: manifestPath,
          type: 'direct',
          ecosystem: 'npm',
        });
      }
    }
  } catch {
    logger.debug({ manifestPath }, 'Failed to parse package.json');
  }

  return deps;
}

/**
 * Parse requirements.txt
 */
function parseRequirementsTxt(content: string, manifestPath: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
      continue;
    }

    // Parse package==version, package>=version, etc.
    const match = trimmed.match(/^([a-zA-Z0-9_-]+)(?:\[.*?\])?(?:([=<>!~]+)(.+))?/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[3] || '*',
        manifest: manifestPath,
        type: 'direct',
        ecosystem: 'pip',
      });
    }
  }

  return deps;
}

/**
 * Parse pyproject.toml
 */
function parsePyprojectToml(content: string, manifestPath: string): Dependency[] {
  const deps: Dependency[] = [];

  // Simple pattern matching for dependencies section
  // [project.dependencies] or [tool.poetry.dependencies]
  const dependenciesMatch = content.match(/\[(?:project\.)?dependencies\]\s*([\s\S]*?)(?=\[|$)/);

  if (dependenciesMatch) {
    const depsSection = dependenciesMatch[1];
    const lines = depsSection.split('\n');

    for (const line of lines) {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*["']?([^"']+)["']?/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[2].replace(/^[^\d]*/, ''),
          manifest: manifestPath,
          type: 'direct',
          ecosystem: 'pip',
        });
      }
    }
  }

  // Parse poetry style
  const poetryMatch = content.match(/\[tool\.poetry\.dependencies\]\s*([\s\S]*?)(?=\[|$)/);
  if (poetryMatch) {
    const depsSection = poetryMatch[1];
    const lines = depsSection.split('\n');

    for (const line of lines) {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*["']?([^"']+)["']?/);
      if (match && match[1] !== 'python') {
        deps.push({
          name: match[1],
          version: match[2].replace(/^[^\d]*/, ''),
          manifest: manifestPath,
          type: 'direct',
          ecosystem: 'pip',
        });
      }
    }
  }

  return deps;
}

/**
 * Parse go.mod
 */
function parseGoMod(content: string, manifestPath: string): Dependency[] {
  const deps: Dependency[] = [];

  // Match require block
  const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
  if (requireBlock) {
    const lines = requireBlock[1].split('\n');
    for (const line of lines) {
      const match = line.trim().match(/^(\S+)\s+(\S+)/);
      if (match && !match[0].startsWith('//')) {
        deps.push({
          name: match[1],
          version: match[2].replace(/^v/, ''),
          manifest: manifestPath,
          type: 'direct',
          ecosystem: 'go',
        });
      }
    }
  }

  // Match single require statements
  const singleRequires = content.matchAll(/require\s+(\S+)\s+(\S+)/g);
  for (const match of singleRequires) {
    deps.push({
      name: match[1],
      version: match[2].replace(/^v/, ''),
      manifest: manifestPath,
      type: 'direct',
      ecosystem: 'go',
    });
  }

  return deps;
}

/**
 * Parse Gemfile
 */
function parseGemfile(content: string, manifestPath: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split('\n');

  for (const line of lines) {
    // Match gem 'name', 'version' or gem 'name', '~> version'
    const match = line.match(/gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[2] || '*',
        manifest: manifestPath,
        type: 'direct',
        ecosystem: 'gem',
      });
    }
  }

  return deps;
}

/**
 * Parse Cargo.toml
 */
function parseCargoToml(content: string, manifestPath: string): Dependency[] {
  const deps: Dependency[] = [];

  // Parse [dependencies] section
  const dependenciesMatch = content.match(/\[dependencies\]\s*([\s\S]*?)(?=\[|$)/);
  if (dependenciesMatch) {
    const lines = dependenciesMatch[1].split('\n');
    for (const line of lines) {
      // Simple version: name = "version"
      const simpleMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
      if (simpleMatch) {
        deps.push({
          name: simpleMatch[1],
          version: simpleMatch[2],
          manifest: manifestPath,
          type: 'direct',
          ecosystem: 'cargo',
        });
        continue;
      }

      // Complex version: name = { version = "x.x", ... }
      const complexMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"/);
      if (complexMatch) {
        deps.push({
          name: complexMatch[1],
          version: complexMatch[2],
          manifest: manifestPath,
          type: 'direct',
          ecosystem: 'cargo',
        });
      }
    }
  }

  // Parse [dev-dependencies] section
  const devDepsMatch = content.match(/\[dev-dependencies\]\s*([\s\S]*?)(?=\[|$)/);
  if (devDepsMatch) {
    const lines = devDepsMatch[1].split('\n');
    for (const line of lines) {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[2],
          manifest: manifestPath,
          type: 'dev',
          ecosystem: 'cargo',
        });
      }
    }
  }

  return deps;
}

/**
 * Parse composer.json
 */
function parseComposerJson(content: string, manifestPath: string): Dependency[] {
  const deps: Dependency[] = [];

  try {
    const composer = JSON.parse(content);

    if (composer.require) {
      for (const [name, version] of Object.entries(composer.require)) {
        if (!name.startsWith('php') && !name.startsWith('ext-')) {
          deps.push({
            name,
            version: String(version).replace(/^[^\d]*/, ''),
            manifest: manifestPath,
            type: 'direct',
            ecosystem: 'composer',
          });
        }
      }
    }

    if (composer['require-dev']) {
      for (const [name, version] of Object.entries(composer['require-dev'])) {
        deps.push({
          name,
          version: String(version).replace(/^[^\d]*/, ''),
          manifest: manifestPath,
          type: 'dev',
          ecosystem: 'composer',
        });
      }
    }
  } catch {
    logger.debug({ manifestPath }, 'Failed to parse composer.json');
  }

  return deps;
}

/**
 * Parse pom.xml (Maven)
 */
function parsePomXml(content: string, manifestPath: string): Dependency[] {
  const deps: Dependency[] = [];

  // Simple XML parsing for dependencies
  const dependencyMatches = content.matchAll(
    /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>(?:\s*<version>([^<]+)<\/version>)?/g
  );

  for (const match of dependencyMatches) {
    deps.push({
      name: `${match[1]}:${match[2]}`,
      version: match[3] || 'managed',
      manifest: manifestPath,
      type: 'direct',
      ecosystem: 'maven',
    });
  }

  return deps;
}

/**
 * Parse .csproj (NuGet)
 */
function parseCsproj(content: string, manifestPath: string): Dependency[] {
  const deps: Dependency[] = [];

  // Parse PackageReference elements
  const matches = content.matchAll(/<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?/g);

  for (const match of matches) {
    deps.push({
      name: match[1],
      version: match[2] || '*',
      manifest: manifestPath,
      type: 'direct',
      ecosystem: 'nuget',
    });
  }

  return deps;
}

/**
 * Parse dependencies from a manifest file
 */
function parseManifest(manifest: ManifestFile): Dependency[] {
  const filename = path.basename(manifest.relativePath);

  switch (filename) {
    case 'package.json':
      return parsePackageJson(manifest.content, manifest.relativePath);

    case 'requirements.txt':
      return parseRequirementsTxt(manifest.content, manifest.relativePath);

    case 'pyproject.toml':
      return parsePyprojectToml(manifest.content, manifest.relativePath);

    case 'go.mod':
      return parseGoMod(manifest.content, manifest.relativePath);

    case 'Gemfile':
      return parseGemfile(manifest.content, manifest.relativePath);

    case 'Cargo.toml':
      return parseCargoToml(manifest.content, manifest.relativePath);

    case 'composer.json':
      return parseComposerJson(manifest.content, manifest.relativePath);

    case 'pom.xml':
      return parsePomXml(manifest.content, manifest.relativePath);

    default:
      if (filename.endsWith('.csproj')) {
        return parseCsproj(manifest.content, manifest.relativePath);
      }
      return [];
  }
}

/**
 * Parse all dependencies in a repository
 */
export async function parseDependencies(repoPath: string): Promise<Dependency[]> {
  logger.info({ repoPath }, 'Starting dependency parsing');

  const startTime = Date.now();
  const allDeps: Dependency[] = [];

  const manifests = await findManifestFiles(repoPath);

  for (const manifest of manifests) {
    const deps = parseManifest(manifest);
    allDeps.push(...deps);
  }

  // Deduplicate by name and ecosystem
  const uniqueDeps: Dependency[] = [];
  const seen = new Set<string>();

  for (const dep of allDeps) {
    const key = `${dep.ecosystem}:${dep.name}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueDeps.push(dep);
    }
  }

  // Sort by ecosystem and name
  uniqueDeps.sort((a, b) => {
    const ecoCompare = a.ecosystem.localeCompare(b.ecosystem);
    if (ecoCompare !== 0) return ecoCompare;
    return a.name.localeCompare(b.name);
  });

  logger.info(
    {
      repoPath,
      dependencyCount: uniqueDeps.length,
      manifestCount: manifests.length,
      durationMs: Date.now() - startTime,
    },
    'Dependency parsing completed'
  );

  return uniqueDeps;
}

/**
 * Get dependencies by ecosystem
 */
export function getDependenciesByEcosystem(
  deps: Dependency[],
  ecosystem: Dependency['ecosystem']
): Dependency[] {
  return deps.filter(d => d.ecosystem === ecosystem);
}

/**
 * Get direct dependencies
 */
export function getDirectDependencies(deps: Dependency[]): Dependency[] {
  return deps.filter(d => d.type === 'direct');
}

/**
 * Get dev dependencies
 */
export function getDevDependencies(deps: Dependency[]): Dependency[] {
  return deps.filter(d => d.type === 'dev');
}

/**
 * Get dependency count by ecosystem
 */
export function getDependencyCountByEcosystem(deps: Dependency[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const dep of deps) {
    counts[dep.ecosystem] = (counts[dep.ecosystem] || 0) + 1;
  }
  return counts;
}
