import { glob } from 'glob';
import { existsSync, lstatSync, readFileSync } from 'fs';
import { join, resolve } from 'path';
import { createLogger } from '../../utils/logger.js';
import type { DetectedProjectContext } from '../../types/index.js';

const logger = createLogger('detect-context');

/** Framework detection patterns: { file glob -> { content match -> framework, port } } */
const FRAMEWORK_PATTERNS: Array<{
  file: string;
  matches: Array<{ pattern: RegExp; framework: string; port: number }>;
}> = [
  {
    file: 'package.json',
    matches: [
      { pattern: /"express"/, framework: 'express', port: 3000 },
      { pattern: /"next"/, framework: 'next', port: 3000 },
      { pattern: /"nuxt"/, framework: 'nuxt', port: 3000 },
      { pattern: /"@angular\/core"/, framework: 'angular', port: 4200 },
      { pattern: /"react-scripts"/, framework: 'create-react-app', port: 3000 },
      { pattern: /"vite"/, framework: 'vite', port: 5173 },
      { pattern: /"fastify"/, framework: 'fastify', port: 3000 },
    ],
  },
  {
    file: 'requirements.txt',
    matches: [
      { pattern: /django/i, framework: 'django', port: 8000 },
      { pattern: /flask/i, framework: 'flask', port: 5000 },
      { pattern: /fastapi/i, framework: 'fastapi', port: 8000 },
    ],
  },
  {
    file: 'pom.xml',
    matches: [
      { pattern: /spring-boot/, framework: 'spring-boot', port: 8080 },
    ],
  },
];

/**
 * Detect framework from manifest files and parse Procfile/scripts
 * for potential dev server ports. Informational only -- logged for future auto-suggest.
 */
function detectFrameworkAndPort(scanDir: string): { framework: string | null; port: number | null } {
  for (const { file, matches } of FRAMEWORK_PATTERNS) {
    const filePath = join(scanDir, file);
    if (!existsSync(filePath)) continue;
    try {
      const content = readFileSync(filePath, 'utf-8');
      for (const { pattern, framework, port } of matches) {
        if (pattern.test(content)) {
          return { framework, port };
        }
      }
    } catch {
      // Unreadable file -- skip
    }
  }

  // Parse Procfile for port hints (e.g., "web: gunicorn -b :$PORT")
  const procfilePath = join(scanDir, 'Procfile');
  if (existsSync(procfilePath)) {
    try {
      const content = readFileSync(procfilePath, 'utf-8');
      const portMatch = content.match(/:(\d{4,5})/);
      if (portMatch) {
        return { framework: null, port: parseInt(portMatch[1], 10) };
      }
    } catch {
      // Unreadable -- skip
    }
  }

  return { framework: null, port: null };
}

/**
 * Auto-detect API specs, collections, contracts, and Docker files in the scan directory.
 * All globs are restricted to scanDir with no symlink traversal.
 */
export async function detectProjectContext(scanDir: string): Promise<DetectedProjectContext> {
  const resolvedDir = resolve(scanDir);

  const safeGlob = async (patterns: string[]): Promise<string[]> => {
    const results: string[] = [];
    for (const pattern of patterns) {
      try {
        const matches = await glob(pattern, {
          cwd: resolvedDir,
          absolute: true,
          nodir: true,
          follow: false,  // No symlink traversal
          ignore: ['**/node_modules/**', '**/.git/**', '**/vendor/**', '**/dist/**', '**/build/**'],
        });
        // Filter out any results that escaped scanDir
        for (const match of matches) {
          if (resolve(match).startsWith(resolvedDir)) {
            results.push(match);
          }
        }
      } catch {
        // Glob error -- skip pattern
      }
    }
    return results;
  };

  const [openapi, postmanCollections, pactContracts] = await Promise.all([
    safeGlob([
      'openapi.{yaml,yml,json}',
      'swagger.{yaml,yml,json}',
      '**/openapi.{yaml,yml,json}',
      '**/swagger.{yaml,yml,json}',
      '**/openapi-spec.{yaml,yml,json}',
      '**/api-docs.{yaml,yml,json}',
    ]),
    safeGlob([
      '*.postman_collection.json',
      '**/postman_collection.json',
      '**/*.postman_collection.json',
    ]),
    safeGlob([
      '**/pacts/*.json',
      'pact/**/*.json',
    ]),
  ]);

  // Deduplicate (multiple patterns may match the same file)
  const dedup = (arr: string[]) => [...new Set(arr)];

  // Check for Docker files at root only
  const dockerComposeFile = ['docker-compose.yml', 'docker-compose.yaml']
    .map(f => join(resolvedDir, f))
    .find(f => existsSync(f) && !lstatSync(f).isSymbolicLink()) || null;

  const dockerfile = [join(resolvedDir, 'Dockerfile')]
    .find(f => existsSync(f) && !lstatSync(f).isSymbolicLink()) || null;

  // Detect framework from package.json / requirements.txt / pom.xml
  const { framework, port } = detectFrameworkAndPort(resolvedDir);

  const ctx: DetectedProjectContext = {
    openapi: dedup(openapi),
    postmanCollections: dedup(postmanCollections),
    pactContracts: dedup(pactContracts),
    dockerComposeFile,
    dockerfile,
    detectedFramework: framework,
    suggestedDevPort: port,
  };

  logger.info({
    openapi: ctx.openapi.length,
    postman: ctx.postmanCollections.length,
    pact: ctx.pactContracts.length,
    hasDockerCompose: !!ctx.dockerComposeFile,
    hasDockerfile: !!ctx.dockerfile,
    framework: ctx.detectedFramework,
    suggestedPort: ctx.suggestedDevPort,
  }, 'Project context detected');

  return ctx;
}
