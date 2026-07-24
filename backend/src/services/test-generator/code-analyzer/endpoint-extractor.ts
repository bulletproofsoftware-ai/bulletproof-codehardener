/**
 * CA-003: Endpoint Extraction
 * Extracts REST and GraphQL endpoints from source code
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { createLogger } from '../../../utils/logger.js';
import { safePath } from '../../../utils/safePath.js';
import type { ExtractedEndpoint, FrameworkDetection, EndpointParameter } from '../types.js';

const logger = createLogger('endpoint-extractor');

// HTTP methods to detect
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'ALL'] as const;

// Common route patterns by framework
const ROUTE_PATTERNS: Record<string, RegExp[]> = {
  Express: [
    // app.get/post/put/delete('/path', handler)
    /(?:app|router)\.(get|post|put|delete|patch|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    // router.route('/path').get(handler).post(handler)
    /\.route\s*\(\s*['"`]([^'"`]+)['"`]\)/gi,
  ],
  Fastify: [
    /fastify\.(get|post|put|delete|patch|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    /\.route\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]/gi,
  ],
  NestJS: [
    /@(Get|Post|Put|Delete|Patch|Options|Head|All)\s*\(\s*['"`]?([^'"`)]*)/gi,
    /@Controller\s*\(\s*['"`]([^'"`]+)['"`]\)/gi,
  ],
  Koa: [
    /router\.(get|post|put|delete|patch|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
  ],
  Flask: [
    /@(?:app|bp|blueprint)\.route\s*\(\s*['"`]([^'"`]+)['"`](?:[^)]*methods\s*=\s*\[([^\]]+)\])?/gi,
    /@(?:app|bp|blueprint)\.(get|post|put|delete|patch|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
  ],
  FastAPI: [
    /@(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    /@(?:app|router)\.api_route\s*\(\s*['"`]([^'"`]+)['"`](?:[^)]*methods\s*=\s*\[([^\]]+)\])?/gi,
  ],
  Django: [
    /path\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    /url\s*\(\s*r?['"`]\^?([^'"`$]+)/gi,
    /@api_view\s*\(\s*\[([^\]]+)\]\)/gi,
  ],
  Gin: [
    /\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Any)\s*\(\s*["']([^"']+)["']/gi,
    /\.Handle\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']/gi,
  ],
  Echo: [
    /e\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s*\(\s*["']([^"']+)["']/gi,
    /\.Add\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']/gi,
  ],
  'Spring Boot': [
    /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/gi,
    /@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["'](?:[^)]*method\s*=\s*RequestMethod\.(\w+))?/gi,
  ],
  Rails: [
    /(?:get|post|put|delete|patch)\s+['"]([^'"]+)['"](?:\s*=>\s*['"]([^'"]+)['"])?/gi,
    /(?:resources?|match)\s+:?(['"]?)(\w+)\1/gi,
  ],
  Laravel: [
    /Route::(get|post|put|delete|patch|options|any)\s*\(\s*['"]([^'"]+)['"]/gi,
    /Route::match\s*\(\s*\[([^\]]+)\]\s*,\s*['"]([^'"]+)['"]/gi,
  ],
};

// GraphQL patterns
const GRAPHQL_PATTERNS = [
  /type\s+Query\s*\{([^}]+)\}/gi,
  /type\s+Mutation\s*\{([^}]+)\}/gi,
  /type\s+Subscription\s*\{([^}]+)\}/gi,
  /@Query\s*\(\s*\)\s*\n?\s*(\w+)/gi,
  /@Mutation\s*\(\s*\)\s*\n?\s*(\w+)/gi,
  /@Resolver\s*\(/gi,
  /Query:\s*\{([^}]+)\}/gi,
  /Mutation:\s*\{([^}]+)\}/gi,
];

// Parameter patterns
const PARAM_PATTERNS = {
  path: [
    /:(\w+)/g,           // Express-style :param
    /\{(\w+)\}/g,        // OpenAPI/FastAPI style {param}
    /<(\w+)(?::[^>]+)?>/g, // Flask style <param:type>
  ],
};

interface FileContent {
  path: string;
  content: string;
  relativePath: string;
}

/**
 * Read source files for endpoint extraction
 */
async function readSourceFiles(
  repoPath: string,
  extensions: string[],
  maxFiles: number = 500
): Promise<FileContent[]> {
  const files: FileContent[] = [];

  async function scan(dirPath: string): Promise<void> {
    if (files.length >= maxFiles) return;

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        if (files.length >= maxFiles) break;

        const fullPath = safePath(dirPath, entry.name);
        const relativePath = path.relative(repoPath, fullPath);

        // Skip common non-source directories
        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'vendor', 'dist', 'build', '__pycache__', 'venv', '.venv'].includes(entry.name)) {
            continue;
          }
          await scan(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name);
          if (extensions.includes(ext)) {
            try {
              const content = await fs.readFile(fullPath, 'utf-8');
              // Skip very large files or binary files
              if (content.length < 500000 && !content.includes('\0')) {
                files.push({ path: fullPath, content, relativePath });
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
  }

  await scan(repoPath);
  return files;
}

/**
 * Extract path parameters from route
 */
function extractPathParams(routePath: string): EndpointParameter[] {
  const params: EndpointParameter[] = [];

  for (const pattern of PARAM_PATTERNS.path) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(routePath)) !== null) {
      if (!params.some(p => p.name === match![1])) {
        params.push({
          name: match[1],
          location: 'path',
          required: true,
        });
      }
    }
    pattern.lastIndex = 0; // Reset regex state
  }

  return params;
}

/**
 * Find line number for a match position
 */
function getLineNumber(content: string, position: number): number {
  return content.substring(0, position).split('\n').length;
}

/**
 * Normalize HTTP method
 */
function normalizeMethod(method: string): ExtractedEndpoint['method'] {
  const upper = method.toUpperCase();
  if (HTTP_METHODS.includes(upper as typeof HTTP_METHODS[number])) {
    return upper as ExtractedEndpoint['method'];
  }
  return 'GET';
}

/**
 * Normalize path
 */
function normalizePath(routePath: string): string {
  // Remove leading/trailing whitespace
  let normalized = routePath.trim();

  // Ensure leading slash
  if (!normalized.startsWith('/')) {
    normalized = '/' + normalized;
  }

  // Remove trailing slash (except for root)
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }

  // Remove regex characters for Django
  normalized = normalized.replace(/[\^$]/g, '');

  return normalized;
}

/**
 * Extract REST endpoints from file
 */
function extractRESTEndpoints(
  file: FileContent,
  frameworks: FrameworkDetection[]
): ExtractedEndpoint[] {
  const endpoints: ExtractedEndpoint[] = [];
  const frameworkNames = new Set(frameworks.map(f => f.framework));

  // Determine which patterns to use based on detected frameworks
  const patternsToUse: RegExp[] = [];

  for (const [frameworkName, patterns] of Object.entries(ROUTE_PATTERNS)) {
    if (frameworkNames.has(frameworkName) || frameworkNames.size === 0) {
      patternsToUse.push(...patterns);
    }
  }

  // If no specific frameworks, try all patterns
  if (patternsToUse.length === 0) {
    for (const patterns of Object.values(ROUTE_PATTERNS)) {
      patternsToUse.push(...patterns);
    }
  }

  for (const pattern of patternsToUse) {
    let match;
    const regex = new RegExp(pattern.source, pattern.flags);

    while ((match = regex.exec(file.content)) !== null) {
      // Different patterns capture method and path in different positions
      let method: string = 'GET';
      let routePath: string = '';

      if (match[2]) {
        // Method in position 1, path in position 2
        method = match[1];
        routePath = match[2];
      } else if (match[1]) {
        // Only path captured
        routePath = match[1];
      }

      if (!routePath) continue;

      const normalizedPath = normalizePath(routePath);
      const line = getLineNumber(file.content, match.index);

      // Check for duplicates
      if (endpoints.some(e => e.path === normalizedPath && e.method === normalizeMethod(method) && e.file === file.relativePath)) {
        continue;
      }

      endpoints.push({
        method: normalizeMethod(method),
        path: normalizedPath,
        file: file.relativePath,
        line,
        parameters: extractPathParams(normalizedPath),
      });
    }
  }

  return endpoints;
}

/**
 * Extract GraphQL operations from file
 */
function extractGraphQLEndpoints(file: FileContent): ExtractedEndpoint[] {
  const endpoints: ExtractedEndpoint[] = [];

  for (const pattern of GRAPHQL_PATTERNS) {
    let match;
    const regex = new RegExp(pattern.source, pattern.flags);

    while ((match = regex.exec(file.content)) !== null) {
      const content = match[1] || match[0];
      const line = getLineNumber(file.content, match.index);

      // Determine GraphQL operation type
      let graphqlType: 'query' | 'mutation' | 'subscription' = 'query';
      const typeMatch = match[0].toLowerCase();
      if (typeMatch.includes('mutation')) {
        graphqlType = 'mutation';
      } else if (typeMatch.includes('subscription')) {
        graphqlType = 'subscription';
      }

      // Extract operation names from the content
      const operationPattern = /(\w+)\s*(?:\([^)]*\))?\s*:/g;
      let opMatch;
      while ((opMatch = operationPattern.exec(content)) !== null) {
        const opName = opMatch[1];
        if (opName && !['type', 'Query', 'Mutation', 'Subscription'].includes(opName)) {
          endpoints.push({
            method: graphqlType === 'query' ? 'GET' : 'POST',
            path: `/graphql#${opName}`,
            file: file.relativePath,
            line: line + content.substring(0, opMatch.index).split('\n').length - 1,
            isGraphQL: true,
            graphqlType,
            handler: opName,
          });
        }
      }
    }
  }

  return endpoints;
}

/**
 * Extract endpoints from a repository
 */
export async function extractEndpoints(
  repoPath: string,
  frameworks: FrameworkDetection[]
): Promise<ExtractedEndpoint[]> {
  logger.info({ repoPath, frameworkCount: frameworks.length }, 'Starting endpoint extraction');

  const startTime = Date.now();
  const endpoints: ExtractedEndpoint[] = [];

  // Determine file extensions to scan based on frameworks
  const extensions = new Set<string>();

  for (const framework of frameworks) {
    switch (framework.framework) {
      case 'Express':
      case 'Fastify':
      case 'NestJS':
      case 'Koa':
      case 'Next.js':
        extensions.add('.js');
        extensions.add('.ts');
        extensions.add('.mjs');
        extensions.add('.cjs');
        break;
      case 'Django':
      case 'Flask':
      case 'FastAPI':
        extensions.add('.py');
        break;
      case 'Gin':
      case 'Echo':
      case 'Fiber':
      case 'Chi':
        extensions.add('.go');
        break;
      case 'Spring Boot':
        extensions.add('.java');
        extensions.add('.kt');
        break;
      case 'Rails':
        extensions.add('.rb');
        break;
      case 'Laravel':
      case 'Symfony':
        extensions.add('.php');
        break;
      default:
        // Add common extensions for unknown frameworks
        extensions.add('.js');
        extensions.add('.ts');
        extensions.add('.py');
        extensions.add('.go');
        extensions.add('.java');
        extensions.add('.rb');
        extensions.add('.php');
    }
  }

  // If no frameworks detected, scan common extensions
  if (extensions.size === 0) {
    ['.js', '.ts', '.py', '.go', '.java', '.rb', '.php', '.graphql', '.gql'].forEach(e => extensions.add(e));
  }

  // Add GraphQL extensions
  extensions.add('.graphql');
  extensions.add('.gql');

  // Read source files
  const files = await readSourceFiles(repoPath, Array.from(extensions));

  // Extract endpoints from each file
  for (const file of files) {
    // REST endpoints
    const restEndpoints = extractRESTEndpoints(file, frameworks);
    endpoints.push(...restEndpoints);

    // GraphQL endpoints
    const graphqlEndpoints = extractGraphQLEndpoints(file);
    endpoints.push(...graphqlEndpoints);
  }

  // Deduplicate
  const uniqueEndpoints: ExtractedEndpoint[] = [];
  const seen = new Set<string>();

  for (const endpoint of endpoints) {
    const key = `${endpoint.method}:${endpoint.path}:${endpoint.file}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueEndpoints.push(endpoint);
    }
  }

  // Sort by file and line
  uniqueEndpoints.sort((a, b) => {
    const fileCompare = a.file.localeCompare(b.file);
    if (fileCompare !== 0) return fileCompare;
    return a.line - b.line;
  });

  logger.info(
    {
      repoPath,
      endpointCount: uniqueEndpoints.length,
      filesScanned: files.length,
      durationMs: Date.now() - startTime,
    },
    'Endpoint extraction completed'
  );

  return uniqueEndpoints;
}

/**
 * Get endpoints by method
 */
export function getEndpointsByMethod(
  endpoints: ExtractedEndpoint[],
  method: ExtractedEndpoint['method']
): ExtractedEndpoint[] {
  return endpoints.filter(e => e.method === method);
}

/**
 * Get GraphQL endpoints
 */
export function getGraphQLEndpoints(endpoints: ExtractedEndpoint[]): ExtractedEndpoint[] {
  return endpoints.filter(e => e.isGraphQL);
}

/**
 * Get endpoints with path parameters
 */
export function getParameterizedEndpoints(endpoints: ExtractedEndpoint[]): ExtractedEndpoint[] {
  return endpoints.filter(e => e.parameters && e.parameters.length > 0);
}
