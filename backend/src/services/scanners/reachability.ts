/**
 * Reachability Filtering
 *
 * Tags findings as reachable/unreachable from entry points using CA-003
 * endpoint data. Builds a coarse-grained file-level reachability map
 * by tracing imports/requires from endpoint files.
 *
 * This catches:
 *   - Dead code (files never imported from any entry point)
 *   - Test files analyzed as production code
 *   - Utility libraries never called from HTTP/CLI endpoints
 *
 * NOT a line-level check — file-level granularity is sufficient for
 * filtering out clearly unreachable findings.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { createLogger } from '../../utils/logger.js';
import type { ExtractedEndpoint } from '../test-generator/types.js';

const logger = createLogger('reachability');

export interface ReachabilityResult {
  /** Files that are reachable from HTTP/CLI entry points */
  reachableFiles: Set<string>;
  /** Map of file to closest entry point (for enrichment context) */
  entryPointMap: Map<string, string>;
  /** Whether the analysis completed fully (false if graph was incomplete) */
  complete: boolean;
}

// Patterns to extract import/require paths from source files
const IMPORT_PATTERNS = [
  // ES imports: import x from './path', import { x } from './path'
  /(?:import\s+(?:[\w{},*\s]+\s+from\s+)?['"]([^'"]+)['"])/g,
  // Dynamic imports: import('./path')
  /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  // CommonJS: require('./path')
  /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  // Go: import "path" or import ( "path" )
  /import\s+(?:\w+\s+)?["']([^"']+)["']/g,
  // Python: from x import y, import x
  /(?:from\s+([\w.]+)\s+import|^import\s+([\w.]+))/gm,
  // Java: import com.example.Class
  /import\s+([\w.]+);/g,
  // Ruby: require 'path', require_relative 'path'
  /require(?:_relative)?\s+['"]([^'"]+)['"]/g,
];

/**
 * Extract import paths from a source file's content.
 * Returns relative file paths (resolved against the file's directory).
 */
function extractImports(content: string, filePath: string, scanTarget: string): string[] {
  const imports: string[] = [];
  const fileDir = path.dirname(filePath);

  for (const pattern of IMPORT_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const importPath = match[1] || match[2];
      if (!importPath) continue;

      // Skip external packages (no relative prefix, not a local path)
      if (importPath.startsWith('@') || importPath.startsWith('node_modules')) continue;
      if (!importPath.startsWith('.') && !importPath.startsWith('/') && !importPath.includes('/')) {
        continue;
      }

      // Resolve relative to file directory
      let resolved: string;
      if (importPath.startsWith('.')) {
        resolved = path.resolve(fileDir, importPath);
      } else if (importPath.startsWith('/')) {
        resolved = importPath;
      } else {
        // Python dotted imports: convert dots to slashes
        resolved = path.resolve(scanTarget, importPath.replace(/\./g, '/'));
      }

      // Normalize: make relative to scan target
      const relativePath = path.relative(scanTarget, resolved);

      // Try common extensions if none specified
      const ext = path.extname(relativePath);
      if (!ext) {
        imports.push(relativePath);
        for (const e of ['.ts', '.tsx', '.js', '.jsx', '.py', '.go', '.java', '.rb']) {
          imports.push(relativePath + e);
        }
        imports.push(path.join(relativePath, 'index.ts'));
        imports.push(path.join(relativePath, 'index.js'));
        imports.push(path.join(relativePath, '__init__.py'));
      } else {
        imports.push(relativePath);
      }
    }
  }

  return imports;
}

/**
 * Build a file-level reachability map from CA-003 endpoints.
 *
 * Algorithm:
 * 1. Seed with all files referenced by endpoints
 * 2. BFS: for each reachable file, find its imports
 * 3. Mark imported files as reachable
 * 4. Repeat until no new files are found
 */
export async function buildReachabilityMap(
  endpoints: ExtractedEndpoint[],
  scanTarget: string,
): Promise<ReachabilityResult> {
  const startTime = Date.now();
  const reachableFiles = new Set<string>();
  const entryPointMap = new Map<string, string>();
  let complete = true;

  if (endpoints.length === 0) {
    logger.info('No endpoints detected — skipping reachability analysis');
    return { reachableFiles, entryPointMap, complete: false };
  }

  // Seed: all files referenced by endpoints
  const queue: Array<{ file: string; entryPoint: string }> = [];

  for (const endpoint of endpoints) {
    const normalizedFile = endpoint.file.replace(/^\//, '');
    if (!reachableFiles.has(normalizedFile)) {
      reachableFiles.add(normalizedFile);
      const entryLabel = `${endpoint.method} ${endpoint.path}`;
      entryPointMap.set(normalizedFile, entryLabel);
      queue.push({ file: normalizedFile, entryPoint: entryLabel });
    }
  }

  // BFS with depth limit to avoid infinite loops
  const MAX_DEPTH = 10;
  const MAX_FILES = 500;
  let depth = 0;

  while (queue.length > 0 && depth < MAX_DEPTH && reachableFiles.size < MAX_FILES) {
    const currentBatch = [...queue];
    queue.length = 0;
    depth++;

    for (const { file, entryPoint } of currentBatch) {
      if (reachableFiles.size >= MAX_FILES) {
        complete = false;
        break;
      }

      try {
        const fullPath = path.join(scanTarget, file);
        const content = await fs.readFile(fullPath, 'utf-8');
        const imports = extractImports(content, fullPath, scanTarget);

        for (const imp of imports) {
          if (!reachableFiles.has(imp)) {
            try {
              await fs.access(path.join(scanTarget, imp));
              reachableFiles.add(imp);
              entryPointMap.set(imp, entryPoint);
              queue.push({ file: imp, entryPoint });
            } catch {
              // File doesn't exist with this path — skip
            }
          }
        }
      } catch {
        // File read failed — skip but don't break
      }
    }
  }

  if (depth >= MAX_DEPTH || reachableFiles.size >= MAX_FILES) {
    complete = false;
  }

  logger.info(
    {
      endpointCount: endpoints.length,
      reachableFileCount: reachableFiles.size,
      depth,
      complete,
      durationMs: Date.now() - startTime,
    },
    'Reachability map built'
  );

  return { reachableFiles, entryPointMap, complete };
}

/**
 * Check if a finding's file is reachable from entry points.
 * Returns true if reachable, false if definitely unreachable,
 * or true if the analysis was incomplete (conservative default).
 */
export function isReachable(
  filePath: string | null,
  reachability: ReachabilityResult,
): boolean {
  if (!filePath) return true;

  // If analysis was incomplete, default to reachable (conservative)
  if (!reachability.complete && reachability.reachableFiles.size === 0) {
    return true;
  }

  const normalized = filePath.replace(/^\//, '');

  if (reachability.reachableFiles.has(normalized)) return true;

  const withoutPrefix = normalized.replace(/^scan-target\//, '');
  if (reachability.reachableFiles.has(withoutPrefix)) return true;

  // If graph was incomplete with few files, be conservative
  if (!reachability.complete && reachability.reachableFiles.size < 10) {
    return true;
  }

  return false;
}

/**
 * Get the entry point that reaches a given file.
 */
export function getEntryPoint(
  filePath: string | null,
  reachability: ReachabilityResult,
): string | null {
  if (!filePath) return null;

  const normalized = filePath.replace(/^\//, '');
  return reachability.entryPointMap.get(normalized)
    || reachability.entryPointMap.get(normalized.replace(/^scan-target\//, ''))
    || null;
}
