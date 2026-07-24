import path from 'path';

/**
 * Safe path.join that prevents directory traversal.
 * Resolves the joined path and verifies it stays within the base directory.
 */
export function safePath(baseDir: string, ...segments: string[]): string {
  const resolved = path.resolve(baseDir, ...segments);
  if (!resolved.startsWith(path.resolve(baseDir))) {
    throw new Error(`Path traversal detected: ${segments.join('/')} escapes ${baseDir}`);
  }
  return resolved;
}
