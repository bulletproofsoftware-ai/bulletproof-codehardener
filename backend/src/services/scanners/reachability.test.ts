import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildReachabilityMap, isReachable, getEntryPoint, type ReachabilityResult } from './reachability.js';
import type { ExtractedEndpoint } from '../test-generator/types.js';

// Mock logger
vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

// Mock fs/promises
const mockReadFile = vi.fn();
const mockAccess = vi.fn();
vi.mock('fs/promises', () => ({
  readFile: (...args: unknown[]) => mockReadFile(...args),
  access: (...args: unknown[]) => mockAccess(...args),
}));

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeEndpoint(overrides: Partial<ExtractedEndpoint> = {}): ExtractedEndpoint {
  return {
    method: 'GET',
    path: '/api/users',
    file: 'src/routes/users.ts',
    line: 10,
    ...overrides,
  };
}

function makeReachability(
  reachableFiles: string[] = [],
  entryPointMap: Record<string, string> = {},
  complete = true,
): ReachabilityResult {
  return {
    reachableFiles: new Set(reachableFiles),
    entryPointMap: new Map(Object.entries(entryPointMap)),
    complete,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Reachability', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('buildReachabilityMap', () => {
    it('returns empty map when no entry points found', async () => {
      const result = await buildReachabilityMap([], '/scan-target');

      expect(result.reachableFiles.size).toBe(0);
      expect(result.entryPointMap.size).toBe(0);
      expect(result.complete).toBe(false);
    });

    it('marks files directly imported by endpoints as reachable', async () => {
      const endpoints = [makeEndpoint({ file: 'src/routes/users.ts' })];

      // The endpoint file imports a controller
      mockReadFile.mockResolvedValueOnce('import { getUser } from "../controllers/user.js";');
      // The controller file has no further imports
      mockReadFile.mockResolvedValueOnce('export function getUser() {}');

      // fs.access checks: the controller file exists
      mockAccess.mockImplementation((filePath: string) => {
        if (filePath.includes('controllers/user.js')) return Promise.resolve();
        return Promise.reject(new Error('ENOENT'));
      });

      const result = await buildReachabilityMap(endpoints, '/scan-target');

      expect(result.reachableFiles.has('src/routes/users.ts')).toBe(true);
      expect(result.reachableFiles.has('src/controllers/user.js')).toBe(true);
    });

    it('follows transitive imports (A imports B imports C)', async () => {
      const endpoints = [makeEndpoint({ file: 'src/routes/users.ts' })];

      // A imports B
      mockReadFile.mockResolvedValueOnce('import { handler } from "../controllers/user.js";');
      // B imports C
      mockReadFile.mockResolvedValueOnce('import { db } from "../db/client.js";');
      // C has no further imports
      mockReadFile.mockResolvedValueOnce('export const db = {};');

      mockAccess.mockImplementation((filePath: string) => {
        if (filePath.includes('controllers/user.js') || filePath.includes('db/client.js')) {
          return Promise.resolve();
        }
        return Promise.reject(new Error('ENOENT'));
      });

      const result = await buildReachabilityMap(endpoints, '/scan-target');

      expect(result.reachableFiles.has('src/routes/users.ts')).toBe(true);
      expect(result.reachableFiles.has('src/controllers/user.js')).toBe(true);
      expect(result.reachableFiles.has('src/db/client.js')).toBe(true);
    });

    it('handles circular imports without infinite loop', async () => {
      const endpoints = [makeEndpoint({ file: 'src/a.ts' })];

      // a.ts imports b.ts, b.ts imports a.ts (circular)
      mockReadFile.mockImplementation((filePath: string) => {
        if (filePath.includes('a.ts')) {
          return Promise.resolve('import { b } from "./b.js";');
        }
        if (filePath.includes('b.js') || filePath.includes('b.ts')) {
          return Promise.resolve('import { a } from "./a.js";');
        }
        return Promise.resolve('');
      });

      mockAccess.mockImplementation((filePath: string) => {
        if (filePath.includes('b.js') || filePath.includes('a.js')) {
          return Promise.resolve();
        }
        return Promise.reject(new Error('ENOENT'));
      });

      // Should not hang — BFS prevents revisiting already-seen files
      const result = await buildReachabilityMap(endpoints, '/scan-target');

      expect(result.reachableFiles.has('src/a.ts')).toBe(true);
      // b.js or b.ts should be reachable depending on resolution
      const hasBFile = [...result.reachableFiles].some(f => f.includes('b.'));
      expect(hasBFile).toBe(true);
    });

    it('handles files that fail to read gracefully', async () => {
      const endpoints = [makeEndpoint({ file: 'src/routes/users.ts' })];

      mockReadFile.mockRejectedValue(new Error('ENOENT'));

      const result = await buildReachabilityMap(endpoints, '/scan-target');

      // The entry point file itself is still reachable (seeded)
      expect(result.reachableFiles.has('src/routes/users.ts')).toBe(true);
      expect(result.reachableFiles.size).toBe(1);
    });

    it('normalizes entry point file paths (strips leading slash)', async () => {
      const endpoints = [makeEndpoint({ file: '/src/routes/users.ts' })];

      mockReadFile.mockResolvedValue('');

      const result = await buildReachabilityMap(endpoints, '/scan-target');

      // Should strip the leading slash
      expect(result.reachableFiles.has('src/routes/users.ts')).toBe(true);
    });

    it('populates entryPointMap with endpoint label', async () => {
      const endpoints = [makeEndpoint({ method: 'POST', path: '/api/users', file: 'src/routes/users.ts' })];

      mockReadFile.mockResolvedValue('');

      const result = await buildReachabilityMap(endpoints, '/scan-target');

      expect(result.entryPointMap.get('src/routes/users.ts')).toBe('POST /api/users');
    });
  });

  describe('isReachable', () => {
    it('returns true when filePath is null', () => {
      const reach = makeReachability(['src/a.ts']);
      expect(isReachable(null, reach)).toBe(true);
    });

    it('returns true when file is in reachable set', () => {
      const reach = makeReachability(['src/controllers/user.ts']);
      expect(isReachable('src/controllers/user.ts', reach)).toBe(true);
    });

    it('returns false for files not in the import graph with complete analysis', () => {
      // Need >= 10 files so the conservative guard doesn't kick in
      const files = Array.from({ length: 15 }, (_, i) => `src/file${i}.ts`);
      const reach = makeReachability(files, {}, true);

      expect(isReachable('src/dead-code.ts', reach)).toBe(false);
    });

    it('returns true when analysis was incomplete and reachable set is empty', () => {
      const reach = makeReachability([], {}, false);
      expect(isReachable('src/any-file.ts', reach)).toBe(true);
    });

    it('returns true when analysis was incomplete with few files (conservative)', () => {
      const reach = makeReachability(['src/a.ts', 'src/b.ts'], {}, false);
      expect(isReachable('src/unknown.ts', reach)).toBe(true);
    });

    it('normalizes file paths with scan-target/ prefix', () => {
      const reach = makeReachability(['src/controllers/user.ts']);
      expect(isReachable('scan-target/src/controllers/user.ts', reach)).toBe(true);
    });

    it('normalizes file paths with leading slash', () => {
      const reach = makeReachability(['src/controllers/user.ts']);
      expect(isReachable('/src/controllers/user.ts', reach)).toBe(true);
    });
  });

  describe('getEntryPoint', () => {
    it('returns null when filePath is null', () => {
      const reach = makeReachability([], { 'src/a.ts': 'GET /api/a' });
      expect(getEntryPoint(null, reach)).toBeNull();
    });

    it('returns the entry point label for a reachable file', () => {
      const reach = makeReachability(
        ['src/controllers/user.ts'],
        { 'src/controllers/user.ts': 'POST /api/users' },
      );
      expect(getEntryPoint('src/controllers/user.ts', reach)).toBe('POST /api/users');
    });

    it('returns null for files not in the entry point map', () => {
      const reach = makeReachability(['src/a.ts'], { 'src/a.ts': 'GET /api/a' });
      expect(getEntryPoint('src/unknown.ts', reach)).toBeNull();
    });

    it('normalizes scan-target/ prefix when looking up entry point', () => {
      const reach = makeReachability(
        ['src/controllers/user.ts'],
        { 'src/controllers/user.ts': 'GET /api/users' },
      );
      expect(getEntryPoint('scan-target/src/controllers/user.ts', reach)).toBe('GET /api/users');
    });
  });
});
