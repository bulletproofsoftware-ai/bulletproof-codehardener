import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ScanJobData } from '../../services/queue/scan.queue.js';

// Minimal ScanJobData with NO DAST context — simulates pre-maximization behavior
function makeJobData(overrides: Partial<ScanJobData> = {}): ScanJobData {
  return {
    scanId: 'test-scan',
    projectId: 'test-project',
    userId: 'test-user',
    profile: 'comprehensive',
    branch: 'main',
    scanners: [],
    ...overrides,
  } as ScanJobData;
}

// Mock child_process to return empty stdout for discovery commands (simulates no files found)
vi.mock('child_process', () => {
  const mockExec = vi.fn((_cmd: string, _opts: unknown, cb?: Function) => {
    // Support both (cmd, cb) and (cmd, opts, cb) signatures
    const callback = typeof _opts === 'function' ? _opts : cb;
    if (callback) {
      callback(null, { stdout: '', stderr: '' });
    }
    return { on: vi.fn(), stdout: { on: vi.fn() }, stderr: { on: vi.fn() } };
  });
  return {
    exec: mockExec,
    execSync: vi.fn(() => ''),
    spawn: vi.fn(),
  };
});

// Mock fs to return false for existsSync (no spec files found on disk)
vi.mock('fs', async () => {
  const actual = await vi.importActual<typeof import('fs')>('fs');
  return {
    ...actual,
    existsSync: vi.fn(() => false),
  };
});

// Mock fs/promises readFile to return empty
vi.mock('fs/promises', async () => {
  const actual = await vi.importActual<typeof import('fs/promises')>('fs/promises');
  return {
    ...actual,
    readFile: vi.fn().mockRejectedValue(new Error('ENOENT: no such file or directory')),
  };
});

// Mock logger to suppress output during tests
vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

// Mock glob (used by detect-context)
vi.mock('glob', () => ({
  glob: vi.fn().mockResolvedValue([]),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Scanner skip reasons — DAST scanners', () => {
  it('ZAP returns no_target_url when no targetUrl', async () => {
    const { runZAP } = await import('./zap.js');
    const result = await runZAP(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_target_url');
    expect(result.skipHint).toBeTruthy();
    expect(result.scanner).toBe('zap');
    expect(result.findings).toEqual([]);
  });

  it('Nuclei returns no_target_url when no targetUrl', async () => {
    const { runNuclei } = await import('./nuclei.js');
    const result = await runNuclei(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_target_url');
    expect(result.skipHint).toBeTruthy();
    expect(result.scanner).toBe('nuclei');
    expect(result.findings).toEqual([]);
  });

  it('Pa11y returns no_target_url when no targetUrl or config', async () => {
    const { runPa11y } = await import('./pa11y.js');
    const result = await runPa11y(makeJobData());
    // Pa11y checks for targetUrl OR pa11y config. With mocked exec returning empty,
    // the config check returns "missing", so it should skip with no_target_url.
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_target_url');
    expect(result.scanner).toBe('pa11y');
  });
});

describe('Scanner skip reasons — API testing scanners', () => {
  it('Newman returns no_postman_collection when none detected', async () => {
    const { runNewman } = await import('./newman.js');
    const result = await runNewman(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_postman_collection');
    expect(result.scanner).toBe('newman');
    expect(result.findings).toEqual([]);
  });

  it('Spectral returns no_api_spec when no OpenAPI spec', async () => {
    const { runSpectral } = await import('./spectral.js');
    const result = await runSpectral(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_api_spec');
    expect(result.scanner).toBe('spectral');
    expect(result.findings).toEqual([]);
  });

  it('Schemathesis returns no_api_spec when no OpenAPI spec', async () => {
    const { runSchemathesis } = await import('./schemathesis.js');
    const result = await runSchemathesis(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_api_spec');
    expect(result.scanner).toBe('schemathesis');
    expect(result.findings).toEqual([]);
  });

  it('RESTler returns no_api_spec when no OpenAPI spec', async () => {
    const { runRESTler } = await import('./restler.js');
    const result = await runRESTler(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_api_spec');
    expect(result.scanner).toBe('restler');
    expect(result.findings).toEqual([]);
  });

  it('Pact returns no_pact_contracts when none detected', async () => {
    const { runPact } = await import('./pact.js');
    const result = await runPact(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_pact_contracts');
    expect(result.scanner).toBe('pact');
    expect(result.findings).toEqual([]);
  });
});

describe('Scanner skip reasons — Container scanners', () => {
  it('Cosign returns no_container_image when no image', async () => {
    const { runCosign } = await import('./cosign.js');
    const result = await runCosign(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_container_image');
    expect(result.scanner).toBe('cosign');
    expect(result.findings).toEqual([]);
  });

  it('Dockle returns no_container_image when no image and no Dockerfiles', async () => {
    const { runDockle } = await import('./dockle.js');
    const result = await runDockle(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_container_image');
    expect(result.scanner).toBe('dockle');
    expect(result.findings).toEqual([]);
  });
});

describe('Scanner skip reasons — Load testing scanners', () => {
  it('Locust returns no_target_url when no targetUrl', async () => {
    const { runLocust } = await import('./locust.js');
    const result = await runLocust(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_target_url');
    expect(result.scanner).toBe('locust');
  });

  it('Artillery returns no_target_url when no targetUrl', async () => {
    const { runArtillery } = await import('./artillery.js');
    const result = await runArtillery(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_target_url');
    expect(result.scanner).toBe('artillery');
  });

  it('Gatling returns no_target_url when no targetUrl', async () => {
    const { runGatling } = await import('./gatling.js');
    const result = await runGatling(makeJobData());
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe('no_target_url');
    expect(result.scanner).toBe('gatling');
  });
});

// Verify every skip result from scanners that skip cleanly has required fields
describe('Scanner skip reasons — field completeness', () => {
  const scannerTests: Array<{
    name: string;
    module: string;
    exportName: string;
    expectedReason: string;
  }> = [
    { name: 'zap', module: './zap.js', exportName: 'runZAP', expectedReason: 'no_target_url' },
    { name: 'nuclei', module: './nuclei.js', exportName: 'runNuclei', expectedReason: 'no_target_url' },
    { name: 'cosign', module: './cosign.js', exportName: 'runCosign', expectedReason: 'no_container_image' },
    { name: 'spectral', module: './spectral.js', exportName: 'runSpectral', expectedReason: 'no_api_spec' },
    { name: 'schemathesis', module: './schemathesis.js', exportName: 'runSchemathesis', expectedReason: 'no_api_spec' },
    { name: 'locust', module: './locust.js', exportName: 'runLocust', expectedReason: 'no_target_url' },
    { name: 'artillery', module: './artillery.js', exportName: 'runArtillery', expectedReason: 'no_target_url' },
    { name: 'gatling', module: './gatling.js', exportName: 'runGatling', expectedReason: 'no_target_url' },
  ];

  for (const { name, module: modulePath, exportName, expectedReason } of scannerTests) {
    it(`${name} skip result has scanner, skipped, skipReason, skipHint, empty findings`, async () => {
      const mod = await import(modulePath);
      const runFn = mod[exportName] as Function;
      expect(runFn, `Expected export ${exportName} in ${modulePath}`).toBeDefined();

      const result = await runFn(makeJobData());
      expect(result.scanner).toBe(name);
      expect(result.skipped).toBe(true);
      expect(result.skipReason).toBe(expectedReason);
      expect(result.skipHint).toBeTruthy();
      expect(result.findings).toEqual([]);
      expect(result.success).toBe(true);
      expect(typeof result.duration).toBe('number');
    });
  }
});
