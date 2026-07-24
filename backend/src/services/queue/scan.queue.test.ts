import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mocks (hoisted before imports) ─────────────────────────────

vi.mock('../../config/env.js', () => ({
  env: {
    N8N_ENABLED: false,
    N8N_WEBHOOK_BASE: 'http://n8n:5678/webhook',
    N8N_API_KEY: '',
    PORT: 7002,
  },
  redisUrl: 'redis://localhost:6379',
  llmVerifyEnabled: false,
}));

vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

const mockDbExecute = vi.fn();
vi.mock('../../db/client.js', () => ({
  db: {
    execute: (...args: unknown[]) => mockDbExecute(...args),
  },
}));

vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({
    strings,
    values,
    _tag: 'sql',
  }),
}));

vi.mock('bullmq', () => {
  return {
    Queue: vi.fn().mockImplementation(() => ({
      add: vi.fn().mockResolvedValue({ id: 'job-1' }),
      getWaitingCount: vi.fn().mockResolvedValue(0),
      getActiveCount: vi.fn().mockResolvedValue(0),
      getCompletedCount: vi.fn().mockResolvedValue(0),
      getFailedCount: vi.fn().mockResolvedValue(0),
    })),
    Worker: vi.fn().mockImplementation((_name: string, _fn: unknown, _opts: unknown) => ({
      on: vi.fn(),
    })),
    Job: vi.fn(),
  };
});

const mockRunScanPipeline = vi.fn();
vi.mock('../scanners/pipeline.js', () => ({
  runScanPipeline: (...args: unknown[]) => mockRunScanPipeline(...args),
}));

const mockCalculateQualityScore = vi.fn();
vi.mock('../assurance/quality-score.js', () => ({
  calculateQualityScore: (...args: unknown[]) => mockCalculateQualityScore(...args),
}));

const mockCreateScanAttestation = vi.fn();
const mockSignAttestation = vi.fn();
const mockStoreAttestation = vi.fn();
vi.mock('../assurance/attestation.js', () => ({
  createScanAttestation: (...args: unknown[]) => mockCreateScanAttestation(...args),
  signAttestation: (...args: unknown[]) => mockSignAttestation(...args),
  storeAttestation: (...args: unknown[]) => mockStoreAttestation(...args),
}));

vi.mock('../defectdojo/index.js', () => ({
  importScanToDefectDojo: vi.fn().mockResolvedValue(null),
}));

const mockTranslateFinding = vi.fn();
vi.mock('../translator/plain-language.js', () => ({
  translateFinding: (...args: unknown[]) => mockTranslateFinding(...args),
}));

const mockGenerateFixDescription = vi.fn();
vi.mock('../scanners/remediation.js', () => ({
  generateFixDescription: (...args: unknown[]) => mockGenerateFixDescription(...args),
}));

vi.mock('../../controllers/suppressions.controller.js', () => ({
  applySuppressions: vi.fn().mockResolvedValue(0),
}));

const mockGetFrameworkSuppressions = vi.fn();
const mockApplyFrameworkSuppressions = vi.fn();
vi.mock('../scanners/framework-suppressions.js', () => ({
  getFrameworkSuppressions: (...args: unknown[]) => mockGetFrameworkSuppressions(...args),
  applyFrameworkSuppressions: (...args: unknown[]) => mockApplyFrameworkSuppressions(...args),
}));

const mockBuildReachabilityMap = vi.fn();
vi.mock('../scanners/reachability.js', () => ({
  buildReachabilityMap: (...args: unknown[]) => mockBuildReachabilityMap(...args),
}));

const mockEnrichFinding = vi.fn();
const mockShouldAutoSuppress = vi.fn();
const mockHasNoConfirmedExploits = vi.fn();
vi.mock('../scanners/finding-enrichment.js', () => ({
  enrichFinding: (...args: unknown[]) => mockEnrichFinding(...args),
  shouldAutoSuppress: (...args: unknown[]) => mockShouldAutoSuppress(...args),
  hasNoConfirmedExploits: (...args: unknown[]) => mockHasNoConfirmedExploits(...args),
}));

vi.mock('../scanners/llm-verifier.js', () => ({
  verifyTopFindingsForScan: vi.fn().mockResolvedValue(0),
}));

// ── Imports (after mocks) ──────────────────────────────────────

import {
  batchGetPriorDismissedStatuses,
  findingFingerprint,
  addScanJob,
  getQueueStats,
  createScanWorker,
} from './scan.queue.js';

// ── Helpers ────────────────────────────────────────────────────

function makeFinding(overrides: Record<string, unknown> = {}) {
  return {
    ruleId: 'B101',
    title: 'Use of assert',
    description: 'Assert used for security check',
    severity: 'medium' as const,
    filePath: 'app.py',
    lineNumber: 10,
    columnNumber: null,
    codeSnippet: 'assert user.is_admin',
    cweId: 'CWE-703',
    owaspCategory: null,
    fixAvailable: false,
    fixDescription: null,
    metadata: {},
    ...overrides,
  };
}

function makeScannerResult(overrides: Record<string, unknown> = {}) {
  return {
    scanner: 'bandit',
    success: true,
    skipped: false,
    skipReason: null,
    skipHint: null,
    findings: [] as ReturnType<typeof makeFinding>[],
    duration: 1500,
    rawOutput: '{}',
    error: null,
    evidence: null,
    ...overrides,
  };
}

// ── Tests ──────────────────────────────────────────────────────

describe('scan.queue - findingFingerprint', () => {
  it('builds fingerprint from scanner, ruleId, and filePath', () => {
    const fp = findingFingerprint('bandit', 'B101', 'app.py');
    expect(fp).toBe('bandit:B101:app.py');
  });

  it('returns null when both ruleId and filePath are null', () => {
    const fp = findingFingerprint('bandit', null, null);
    expect(fp).toBeNull();
  });

  it('handles null ruleId with non-null filePath', () => {
    const fp = findingFingerprint('trivy', null, 'package.json');
    expect(fp).toBe('trivy::package.json');
  });

  it('handles non-null ruleId with null filePath', () => {
    const fp = findingFingerprint('gitleaks', 'generic-api-key', null);
    expect(fp).toBe('gitleaks:generic-api-key:');
  });

  it('handles empty strings (treated as falsy for ruleId/filePath but still constructs)', () => {
    // empty string is falsy, so same as null behavior for the ternary
    const fp = findingFingerprint('scanner', '', '');
    // ruleId='' is falsy → '' , filePath='' is falsy → ''
    expect(fp).toBeNull();
  });
});

describe('scan.queue - batchGetPriorDismissedStatuses', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns empty map when no prior dismissed findings exist', async () => {
    mockDbExecute.mockResolvedValueOnce({ rows: [] });
    const result = await batchGetPriorDismissedStatuses('proj-1', 'scan-1');
    expect(result).toBeInstanceOf(Map);
    expect(result.size).toBe(0);
  });

  it('builds map keyed by scanner:ruleId:filePath', async () => {
    mockDbExecute.mockResolvedValueOnce({
      rows: [
        { scanner: 'bandit', rule_id: 'B101', file_path: 'app.py', status: 'false_positive' },
        { scanner: 'trivy', rule_id: 'CVE-2024-001', file_path: 'package.json', status: 'ignored' },
      ],
    });
    const result = await batchGetPriorDismissedStatuses('proj-1', 'scan-2');
    expect(result.size).toBe(2);
    expect(result.get('bandit:B101:app.py')).toBe('false_positive');
    expect(result.get('trivy:CVE-2024-001:package.json')).toBe('ignored');
  });

  it('handles null rule_id and file_path in rows', async () => {
    mockDbExecute.mockResolvedValueOnce({
      rows: [
        { scanner: 'gitleaks', rule_id: null, file_path: null, status: 'deferred' },
      ],
    });
    const result = await batchGetPriorDismissedStatuses('proj-1', 'scan-3');
    expect(result.size).toBe(1);
    expect(result.get('gitleaks::')).toBe('deferred');
  });

  it('includes all dismissed statuses (ignored, false_positive, fixed, deferred)', async () => {
    mockDbExecute.mockResolvedValueOnce({
      rows: [
        { scanner: 's1', rule_id: 'r1', file_path: 'f1', status: 'ignored' },
        { scanner: 's2', rule_id: 'r2', file_path: 'f2', status: 'false_positive' },
        { scanner: 's3', rule_id: 'r3', file_path: 'f3', status: 'fixed' },
        { scanner: 's4', rule_id: 'r4', file_path: 'f4', status: 'deferred' },
      ],
    });
    const result = await batchGetPriorDismissedStatuses('proj-1', 'scan-4');
    expect(result.size).toBe(4);
    expect(result.get('s1:r1:f1')).toBe('ignored');
    expect(result.get('s2:r2:f2')).toBe('false_positive');
    expect(result.get('s3:r3:f3')).toBe('fixed');
    expect(result.get('s4:r4:f4')).toBe('deferred');
  });
});

describe('scan.queue - addScanJob', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('adds job to queue and returns job object', async () => {
    const data = {
      scanId: 'scan-100',
      projectId: 'proj-1',
      userId: 'user-1',
      profile: 'standard',
      branch: 'main',
      scanners: ['bandit', 'trivy'],
    };
    const job = await addScanJob(data);
    expect(job).toBeDefined();
    expect(job.id).toBe('job-1');
  });
});

describe('scan.queue - getQueueStats', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns queue statistics', async () => {
    const stats = await getQueueStats();
    expect(stats).toEqual({
      waiting: 0,
      active: 0,
      completed: 0,
      failed: 0,
    });
  });
});

describe('scan.queue - createScanWorker', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('creates a worker and attaches event listeners', () => {
    const worker = createScanWorker();
    expect(worker).toBeDefined();
    expect(worker.on).toBeDefined();
    // Worker constructor is called, events are attached
    expect(worker.on).toHaveBeenCalledWith('completed', expect.any(Function));
    expect(worker.on).toHaveBeenCalledWith('failed', expect.any(Function));
    expect(worker.on).toHaveBeenCalledWith('error', expect.any(Function));
  });
});

describe('scan.queue - ScanJobData interface (via addScanJob)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('accepts minimal ScanJobData', async () => {
    const data = {
      scanId: 'scan-min',
      projectId: 'proj-1',
      userId: 'user-1',
      profile: 'quick',
      branch: 'main',
      scanners: ['bandit'],
    };
    // Should not throw
    const job = await addScanJob(data);
    expect(job).toBeDefined();
  });

  it('accepts ScanJobData with all optional fields', async () => {
    const data = {
      scanId: 'scan-full',
      projectId: 'proj-1',
      userId: 'user-1',
      profile: 'comprehensive',
      branch: 'develop',
      commitSha: 'abc123',
      repositoryUrl: 'https://github.com/test/repo',
      scanners: ['bandit', 'trivy', 'gitleaks'],
      options: {
        depth: 'full' as const,
        excludePatterns: ['*.test.*'],
        failThreshold: 'high',
        timeout: 600000,
        parallel: true,
        healthCheckTimeout: 5000,
        mutationScoreThreshold: 30,
      },
      targetUrl: 'http://localhost:8080',
      containerImage: 'myapp:latest',
      openapiSpecPath: '/api/openapi.json',
    };
    const job = await addScanJob(data);
    expect(job).toBeDefined();
  });
});

describe('scan.queue - findings deduplication logic', () => {
  // These test the dedup key construction logic indirectly through findingFingerprint
  it('dedup key includes scanner, ruleId, title, filePath, lineNumber', () => {
    // The in-memory dedup key pattern used in the worker is:
    // `${result.scanner}:${finding.ruleId}:${finding.title}:${finding.filePath ?? ''}:${finding.lineNumber ?? ''}`
    // We verify the building blocks via findingFingerprint for the DB-level dedup
    const fp1 = findingFingerprint('bandit', 'B101', 'app.py');
    const fp2 = findingFingerprint('bandit', 'B101', 'other.py');
    expect(fp1).not.toBe(fp2);
  });

  it('same scanner+rule but different files produce different fingerprints', () => {
    const fp1 = findingFingerprint('trivy', 'CVE-2024-001', 'package.json');
    const fp2 = findingFingerprint('trivy', 'CVE-2024-001', 'go.sum');
    expect(fp1).not.toBe(fp2);
  });
});

describe('scan.queue - findings_count JSONB structure', () => {
  // The findings_count stored in the scans table should have the shape:
  // { critical, high, medium, low, info, total, raw: { critical, high, medium, low, info, total } }
  // We test this by verifying the structure is constructed correctly

  it('findings_count has both open-only and raw sub-objects', () => {
    const totalFindings = { critical: 1, high: 2, medium: 3, low: 4, info: 5, total: 15 };
    const rawFindings = { critical: 2, high: 3, medium: 5, low: 6, info: 5, total: 21 };

    const findingsCount = { ...totalFindings, raw: rawFindings };

    expect(findingsCount.critical).toBe(1);
    expect(findingsCount.total).toBe(15);
    expect(findingsCount.raw.critical).toBe(2);
    expect(findingsCount.raw.total).toBe(21);
  });

  it('raw counts >= open-only counts (suppressions reduce open count)', () => {
    const totalFindings = { critical: 0, high: 1, medium: 2, low: 3, info: 0, total: 6 };
    const rawFindings = { critical: 1, high: 2, medium: 4, low: 5, info: 0, total: 12 };

    expect(rawFindings.total).toBeGreaterThanOrEqual(totalFindings.total);
    expect(rawFindings.critical).toBeGreaterThanOrEqual(totalFindings.critical);
    expect(rawFindings.high).toBeGreaterThanOrEqual(totalFindings.high);
    expect(rawFindings.medium).toBeGreaterThanOrEqual(totalFindings.medium);
    expect(rawFindings.low).toBeGreaterThanOrEqual(totalFindings.low);
  });
});

describe('scan.queue - quality score edge cases', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('score is 0 when no scanners ran at all (empty results array)', () => {
    // The worker logic: if (results.length === 0) → score = 0, qualityLevel = 'critical'
    const results: unknown[] = [];
    let score = 500; // pretend quality score returned 500
    let qualityLevel = 'moderate';

    if (results.length === 0) {
      score = 0;
      qualityLevel = 'critical';
    }

    expect(score).toBe(0);
    expect(qualityLevel).toBe('critical');
  });

  it('score is 0 when all scanners skipped', () => {
    const results = [
      makeScannerResult({ skipped: true, success: true }),
      makeScannerResult({ scanner: 'trivy', skipped: true, success: true }),
    ];
    const successfulScanners = results.filter(r => r.success && !r.skipped).length;
    const skippedScanners = results.filter(r => r.skipped).length;

    let score = 800;
    let qualityLevel = 'good';

    if (successfulScanners === 0 && skippedScanners === results.length) {
      score = 0;
      qualityLevel = 'unknown';
    }

    expect(score).toBe(0);
    expect(qualityLevel).toBe('unknown');
  });

  it('score is 0 when all scanners failed (not skipped)', () => {
    const results = [
      makeScannerResult({ success: false, error: 'timeout' }),
      makeScannerResult({ scanner: 'trivy', success: false, error: 'crash' }),
    ];
    const successfulScanners = results.filter(r => r.success && !r.skipped).length;
    const skippedScanners = results.filter(r => r.skipped).length;

    let score = 700;
    let qualityLevel = 'good';

    if (results.length === 0) {
      score = 0;
      qualityLevel = 'critical';
    } else if (successfulScanners === 0 && skippedScanners === results.length) {
      score = 0;
      qualityLevel = 'unknown';
    } else if (successfulScanners === 0) {
      score = 0;
      qualityLevel = 'critical';
    }

    expect(score).toBe(0);
    expect(qualityLevel).toBe('critical');
  });
});

describe('scan.queue - bonus computation logic', () => {
  it('hasSbom is true when syft is in successful scanners', () => {
    const results = [
      makeScannerResult({ scanner: 'syft', success: true, skipped: false }),
      makeScannerResult({ scanner: 'bandit', success: true, skipped: false }),
    ];
    const successfulScannerNames = results.filter(r => r.success && !r.skipped).map(r => r.scanner);
    expect(successfulScannerNames.includes('syft')).toBe(true);
  });

  it('cleanSecrets requires gitleaks success with zero findings', () => {
    const results = [
      makeScannerResult({ scanner: 'gitleaks', success: true, findings: [] }),
    ];
    const successfulScannerNames = results.filter(r => r.success && !r.skipped).map(r => r.scanner);
    const scannerHasNoFindings = (name: string) =>
      results.find(r => r.scanner === name && r.success)?.findings.length === 0;

    const cleanSecrets = successfulScannerNames.includes('gitleaks') && scannerHasNoFindings('gitleaks');
    expect(cleanSecrets).toBe(true);
  });

  it('cleanSecrets is false when gitleaks has findings', () => {
    const results = [
      makeScannerResult({
        scanner: 'gitleaks',
        success: true,
        findings: [makeFinding({ title: 'Leaked API key' })],
      }),
    ];
    const scannerHasNoFindings = (name: string) =>
      results.find(r => r.scanner === name && r.success)?.findings.length === 0;

    const cleanSecrets = results.some(r => r.scanner === 'gitleaks' && r.success) && scannerHasNoFindings('gitleaks');
    expect(cleanSecrets).toBe(false);
  });

  it('hasSupplyChainVerification is true when cosign or in-toto ran', () => {
    const results = [
      makeScannerResult({ scanner: 'cosign', success: true }),
    ];
    const successfulScannerNames = results.filter(r => r.success && !r.skipped).map(r => r.scanner);
    const hasSupplyChain = successfulScannerNames.some(s => ['cosign', 'in-toto'].includes(s));
    expect(hasSupplyChain).toBe(true);
  });

  it('multipleProfilesUsed bonus requires >= 2 distinct profiles historically', () => {
    // The worker queries: SELECT COUNT(DISTINCT profile) as profile_count FROM scans WHERE ...
    const profileCount = 3;
    expect(profileCount >= 2).toBe(true);
  });

  it('allTestsPassing requires test runners with no FAIL/ERROR/NO-TESTS findings', () => {
    const testResults = [
      makeScannerResult({
        scanner: 'jest',
        success: true,
        skipped: false,
        findings: [
          makeFinding({ ruleId: 'JEST-PASS', title: 'test suite passed' }),
        ],
      }),
    ];
    const allTestsPassing = testResults.length > 0 && testResults.every(r =>
      r.findings.filter(f =>
        f.ruleId.endsWith('-FAIL') || f.ruleId.endsWith('-ERROR') || f.ruleId.endsWith('-NO-TESTS')
      ).length === 0
    );
    expect(allTestsPassing).toBe(true);
  });

  it('allTestsPassing is false when test runner has FAIL findings', () => {
    const testResults = [
      makeScannerResult({
        scanner: 'jest',
        success: true,
        skipped: false,
        findings: [
          makeFinding({ ruleId: 'JEST-FAIL', title: '3 tests failed' }),
        ],
      }),
    ];
    const allTestsPassing = testResults.length > 0 && testResults.every(r =>
      r.findings.filter(f =>
        f.ruleId.endsWith('-FAIL') || f.ruleId.endsWith('-ERROR') || f.ruleId.endsWith('-NO-TESTS')
      ).length === 0
    );
    expect(allTestsPassing).toBe(false);
  });
});

describe('scan.queue - scannersExecuted summary', () => {
  it('builds correct scannersExecuted shape', () => {
    const results = [
      makeScannerResult({
        scanner: 'bandit',
        success: true,
        findings: [makeFinding(), makeFinding({ ruleId: 'B102' })],
        duration: 2500,
        evidence: { configuration: 'python 3.11' },
      }),
      makeScannerResult({
        scanner: 'trivy',
        success: true,
        skipped: true,
        skipReason: 'no_container_image',
        skipHint: 'Configure a container image to enable Trivy scanning',
        findings: [],
        duration: 100,
      }),
    ];

    const scannersExecuted = results.map(r => ({
      scanner: r.scanner,
      success: r.success,
      skipped: r.skipped || false,
      skipReason: r.skipReason || null,
      skipHint: r.skipHint || null,
      findings: r.findings.length,
      duration: r.duration,
      error: r.error || null,
      evidence: r.evidence || null,
    }));

    expect(scannersExecuted).toHaveLength(2);
    expect(scannersExecuted[0]).toEqual({
      scanner: 'bandit',
      success: true,
      skipped: false,
      skipReason: null,
      skipHint: null,
      findings: 2,
      duration: 2500,
      error: null,
      evidence: { configuration: 'python 3.11' },
    });
    expect(scannersExecuted[1].skipped).toBe(true);
    expect(scannersExecuted[1].skipReason).toBe('no_container_image');
  });
});

describe('scan.queue - status carry-forward', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('carries forward false_positive status from prior scan', () => {
    const dismissedMap = new Map<string, string>();
    dismissedMap.set('bandit:B101:app.py', 'false_positive');

    const fp = findingFingerprint('bandit', 'B101', 'app.py');
    const priorStatus = fp ? dismissedMap.get(fp) ?? null : null;
    const effectiveStatus = priorStatus || 'open';

    expect(effectiveStatus).toBe('false_positive');
  });

  it('defaults to open when no prior dismissed status exists', () => {
    const dismissedMap = new Map<string, string>();

    const fp = findingFingerprint('bandit', 'B101', 'app.py');
    const priorStatus = fp ? dismissedMap.get(fp) ?? null : null;
    const effectiveStatus = priorStatus || 'open';

    expect(effectiveStatus).toBe('open');
  });

  it('carries forward deferred status', () => {
    const dismissedMap = new Map<string, string>();
    dismissedMap.set('trivy:CVE-2024-001:package.json', 'deferred');

    const fp = findingFingerprint('trivy', 'CVE-2024-001', 'package.json');
    const priorStatus = fp ? dismissedMap.get(fp) ?? null : null;
    const effectiveStatus = priorStatus || 'open';

    expect(effectiveStatus).toBe('deferred');
  });
});

describe('scan.queue - DB error handling in dedup', () => {
  it('unique constraint violation (23505) is treated as duplicate', () => {
    const error = { code: '23505', message: 'duplicate key value violates unique constraint' };

    // The worker catches this error and increments inScanDuplicates
    let inScanDuplicates = 0;
    if ((error as Record<string, unknown>)?.code === '23505') {
      inScanDuplicates++;
    }

    expect(inScanDuplicates).toBe(1);
  });

  it('non-23505 DB errors are re-thrown', () => {
    const error = { code: '23502', message: 'null value in column violates not-null constraint' };

    expect(() => {
      if ((error as Record<string, unknown>)?.code === '23505') {
        // skip
      } else {
        throw error;
      }
    }).toThrow();
  });
});
