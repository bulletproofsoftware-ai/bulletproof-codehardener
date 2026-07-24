import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mocks ──────────────────────────────────────────────────────

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

// ── Imports ────────────────────────────────────────────────────

import {
  createScanAttestation,
  verifyAttestation,
  storeAttestation,
  getAttestationByScanId,
  generateAttestationBundle,
  type ScanAttestation,
} from './attestation.js';

// ── Helpers ────────────────────────────────────────────────────

function makeScanResult() {
  return {
    profile: 'standard',
    scannersUsed: ['bandit', 'trivy', 'gitleaks'],
    startTime: new Date('2026-03-14T10:00:00Z'),
    endTime: new Date('2026-03-14T10:05:00Z'),
    duration: 300000,
    findings: {
      critical: 0,
      high: 2,
      medium: 5,
      low: 10,
      info: 3,
      total: 20,
    },
    score: 800,
    qualityLevel: 'good',
  };
}

// ── Tests ──────────────────────────────────────────────────────

describe('attestation - createScanAttestation', () => {
  it('generates attestation with correct structure', async () => {
    const attestation = await createScanAttestation(
      'scan-1',
      'proj-1',
      'My Project',
      makeScanResult(),
    );

    expect(attestation.id).toBeDefined();
    expect(attestation.id).toMatch(/^[0-9a-f-]{36}$/); // UUID format
    expect(attestation.scanId).toBe('scan-1');
    expect(attestation.projectId).toBe('proj-1');
    expect(attestation.timestamp).toBeDefined();
    expect(attestation.subject.name).toBe('My Project');
    expect(attestation.subject.digest.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(attestation.predicate.type).toBe('https://codehardener.com/scan/v1');
  });

  it('includes scan metadata in predicate', async () => {
    const scanResult = makeScanResult();
    const attestation = await createScanAttestation('scan-2', 'proj-1', 'Test', scanResult);

    expect(attestation.predicate.scanMetadata.scanId).toBe('scan-2');
    expect(attestation.predicate.scanMetadata.profile).toBe('standard');
    expect(attestation.predicate.scanMetadata.scannersUsed).toEqual(['bandit', 'trivy', 'gitleaks']);
    expect(attestation.predicate.scanMetadata.duration).toBe(300000);
    expect(attestation.predicate.scanMetadata.startTime).toBe('2026-03-14T10:00:00.000Z');
    expect(attestation.predicate.scanMetadata.endTime).toBe('2026-03-14T10:05:00.000Z');
  });

  it('includes findings summary in predicate', async () => {
    const attestation = await createScanAttestation('scan-3', 'proj-1', 'Test', makeScanResult());

    expect(attestation.predicate.findings.total).toBe(20);
    expect(attestation.predicate.findings.bySeverity).toEqual({
      critical: 0,
      high: 2,
      medium: 5,
      low: 10,
      info: 3,
    });
  });

  it('includes score and quality level in predicate', async () => {
    const attestation = await createScanAttestation('scan-4', 'proj-1', 'Test', makeScanResult());

    expect(attestation.predicate.score).toBe(800);
    expect(attestation.predicate.qualityLevel).toBe('good');
  });

  it('generates unique content hash (different inputs produce different hashes)', async () => {
    const result1 = makeScanResult();
    const result2 = { ...makeScanResult(), score: 600 };

    const att1 = await createScanAttestation('scan-a', 'proj-1', 'Test', result1);
    const att2 = await createScanAttestation('scan-b', 'proj-1', 'Test', result2);

    expect(att1.subject.digest.sha256).not.toBe(att2.subject.digest.sha256);
  });
});

describe('attestation - verifyAttestation', () => {
  it('returns invalid when attestation has no signature', async () => {
    const attestation: ScanAttestation = {
      id: 'att-1',
      scanId: 'scan-1',
      projectId: 'proj-1',
      timestamp: new Date().toISOString(),
      subject: {
        name: 'Test',
        digest: { sha256: 'abc123' },
      },
      predicate: {
        type: 'https://codehardener.com/scan/v1',
        scanMetadata: {
          scanId: 'scan-1',
          profile: 'standard',
          scannersUsed: [],
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          duration: 1000,
        },
        findings: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
        score: 1000,
        qualityLevel: 'excellent',
      },
    };

    const result = await verifyAttestation(attestation);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Attestation is not signed');
  });

  it('returns invalid when attestation has no certificate', async () => {
    const attestation: ScanAttestation = {
      id: 'att-2',
      scanId: 'scan-1',
      projectId: 'proj-1',
      timestamp: new Date().toISOString(),
      subject: {
        name: 'Test',
        digest: { sha256: 'abc123' },
      },
      predicate: {
        type: 'https://codehardener.com/scan/v1',
        scanMetadata: {
          scanId: 'scan-1',
          profile: 'standard',
          scannersUsed: [],
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          duration: 1000,
        },
        findings: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
        score: 1000,
        qualityLevel: 'excellent',
      },
      signature: 'some-sig',
      // no certificate
    };

    const result = await verifyAttestation(attestation);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Attestation is not signed');
  });
});

describe('attestation - storeAttestation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('inserts attestation into database', async () => {
    mockDbExecute.mockResolvedValueOnce({ rows: [] });

    const attestation: ScanAttestation = {
      id: 'att-store-1',
      scanId: 'scan-1',
      projectId: 'proj-1',
      timestamp: '2026-03-14T10:00:00.000Z',
      subject: {
        name: 'My Project',
        digest: { sha256: 'deadbeef'.repeat(8) },
      },
      predicate: {
        type: 'https://codehardener.com/scan/v1',
        scanMetadata: {
          scanId: 'scan-1',
          profile: 'standard',
          scannersUsed: ['bandit'],
          startTime: '2026-03-14T10:00:00.000Z',
          endTime: '2026-03-14T10:05:00.000Z',
          duration: 300000,
        },
        findings: { total: 5, bySeverity: { critical: 0, high: 1, medium: 2, low: 1, info: 1 } },
        score: 800,
        qualityLevel: 'good',
      },
      signature: 'base64sig==',
      signatureAlgorithm: 'ed25519-local',
      certificate: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
    };

    await storeAttestation(attestation);
    expect(mockDbExecute).toHaveBeenCalledTimes(1);
  });

  it('stores unsigned attestation (null signature fields)', async () => {
    mockDbExecute.mockResolvedValueOnce({ rows: [] });

    const attestation: ScanAttestation = {
      id: 'att-unsigned',
      scanId: 'scan-2',
      projectId: 'proj-1',
      timestamp: '2026-03-14T10:00:00.000Z',
      subject: {
        name: 'Test',
        digest: { sha256: 'abc'.repeat(21) + 'a' },
      },
      predicate: {
        type: 'https://codehardener.com/scan/v1',
        scanMetadata: {
          scanId: 'scan-2',
          profile: 'quick',
          scannersUsed: [],
          startTime: '2026-03-14T10:00:00.000Z',
          endTime: '2026-03-14T10:00:01.000Z',
          duration: 1000,
        },
        findings: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
        score: 1000,
        qualityLevel: 'excellent',
      },
      // No signature, certificate, etc.
    };

    await storeAttestation(attestation);
    expect(mockDbExecute).toHaveBeenCalledTimes(1);
  });
});

describe('attestation - getAttestationByScanId', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns null when no attestation found', async () => {
    mockDbExecute.mockResolvedValueOnce({ rows: [] });
    const result = await getAttestationByScanId('scan-nonexistent');
    expect(result).toBeNull();
  });

  it('returns attestation with correct fields when found', async () => {
    mockDbExecute.mockResolvedValueOnce({
      rows: [{
        id: 'att-1',
        scan_id: 'scan-1',
        subject_name: 'My Project',
        subject_digest: 'deadbeef'.repeat(8),
        predicate: {
          type: 'https://codehardener.com/scan/v1',
          scanMetadata: { scanId: 'scan-1', profile: 'standard', scannersUsed: [], startTime: '', endTime: '', duration: 0 },
          findings: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
          score: 1000,
          qualityLevel: 'excellent',
        },
        signature: 'sig123',
        signature_algorithm: 'ed25519-local',
        certificate: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
        rekor_log_id: null,
        created_at: '2026-03-14T10:00:00.000Z',
      }],
    });

    const result = await getAttestationByScanId('scan-1');
    expect(result).not.toBeNull();
    expect(result!.id).toBe('att-1');
    expect(result!.scanId).toBe('scan-1');
    expect(result!.subject.name).toBe('My Project');
    expect(result!.signature).toBe('sig123');
    expect(result!.signatureAlgorithm).toBe('ed25519-local');
  });
});

describe('attestation - generateAttestationBundle', () => {
  it('generates valid JSON bundle with in-toto format', () => {
    const attestation: ScanAttestation = {
      id: 'att-bundle',
      scanId: 'scan-1',
      projectId: 'proj-1',
      timestamp: '2026-03-14T10:00:00.000Z',
      subject: {
        name: 'My Project',
        digest: { sha256: 'deadbeef'.repeat(8) },
      },
      predicate: {
        type: 'https://codehardener.com/scan/v1',
        scanMetadata: {
          scanId: 'scan-1',
          profile: 'standard',
          scannersUsed: ['bandit'],
          startTime: '2026-03-14T10:00:00.000Z',
          endTime: '2026-03-14T10:05:00.000Z',
          duration: 300000,
        },
        findings: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
        score: 1000,
        qualityLevel: 'excellent',
      },
      signature: 'base64sig==',
      signatureAlgorithm: 'ed25519-local',
      certificate: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
    };

    const bundleStr = generateAttestationBundle(attestation);
    const bundle = JSON.parse(bundleStr);

    expect(bundle.mediaType).toBe('application/vnd.codehardener.attestation+json');
    expect(bundle.attestation._type).toBe('https://in-toto.io/Statement/v0.1');
    expect(bundle.attestation.subject).toEqual([attestation.subject]);
    expect(bundle.attestation.predicateType).toBe('https://codehardener.com/scan/v1');
    expect(bundle.signatureAlgorithm).toBe('ed25519-local');
    expect(bundle.signatures).toHaveLength(1);
    expect(bundle.signatures[0].keyid).toBe('local-ed25519');
    expect(bundle.signatures[0].sig).toBe('base64sig==');
  });

  it('generates bundle with empty signatures when unsigned', () => {
    const attestation: ScanAttestation = {
      id: 'att-unsigned-bundle',
      scanId: 'scan-1',
      projectId: 'proj-1',
      timestamp: '2026-03-14T10:00:00.000Z',
      subject: {
        name: 'Test',
        digest: { sha256: 'abc'.repeat(21) + 'a' },
      },
      predicate: {
        type: 'https://codehardener.com/scan/v1',
        scanMetadata: {
          scanId: 'scan-1',
          profile: 'quick',
          scannersUsed: [],
          startTime: '2026-03-14T10:00:00.000Z',
          endTime: '2026-03-14T10:00:01.000Z',
          duration: 1000,
        },
        findings: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
        score: 1000,
        qualityLevel: 'excellent',
      },
    };

    const bundleStr = generateAttestationBundle(attestation);
    const bundle = JSON.parse(bundleStr);

    expect(bundle.signatures).toEqual([]);
    expect(bundle.signatureAlgorithm).toBe('unknown');
    expect(bundle.rekorBundle).toBeNull();
  });

  it('includes rekor bundle when rekorLogId is present', () => {
    const attestation: ScanAttestation = {
      id: 'att-rekor',
      scanId: 'scan-1',
      projectId: 'proj-1',
      timestamp: '2026-03-14T10:00:00.000Z',
      subject: {
        name: 'Test',
        digest: { sha256: '1234'.repeat(16) },
      },
      predicate: {
        type: 'https://codehardener.com/scan/v1',
        scanMetadata: {
          scanId: 'scan-1',
          profile: 'standard',
          scannersUsed: [],
          startTime: '2026-03-14T10:00:00.000Z',
          endTime: '2026-03-14T10:05:00.000Z',
          duration: 300000,
        },
        findings: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
        score: 1000,
        qualityLevel: 'excellent',
      },
      signature: 'sig',
      signatureAlgorithm: 'sigstore-cosign',
      certificate: 'cert-data',
      rekorLogId: '12345',
    };

    const bundleStr = generateAttestationBundle(attestation);
    const bundle = JSON.parse(bundleStr);

    expect(bundle.rekorBundle).toEqual({
      logId: '12345',
      logIndex: '12345',
    });
    expect(bundle.signatures[0].keyid).toBe(''); // non-ed25519-local gets empty keyid
  });
});
