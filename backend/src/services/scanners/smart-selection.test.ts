import { describe, it, expect } from 'vitest';
import { augmentScannersWithContext } from './smart-selection.js';
import type { DetectedProjectContext } from '../../types/index.js';

const emptyContext: DetectedProjectContext = {
  openapi: [],
  postmanCollections: [],
  pactContracts: [],
  dockerComposeFile: null,
  dockerfile: null,
  detectedFramework: null,
  suggestedDevPort: null,
};

describe('augmentScannersWithContext', () => {
  it('adds DAST scanners when targetUrl is set for comprehensive profile', () => {
    const base = ['opengrep', 'trivy', 'gitleaks'];
    const result = augmentScannersWithContext(base, 'comprehensive', {
      targetUrl: 'http://localhost:3000',
      detectedSpecs: emptyContext,
    });
    expect(result).toContain('zap');
    expect(result).toContain('nuclei');
    expect(result).toContain('pa11y');
  });

  it('does not add DAST scanners for quick profile', () => {
    const base = ['gitleaks', 'trivy'];
    const result = augmentScannersWithContext(base, 'quick', {
      targetUrl: 'http://localhost:3000',
      detectedSpecs: emptyContext,
    });
    expect(result).not.toContain('zap');
    expect(result).not.toContain('nuclei');
  });

  it('adds Spectral/Schemathesis when OpenAPI spec detected', () => {
    const base = ['opengrep', 'trivy'];
    const result = augmentScannersWithContext(base, 'comprehensive', {
      detectedSpecs: { ...emptyContext, openapi: ['/scan-target/openapi.yaml'] },
    });
    expect(result).toContain('spectral');
    expect(result).toContain('schemathesis');
  });

  it('adds Newman when Postman collection detected', () => {
    const base = ['opengrep'];
    const result = augmentScannersWithContext(base, 'comprehensive', {
      detectedSpecs: { ...emptyContext, postmanCollections: ['/scan-target/api.postman_collection.json'] },
    });
    expect(result).toContain('newman');
  });

  it('adds Dockle when containerImage set', () => {
    const base = ['trivy', 'grype'];
    const result = augmentScannersWithContext(base, 'comprehensive', {
      containerImage: 'ghcr.io/org/app:latest',
      detectedSpecs: emptyContext,
    });
    expect(result).toContain('dockle');
  });

  it('adds Pact when contracts detected', () => {
    const base = ['opengrep'];
    const result = augmentScannersWithContext(base, 'comprehensive', {
      detectedSpecs: { ...emptyContext, pactContracts: ['/scan-target/pacts/consumer.json'] },
    });
    expect(result).toContain('pact');
  });

  it('does not duplicate scanners already in the list', () => {
    const base = ['zap', 'nuclei', 'trivy'];
    const result = augmentScannersWithContext(base, 'comprehensive', {
      targetUrl: 'http://localhost:3000',
      detectedSpecs: emptyContext,
    });
    expect(result.filter(s => s === 'zap').length).toBe(1);
  });

  it('returns base list unchanged when no context', () => {
    const base = ['opengrep', 'trivy', 'gitleaks'];
    const result = augmentScannersWithContext(base, 'standard', {
      detectedSpecs: emptyContext,
    });
    expect(result).toEqual(base);
  });
});
