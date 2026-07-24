import { describe, it, expect, vi } from 'vitest';
import {
  enrichFinding,
  shouldAutoSuppress,
  hasNoConfirmedExploits,
  type EnrichmentResult,
} from './finding-enrichment.js';
import type { NormalizedFinding } from '../../types/index.js';
import type { CodeAnalysisResult, DataFlow, ExtractedEndpoint } from '../test-generator/types.js';
import type { ReachabilityResult } from './reachability.js';

// Mock logger and reachability
vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

vi.mock('./reachability.js', () => ({
  isReachable: (filePath: string | null, reachability: ReachabilityResult) => {
    if (!filePath) return true;
    const normalized = filePath.replace(/^\//, '').replace(/^scan-target\//, '');
    return reachability.reachableFiles.has(normalized);
  },
  getEntryPoint: (filePath: string | null, reachability: ReachabilityResult) => {
    if (!filePath) return null;
    const normalized = filePath.replace(/^\//, '').replace(/^scan-target\//, '');
    return reachability.entryPointMap.get(normalized) || null;
  },
}));

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    ruleId: 'test-rule',
    severity: 'high',
    title: 'Test Finding',
    description: 'A test finding',
    filePath: 'src/controllers/user.ts',
    lineNumber: 42,
    columnNumber: null,
    codeSnippet: null,
    cweId: 'CWE-89',
    owaspCategory: null,
    fixAvailable: false,
    fixDescription: null,
    metadata: {},
    ...overrides,
  };
}

function makeDataFlow(overrides: Partial<DataFlow> = {}): DataFlow {
  return {
    id: 'df-1',
    source: {
      type: 'user_input',
      location: 'src/controllers/user.ts',
      variable: 'req.body.name',
      line: 30,
    },
    sink: {
      type: 'db',
      location: 'src/controllers/user.ts',
      operation: 'query',
      line: 42,
    },
    path: [],
    sanitized: false,
    validated: false,
    tainted: true,
    riskLevel: 'high',
    ...overrides,
  };
}

function makeCodeAnalysis(overrides: Partial<CodeAnalysisResult> = {}): CodeAnalysisResult {
  return {
    id: 'ca-1',
    projectId: 'proj-1',
    analysisDate: new Date(),
    languages: [],
    frameworks: [],
    endpoints: [],
    authPatterns: [],
    dataFlows: [],
    sensitiveData: [],
    dependencies: [],
    infrastructure: [],
    summary: {
      totalFiles: 10,
      totalLinesOfCode: 500,
      primaryLanguage: 'typescript',
      complexityScore: 5,
      testCoverage: null,
    },
    status: 'completed',
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

describe('Finding Enrichment', () => {
  describe('enrichFinding', () => {
    it('marks unreachable findings as unlikely', () => {
      const finding = makeFinding();
      const ca = makeCodeAnalysis();
      const reach = makeReachability([]); // nothing reachable

      const result = enrichFinding(finding, 'semgrep', ca, reach);

      expect(result.reachable).toBe(false);
      expect(result.exploitability).toBe('unlikely');
    });

    it('marks reachable finding with no dataflow as theoretical', () => {
      const finding = makeFinding();
      const ca = makeCodeAnalysis(); // no dataflows
      const reach = makeReachability(['src/controllers/user.ts']);

      const result = enrichFinding(finding, 'semgrep', ca, reach);

      expect(result.reachable).toBe(true);
      expect(result.dataflowMatch).toBe('no_match');
      expect(result.exploitability).toBe('theoretical');
    });

    it('marks sanitized dataflow finding as theoretical', () => {
      const finding = makeFinding();
      const ca = makeCodeAnalysis({
        dataFlows: [makeDataFlow({ sanitized: true, tainted: false })],
      });
      const reach = makeReachability(['src/controllers/user.ts']);

      const result = enrichFinding(finding, 'semgrep', ca, reach);

      expect(result.reachable).toBe(true);
      expect(result.dataflowMatch).toBe('sanitized');
      expect(result.exploitability).toBe('theoretical');
      expect(result.sanitizationEvidence).toBeTruthy();
    });

    it('marks sanitized + auth-protected finding as unlikely', () => {
      const finding = makeFinding();
      const ca = makeCodeAnalysis({
        dataFlows: [makeDataFlow({ sanitized: true, tainted: false })],
        authPatterns: [{
          type: 'jwt',
          file: 'src/controllers/user.ts',
          line: 10,
          mechanism: 'JWT middleware',
          indicators: ['jsonwebtoken'],
        }],
      });
      const reach = makeReachability(['src/controllers/user.ts']);

      const result = enrichFinding(finding, 'semgrep', ca, reach);

      expect(result.exploitability).toBe('unlikely');
    });

    it('marks confirmed dataflow + external endpoint as confirmed exploitable', () => {
      const finding = makeFinding();
      const endpoint: ExtractedEndpoint = {
        method: 'POST',
        path: '/api/users',
        file: 'src/controllers/user.ts',
        line: 40,
      };
      const ca = makeCodeAnalysis({
        dataFlows: [makeDataFlow({ sanitized: false, tainted: true })],
        endpoints: [endpoint],
      });
      const reach = makeReachability(
        ['src/controllers/user.ts'],
        { 'src/controllers/user.ts': 'POST /api/users' },
      );

      const result = enrichFinding(finding, 'semgrep', ca, reach);

      expect(result.reachable).toBe(true);
      expect(result.dataflowMatch).toBe('confirmed');
      expect(result.exploitability).toBe('confirmed');
    });

    it('marks confirmed dataflow + external + auth as likely', () => {
      const finding = makeFinding();
      const endpoint: ExtractedEndpoint = {
        method: 'POST',
        path: '/api/users',
        file: 'src/controllers/user.ts',
        line: 40,
        middleware: ['authMiddleware'],
      };
      const ca = makeCodeAnalysis({
        dataFlows: [makeDataFlow({ sanitized: false, tainted: true })],
        endpoints: [endpoint],
        authPatterns: [{
          type: 'bearer',
          file: 'src/controllers/user.ts',
          line: 5,
          mechanism: 'Bearer token',
          indicators: ['Authorization'],
        }],
      });
      const reach = makeReachability(['src/controllers/user.ts']);

      const result = enrichFinding(finding, 'semgrep', ca, reach);

      expect(result.dataflowMatch).toBe('confirmed');
      expect(result.exploitability).toBe('likely');
    });

    it('matches dataflow within line proximity threshold', () => {
      const finding = makeFinding({ lineNumber: 45 }); // within ±5 of sink at 42
      const ca = makeCodeAnalysis({
        dataFlows: [makeDataFlow({
          sink: { type: 'db', location: 'src/controllers/user.ts', operation: 'query', line: 42 },
          sanitized: false,
          tainted: true,
        })],
      });
      const reach = makeReachability(['src/controllers/user.ts']);

      const result = enrichFinding(finding, 'semgrep', ca, reach);
      expect(result.dataflowMatch).toBe('confirmed');
    });

    it('does NOT match dataflow beyond line proximity threshold', () => {
      const finding = makeFinding({ lineNumber: 100 }); // too far from sink at 42
      const ca = makeCodeAnalysis({
        dataFlows: [makeDataFlow({
          sink: { type: 'db', location: 'src/controllers/user.ts', operation: 'query', line: 42 },
        })],
      });
      const reach = makeReachability(['src/controllers/user.ts']);

      const result = enrichFinding(finding, 'semgrep', ca, reach);
      expect(result.dataflowMatch).toBe('no_match');
    });

    it('handles findings with no file path', () => {
      const finding = makeFinding({ filePath: null, lineNumber: null });
      const ca = makeCodeAnalysis();
      const reach = makeReachability(['src/controllers/user.ts']);

      const result = enrichFinding(finding, 'trivy', ca, reach);

      // No file → reachability defaults to true, no dataflow match
      expect(result.dataflowMatch).toBe('no_match');
    });

    it('normalizes file paths with /scan-target/ prefix', () => {
      const finding = makeFinding({ filePath: '/scan-target/src/controllers/user.ts' });
      const ca = makeCodeAnalysis({
        dataFlows: [makeDataFlow({
          sink: { type: 'db', location: 'src/controllers/user.ts', operation: 'query', line: 42 },
          sanitized: false,
          tainted: true,
        })],
      });
      const reach = makeReachability(['src/controllers/user.ts']);

      const result = enrichFinding(finding, 'semgrep', ca, reach);
      expect(result.dataflowMatch).toBe('confirmed');
    });

    it('includes reachableFrom entry point info', () => {
      const finding = makeFinding();
      const ca = makeCodeAnalysis();
      const reach = makeReachability(
        ['src/controllers/user.ts'],
        { 'src/controllers/user.ts': 'POST /api/users' },
      );

      const result = enrichFinding(finding, 'semgrep', ca, reach);
      expect(result.reachableFrom).toBe('POST /api/users');
    });

    it('marks reachable + no dataflow + external endpoint as likely', () => {
      const finding = makeFinding();
      const endpoint: ExtractedEndpoint = {
        method: 'GET',
        path: '/api/users',
        file: 'src/controllers/user.ts',
        line: 40,
      };
      const ca = makeCodeAnalysis({ endpoints: [endpoint] }); // no dataflows
      const reach = makeReachability(['src/controllers/user.ts']);

      const result = enrichFinding(finding, 'semgrep', ca, reach);

      expect(result.dataflowMatch).toBe('no_match');
      expect(result.exploitability).toBe('likely');
    });

    it('prefers sanitized flow over confirmed when both exist', () => {
      const finding = makeFinding();
      const ca = makeCodeAnalysis({
        dataFlows: [
          makeDataFlow({ id: 'df-1', sanitized: false, tainted: true }),
          makeDataFlow({ id: 'df-2', sanitized: true, tainted: false }),
        ],
      });
      const reach = makeReachability(['src/controllers/user.ts']);

      const result = enrichFinding(finding, 'semgrep', ca, reach);
      // Sanitized flow takes priority — conservative approach
      expect(result.dataflowMatch).toBe('sanitized');
    });
  });

  describe('shouldAutoSuppress', () => {
    it('suppresses when dataflow is sanitized', () => {
      const enrichment: EnrichmentResult = {
        reachable: true,
        dataflowMatch: 'sanitized',
        sanitizationEvidence: 'Input sanitized via DOMPurify',
        exploitability: 'theoretical',
        suppressAsFramework: false,
      };

      const result = shouldAutoSuppress(enrichment);
      expect(result.suppress).toBe(true);
      expect(result.reason).toContain('sanitized');
    });

    it('does NOT suppress when dataflow is confirmed', () => {
      const enrichment: EnrichmentResult = {
        reachable: true,
        dataflowMatch: 'confirmed',
        exploitability: 'confirmed',
        suppressAsFramework: false,
      };

      const result = shouldAutoSuppress(enrichment);
      expect(result.suppress).toBe(false);
    });

    it('does NOT suppress on no_match', () => {
      const enrichment: EnrichmentResult = {
        reachable: true,
        dataflowMatch: 'no_match',
        exploitability: 'theoretical',
        suppressAsFramework: false,
      };

      const result = shouldAutoSuppress(enrichment);
      expect(result.suppress).toBe(false);
    });

    it('does NOT suppress on unreachable alone', () => {
      const enrichment: EnrichmentResult = {
        reachable: false,
        dataflowMatch: 'no_match',
        exploitability: 'unlikely',
        suppressAsFramework: false,
      };

      const result = shouldAutoSuppress(enrichment);
      expect(result.suppress).toBe(false);
    });
  });

  describe('hasNoConfirmedExploits', () => {
    it('returns true when all enrichments are theoretical or unlikely', () => {
      const map = new Map<string, EnrichmentResult>([
        ['f1', { reachable: true, dataflowMatch: 'no_match', exploitability: 'theoretical', suppressAsFramework: false }],
        ['f2', { reachable: false, dataflowMatch: 'no_match', exploitability: 'unlikely', suppressAsFramework: false }],
        ['f3', { reachable: true, dataflowMatch: 'sanitized', exploitability: 'theoretical', suppressAsFramework: false }],
      ]);

      expect(hasNoConfirmedExploits(map)).toBe(true);
    });

    it('returns false when any enrichment is confirmed', () => {
      const map = new Map<string, EnrichmentResult>([
        ['f1', { reachable: true, dataflowMatch: 'no_match', exploitability: 'theoretical', suppressAsFramework: false }],
        ['f2', { reachable: true, dataflowMatch: 'confirmed', exploitability: 'confirmed', suppressAsFramework: false }],
      ]);

      expect(hasNoConfirmedExploits(map)).toBe(false);
    });

    it('returns false when any enrichment is likely', () => {
      const map = new Map<string, EnrichmentResult>([
        ['f1', { reachable: true, dataflowMatch: 'confirmed', exploitability: 'likely', suppressAsFramework: false }],
      ]);

      expect(hasNoConfirmedExploits(map)).toBe(false);
    });

    it('returns false when map is empty', () => {
      expect(hasNoConfirmedExploits(new Map())).toBe(false);
    });
  });
});
