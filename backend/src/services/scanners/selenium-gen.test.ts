// backend/src/services/scanners/selenium-gen.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the code analysis module
vi.mock('../test-generator/code-analyzer/index.js', () => ({
  analyzeCode: vi.fn(),
}));

import { runSeleniumGen } from './selenium-gen.js';
import { analyzeCode } from '../test-generator/code-analyzer/index.js';
import type { ScanJobData } from '../queue/scan.queue.js';

const mockJobData: ScanJobData = {
  scanId: 'test-scan-123',
  projectId: 'test-project-456',
  userId: 'test-user',
  profile: 'comprehensive',
  branch: 'main',
  scanners: ['selenium-gen'],
};

describe('selenium-gen scanner', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('skips when code analysis finds no endpoints', async () => {
    const mockAnalysis = {
      result: {
        languages: [],
        frameworks: [],
        endpoints: [],
        authPatterns: [],
        dataFlows: [],
      },
      metadata: { durationMs: 100 },
    };
    vi.mocked(analyzeCode).mockResolvedValue(mockAnalysis as any);

    const result = await runSeleniumGen(mockJobData);

    expect(result.scanner).toBe('selenium-gen');
    expect(result.success).toBe(true);
    expect(result.skipped).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('SELENIUM-GEN-SKIPPED');
  });

  it('generates functional tests from detected endpoints', async () => {
    const mockAnalysis = {
      result: {
        languages: [{ language: 'TypeScript', percentage: 80 }],
        frameworks: [{ name: 'Express', framework: 'express' }],
        endpoints: [
          { method: 'GET', path: '/api/users', file: 'src/routes.ts', line: 10 },
          { method: 'POST', path: '/api/login', file: 'src/auth.ts', line: 25, authentication: 'jwt' },
        ],
        authPatterns: [
          { type: 'jwt', file: 'src/auth.ts', line: 5, mechanism: 'jsonwebtoken', indicators: ['jwt.verify'] },
        ],
        dataFlows: [],
      },
      metadata: { durationMs: 200 },
    };
    vi.mocked(analyzeCode).mockResolvedValue(mockAnalysis as any);

    const result = await runSeleniumGen(mockJobData);

    expect(result.scanner).toBe('selenium-gen');
    expect(result.success).toBe(true);
    expect(result.skipped).toBeUndefined();
    const functionalFinding = result.findings.find(f => f.ruleId === 'SELENIUM-GEN-FUNCTIONAL');
    const securityFinding = result.findings.find(f => f.ruleId === 'SELENIUM-GEN-SECURITY');
    expect(functionalFinding).toBeDefined();
    expect(functionalFinding!.severity).toBe('info');
    expect(securityFinding).toBeDefined();
    expect(result.rawOutput).toBeDefined();
    const parsed = JSON.parse(result.rawOutput!);
    expect(parsed.functionalTestCount).toBeGreaterThan(0);
    expect(parsed.securityTestCount).toBeGreaterThan(0);
    expect(parsed.functionalTestCode).toContain('selenium-webdriver');
    expect(parsed.securityTestCode).toContain('selenium-webdriver');
  });

  it('generates XSS tests for endpoints with user input', async () => {
    const mockAnalysis = {
      result: {
        languages: [{ language: 'JavaScript', percentage: 100 }],
        frameworks: [{ name: 'Express', framework: 'express' }],
        endpoints: [
          {
            method: 'POST', path: '/api/comments', file: 'src/comments.ts', line: 15,
            parameters: [{ name: 'body', location: 'body', type: 'string' }],
          },
        ],
        authPatterns: [],
        dataFlows: [
          {
            id: 'df-1',
            source: { type: 'user_input', location: 'src/comments.ts', variable: 'body', line: 16 },
            sink: { type: 'response', location: 'src/comments.ts', operation: 'res.send', line: 20 },
            path: [],
            sanitized: false,
            validated: false,
            tainted: true,
            riskLevel: 'high',
          },
        ],
      },
      metadata: { durationMs: 150 },
    };
    vi.mocked(analyzeCode).mockResolvedValue(mockAnalysis as any);

    const result = await runSeleniumGen(mockJobData);

    expect(result.success).toBe(true);
    const securityFinding = result.findings.find(f => f.ruleId === 'SELENIUM-GEN-SECURITY');
    expect(securityFinding).toBeDefined();
    const parsed = JSON.parse(result.rawOutput!);
    expect(parsed.securityTestCode).toContain('<script>');
  });

  it('generates auth bypass tests for protected routes', async () => {
    const mockAnalysis = {
      result: {
        languages: [{ language: 'TypeScript', percentage: 100 }],
        frameworks: [{ name: 'Express', framework: 'express' }],
        endpoints: [
          { method: 'GET', path: '/api/admin', file: 'src/admin.ts', line: 10, authentication: 'jwt' },
          { method: 'DELETE', path: '/api/users/:id', file: 'src/users.ts', line: 30, authentication: 'session' },
        ],
        authPatterns: [
          { type: 'jwt', file: 'src/auth.ts', line: 5, mechanism: 'jsonwebtoken', indicators: ['jwt.verify'] },
        ],
        dataFlows: [],
      },
      metadata: { durationMs: 100 },
    };
    vi.mocked(analyzeCode).mockResolvedValue(mockAnalysis as any);

    const result = await runSeleniumGen(mockJobData);

    expect(result.success).toBe(true);
    const parsed = JSON.parse(result.rawOutput!);
    expect(parsed.securityTestCode).toContain('/api/admin');
    expect(parsed.securityTestCode).toContain('without authentication');
  });

  it('handles code analysis failure gracefully', async () => {
    vi.mocked(analyzeCode).mockRejectedValue(new Error('Analysis failed'));

    const result = await runSeleniumGen(mockJobData);

    expect(result.scanner).toBe('selenium-gen');
    expect(result.success).toBe(true);
    expect(result.skipped).toBe(true);
  });
});
