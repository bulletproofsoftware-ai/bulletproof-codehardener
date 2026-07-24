import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { NormalizedFinding } from '../../types/index.js';

vi.mock('../../config/env.js', () => ({
  env: {},
}));

vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

const mockExecute = vi.fn();
vi.mock('../../db/client.js', () => ({
  db: {
    execute: (...args: unknown[]) => mockExecute(...args),
  },
}));

vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({
    strings,
    values,
    _tag: 'sql',
  }),
}));

import { evaluateFindings } from './evaluator.js';

function makeFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    title: 'Test Finding',
    description: 'A test finding',
    severity: 'medium',
    scanner: 'test-scanner',
    confidence: 'high',
    ...overrides,
  };
}

describe('Policy Evaluator', () => {
  beforeEach(() => {
    mockExecute.mockReset();
  });

  it('returns passed when no policies exist', async () => {
    mockExecute.mockResolvedValueOnce({ rows: [] }); // no policies

    const result = await evaluateFindings('user-1', 'project-1', []);

    expect(result.passed).toBe(true);
    expect(result.shouldBlock).toBe(false);
    expect(result.violations).toHaveLength(0);
    expect(result.warnings).toHaveLength(0);
  });

  it('evaluates severity_threshold rule and blocks', async () => {
    // Return one active policy
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'policy-1',
        name: 'Security Policy',
        severity_threshold: null,
        auto_fail: false,
      }],
    });
    // Return one rule for the policy
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'rule-1',
        rule_type: 'severity_threshold',
        condition: { severity: 'critical', max_allowed: 0 },
        action: 'block',
        message: 'No critical findings allowed',
      }],
    });

    const findings = [
      makeFinding({ severity: 'critical', title: 'SQL Injection' }),
      makeFinding({ severity: 'high', title: 'XSS' }),
    ];

    const result = await evaluateFindings('user-1', 'project-1', findings);

    expect(result.passed).toBe(false);
    expect(result.shouldBlock).toBe(true);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].ruleType).toBe('severity_threshold');
    expect(result.violations[0].action).toBe('block');
  });

  it('evaluates no_secrets rule', async () => {
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'policy-1',
        name: 'No Secrets Policy',
        severity_threshold: null,
        auto_fail: false,
      }],
    });
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'rule-2',
        rule_type: 'no_secrets',
        condition: {},
        action: 'block',
        message: 'Hardcoded secrets not allowed',
      }],
    });

    const findings = [
      makeFinding({ cweId: 'CWE-798', title: 'Hardcoded password' }),
    ];

    const result = await evaluateFindings('user-1', 'project-1', findings);

    expect(result.passed).toBe(false);
    expect(result.shouldBlock).toBe(true);
    expect(result.violations[0].ruleType).toBe('no_secrets');
  });

  it('evaluates max_total_findings rule', async () => {
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'policy-1',
        name: 'Cap Policy',
        severity_threshold: null,
        auto_fail: false,
      }],
    });
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'rule-3',
        rule_type: 'max_total_findings',
        condition: { max: 2 },
        action: 'warn',
        message: 'Too many findings',
      }],
    });

    const findings = [
      makeFinding({ title: 'Finding 1' }),
      makeFinding({ title: 'Finding 2' }),
      makeFinding({ title: 'Finding 3' }),
    ];

    const result = await evaluateFindings('user-1', 'project-1', findings);

    expect(result.passed).toBe(true); // warn action doesn't block
    expect(result.shouldBlock).toBe(false);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0].ruleType).toBe('max_total_findings');
  });

  it('evaluates cwe_blocklist rule', async () => {
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'policy-1',
        name: 'CWE Block Policy',
        severity_threshold: null,
        auto_fail: false,
      }],
    });
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'rule-4',
        rule_type: 'cwe_blocklist',
        condition: { cwes: ['CWE-89', 'CWE-79'] },
        action: 'block',
        message: 'Blocked CWE found',
      }],
    });

    const findings = [
      makeFinding({ cweId: 'CWE-89', title: 'SQL Injection' }),
    ];

    const result = await evaluateFindings('user-1', 'project-1', findings);

    expect(result.passed).toBe(false);
    expect(result.shouldBlock).toBe(true);
    expect(result.violations[0].ruleType).toBe('cwe_blocklist');
  });

  it('evaluates policy-level severity_threshold with auto_fail', async () => {
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'policy-1',
        name: 'Auto Fail Policy',
        severity_threshold: 'high',
        auto_fail: true,
      }],
    });
    // No individual rules
    mockExecute.mockResolvedValueOnce({ rows: [] });

    const findings = [
      makeFinding({ severity: 'high', title: 'High severity issue' }),
    ];

    const result = await evaluateFindings('user-1', 'project-1', findings);

    expect(result.passed).toBe(false);
    expect(result.shouldBlock).toBe(true);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].ruleType).toBe('severity_threshold');
    expect(result.violations[0].message).toContain('auto-fail');
  });

  it('passes when severity is below threshold', async () => {
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'policy-1',
        name: 'Standard Policy',
        severity_threshold: 'critical',
        auto_fail: true,
      }],
    });
    mockExecute.mockResolvedValueOnce({ rows: [] });

    const findings = [
      makeFinding({ severity: 'high', title: 'High but not critical' }),
      makeFinding({ severity: 'medium', title: 'Medium issue' }),
    ];

    const result = await evaluateFindings('user-1', 'project-1', findings);

    // auto_fail is for critical, but we only have high/medium
    expect(result.passed).toBe(true);
    expect(result.shouldBlock).toBe(false);
  });

  it('handles multiple policies with multiple rules', async () => {
    // Two policies
    mockExecute.mockResolvedValueOnce({
      rows: [
        { id: 'policy-1', name: 'Policy A', severity_threshold: null, auto_fail: false },
        { id: 'policy-2', name: 'Policy B', severity_threshold: null, auto_fail: false },
      ],
    });
    // Rules for policy-1
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'rule-1',
        rule_type: 'severity_threshold',
        condition: { severity: 'critical', max_allowed: 0 },
        action: 'block',
        message: '',
      }],
    });
    // Rules for policy-2
    mockExecute.mockResolvedValueOnce({
      rows: [{
        id: 'rule-2',
        rule_type: 'no_secrets',
        condition: {},
        action: 'warn',
        message: '',
      }],
    });

    const findings = [
      makeFinding({ severity: 'critical', title: 'Critical vuln' }),
      makeFinding({ ruleId: 'secret-detected', title: 'API key in code' }),
    ];

    const result = await evaluateFindings('user-1', 'project-1', findings);

    expect(result.passed).toBe(false);
    expect(result.shouldBlock).toBe(true);
    expect(result.violations).toHaveLength(1);
    expect(result.warnings).toHaveLength(1);
  });
});
