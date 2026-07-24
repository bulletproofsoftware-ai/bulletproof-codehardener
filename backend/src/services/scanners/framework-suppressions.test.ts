import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getFrameworkSuppressions, applyFrameworkSuppressions, type SuppressionMatch } from './framework-suppressions.js';
import type { FrameworkDetection } from '../test-generator/types.js';

// Mock logger
vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

// Mock db
const mockExecute = vi.fn();
vi.mock('../../db/client.js', () => ({
  db: {
    execute: (...args: unknown[]) => mockExecute(...args),
  },
}));

vi.mock('drizzle-orm', () => ({
  sql: Object.assign(
    (strings: TemplateStringsArray, ...values: unknown[]) => ({
      strings,
      values,
      _tag: 'sql',
    }),
    {
      join: (items: unknown[], separator: unknown) => ({ items, separator, _tag: 'sql.join' }),
    },
  ),
}));

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeFramework(overrides: Partial<FrameworkDetection> = {}): FrameworkDetection {
  return {
    framework: 'express',
    type: 'api',
    confidence: 0.9,
    indicators: ['package.json'],
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Framework Suppressions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getFrameworkSuppressions', () => {
    it('returns empty array when no frameworks detected', () => {
      const result = getFrameworkSuppressions([]);
      expect(result).toEqual([]);
    });

    it('suppresses Django ORM SQL injection false positives', () => {
      const frameworks = [makeFramework({ framework: 'django', type: 'web' })];
      const result = getFrameworkSuppressions(frameworks);

      const sqlInjection = result.find(s => s.cwePattern === 'CWE-89');
      expect(sqlInjection).toBeDefined();
      expect(sqlInjection!.framework).toBe('django');
      expect(sqlInjection!.reason).toContain('parameterized queries');
    });

    it('suppresses React JSX XSS false positives', () => {
      const frameworks = [makeFramework({ framework: 'react', type: 'web' })];
      const result = getFrameworkSuppressions(frameworks);

      const xss = result.find(s => s.cwePattern === 'CWE-79');
      expect(xss).toBeDefined();
      expect(xss!.framework).toBe('react');
      expect(xss!.reason).toContain('auto-escapes');
      expect(xss!.titlePattern).toBeDefined();
      expect(xss!.titlePattern!.test('XSS vulnerability')).toBe(true);
      expect(xss!.titlePattern!.test('Cross-Site Scripting detected')).toBe(true);
    });

    it('suppresses Express security header findings when helmet detected', () => {
      const frameworks = [makeFramework({ framework: 'express', type: 'api' })];
      const result = getFrameworkSuppressions(frameworks);

      const headers = result.find(s => s.reason.includes('helmet'));
      expect(headers).toBeDefined();
      expect(headers!.framework).toBe('express');
      expect(headers!.titlePattern).toBeDefined();
      expect(headers!.titlePattern!.test('Missing Security Header X-Frame-Options')).toBe(true);
      expect(headers!.titlePattern!.test('HSTS not enabled')).toBe(true);
    });

    it('does NOT suppress findings for unrecognized frameworks', () => {
      const frameworks = [makeFramework({ framework: 'unknown-framework', type: 'web' })];
      const result = getFrameworkSuppressions(frameworks);
      expect(result).toEqual([]);
    });

    it('handles multiple frameworks in same project', () => {
      const frameworks = [
        makeFramework({ framework: 'django', type: 'web' }),
        makeFramework({ framework: 'react', type: 'web' }),
      ];
      const result = getFrameworkSuppressions(frameworks);

      const djangoRules = result.filter(s => s.framework === 'django');
      const reactRules = result.filter(s => s.framework === 'react');

      expect(djangoRules.length).toBe(3); // SQL injection, CSRF, XSS
      expect(reactRules.length).toBe(1);  // XSS
    });

    it('returns correct suppression reason for each framework', () => {
      const frameworks = [makeFramework({ framework: 'rails', type: 'web' })];
      const result = getFrameworkSuppressions(frameworks);

      const sqlInj = result.find(s => s.cwePattern === 'CWE-89');
      expect(sqlInj!.reason).toContain('ActiveRecord');

      const csrf = result.find(s => s.cwePattern === 'CWE-352');
      expect(csrf!.reason).toContain('protect_from_forgery');

      const xss = result.find(s => s.cwePattern === 'CWE-79');
      expect(xss!.reason).toContain('ERB templates');
    });

    it('handles frameworks with name field instead of framework field', () => {
      // The code reads (f.name || f.framework).toLowerCase()
      const frameworks = [makeFramework({ framework: 'something', name: 'django', type: 'web' })];
      const result = getFrameworkSuppressions(frameworks);

      const djangoRules = result.filter(s => s.framework === 'django');
      expect(djangoRules.length).toBe(3);
    });

    it('handles case-insensitive framework matching', () => {
      const frameworks = [makeFramework({ framework: 'Django', type: 'web' })];
      const result = getFrameworkSuppressions(frameworks);

      const djangoRules = result.filter(s => s.framework === 'django');
      expect(djangoRules.length).toBe(3);
    });
  });

  describe('applyFrameworkSuppressions', () => {
    it('returns 0 when suppressions array is empty', async () => {
      const result = await applyFrameworkSuppressions('scan-1', 'proj-1', []);
      expect(result).toBe(0);
      expect(mockExecute).not.toHaveBeenCalled();
    });

    it('executes UPDATE query for each suppression rule', async () => {
      mockExecute.mockResolvedValue({ rows: [{ id: 'f-1' }, { id: 'f-2' }] });

      const suppressions: SuppressionMatch[] = [{
        framework: 'django',
        cwePattern: 'CWE-89',
        titlePattern: /sql.?injection/i,
        reason: 'Django ORM uses parameterized queries',
      }];

      const result = await applyFrameworkSuppressions('scan-1', 'proj-1', suppressions);

      expect(result).toBe(2);
      expect(mockExecute).toHaveBeenCalledTimes(1);
    });

    it('skips rules with no CWE, title, or rule pattern', async () => {
      const suppressions: SuppressionMatch[] = [{
        framework: 'custom',
        reason: 'No patterns defined',
        // No cwePattern, titlePattern, or rulePattern
      }];

      const result = await applyFrameworkSuppressions('scan-1', 'proj-1', suppressions);

      expect(result).toBe(0);
      expect(mockExecute).not.toHaveBeenCalled();
    });

    it('accumulates total suppressed across multiple rules', async () => {
      mockExecute
        .mockResolvedValueOnce({ rows: [{ id: 'f-1' }] })
        .mockResolvedValueOnce({ rows: [{ id: 'f-2' }, { id: 'f-3' }] });

      const suppressions: SuppressionMatch[] = [
        {
          framework: 'django',
          cwePattern: 'CWE-89',
          reason: 'Parameterized queries',
        },
        {
          framework: 'django',
          cwePattern: 'CWE-352',
          reason: 'Built-in CSRF',
        },
      ];

      const result = await applyFrameworkSuppressions('scan-1', 'proj-1', suppressions);

      expect(result).toBe(3);
      expect(mockExecute).toHaveBeenCalledTimes(2);
    });

    it('returns 0 when no findings match the suppression rules', async () => {
      mockExecute.mockResolvedValue({ rows: [] });

      const suppressions: SuppressionMatch[] = [{
        framework: 'react',
        cwePattern: 'CWE-79',
        titlePattern: /xss/i,
        reason: 'React auto-escapes',
      }];

      const result = await applyFrameworkSuppressions('scan-1', 'proj-1', suppressions);

      expect(result).toBe(0);
    });
  });
});
