import { describe, it, expect } from 'vitest';
import { translateFinding, translateFindings } from './plain-language.js';
import type { Severity } from '../../types/index.js';

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Plain Language Translator', () => {
  describe('translateFinding', () => {
    it('translates SQL injection finding to plain language', () => {
      const result = translateFinding(
        'CWE-89: SQL Injection in user query',
        'Original technical description',
        'critical',
        'CWE-89',
        null,
        'semgrep',
      );

      expect(result.descriptionSimple).toContain('SQL Injection');
      expect(result.descriptionSimple).toContain('parameterized queries');
      expect(result.titleSimple).not.toMatch(/^CWE-89:/);
      expect(result.actionRequired).toContain('parameterized queries');
      expect(result.actionRequired).toContain('Immediately');
    });

    it('translates XSS finding to plain language', () => {
      const result = translateFinding(
        'Cross-Site Scripting in output',
        'Technical XSS description',
        'high',
        'CWE-79',
        null,
        'opengrep',
      );

      expect(result.descriptionSimple).toContain('Cross-Site Scripting');
      expect(result.descriptionSimple).toContain('malicious scripts');
      expect(result.actionRequired).toContain('Sanitize');
    });

    it('translates hardcoded secrets finding', () => {
      const result = translateFinding(
        'Hardcoded credential found',
        'API key embedded in source',
        'high',
        'CWE-798',
        null,
        'gitleaks',
      );

      expect(result.descriptionSimple).toContain('credentials');
      expect(result.descriptionSimple).toContain('embedded directly');
      expect(result.actionRequired).toContain('secret manager');
    });

    it('returns original description when no CWE translation available', () => {
      const originalDesc = 'Some custom finding description from an obscure scanner';
      const result = translateFinding(
        'Custom Finding',
        originalDesc,
        'medium',
        'CWE-99999', // Non-existent CWE
        null,
        'custom-scanner',
      );

      expect(result.descriptionSimple).toBe(originalDesc);
    });

    it('handles null CWE ID', () => {
      const result = translateFinding(
        'Missing header',
        'The X-Frame-Options header is not set',
        'low',
        null,
        null,
        'nuclei',
      );

      expect(result.descriptionSimple).toBe('The X-Frame-Options header is not set');
      expect(result.actionRequired).toContain('Review and fix');
    });

    it('handles undefined-like CWE ID (empty string)', () => {
      const result = translateFinding(
        'Some finding',
        'Some description',
        'info',
        '',
        null,
        'trivy',
      );

      // Empty string is falsy, so CWE lookup should not apply
      expect(result.descriptionSimple).toBe('Some description');
    });

    it('generates fix description for known CWEs', () => {
      const result = translateFinding(
        'Path traversal',
        'File path manipulation detected',
        'high',
        'CWE-22',
        null,
        'semgrep',
      );

      expect(result.actionRequired).toContain('path canonicalization');
    });

    it('handles findings with no description gracefully', () => {
      const result = translateFinding(
        'Vulnerability detected',
        '',
        'medium',
        null,
        null,
        'trivy',
      );

      expect(result.descriptionSimple).toBe('');
      expect(result.titleSimple).toBeTruthy();
      expect(result.riskExplanation).toBeTruthy();
      expect(result.actionRequired).toBeTruthy();
    });

    it('provides OWASP explanation when CWE is null but OWASP category exists', () => {
      const result = translateFinding(
        'Broken access control',
        'Original description',
        'high',
        null,
        'A01:2021-Broken Access Control',
        'zap',
      );

      expect(result.descriptionSimple).toContain('shouldn\'t be allowed');
    });

    it('CWE explanation takes precedence over OWASP when both present', () => {
      const result = translateFinding(
        'SQL Injection',
        'Original description',
        'critical',
        'CWE-89',
        'A03:2021-Injection',
        'semgrep',
      );

      // CWE-89 explanation should win over OWASP A03
      expect(result.descriptionSimple).toContain('SQL Injection');
      expect(result.descriptionSimple).toContain('parameterized queries');
    });

    it('maps severity to correct risk explanation', () => {
      const critical = translateFinding('Test', 'Desc', 'critical', null, null, 'test');
      expect(critical.riskExplanation).toContain('immediate and severe');

      const high = translateFinding('Test', 'Desc', 'high', null, null, 'test');
      expect(high.riskExplanation).toContain('serious');

      const medium = translateFinding('Test', 'Desc', 'medium', null, null, 'test');
      expect(medium.riskExplanation).toContain('moderate');

      const low = translateFinding('Test', 'Desc', 'low', null, null, 'test');
      expect(low.riskExplanation).toContain('minor');

      const info = translateFinding('Test', 'Desc', 'info', null, null, 'test');
      expect(info.riskExplanation).toContain('informational');
    });

    it('simplifies title by removing CVE/CWE prefixes', () => {
      const result = translateFinding(
        'CVE-2023-12345: Buffer overflow in libfoo',
        'Desc',
        'high',
        null,
        null,
        'trivy',
      );

      expect(result.titleSimple).not.toMatch(/^CVE-/);
      expect(result.titleSimple).toContain('Buffer overflow');
    });

    it('simplifies title by removing scanner prefixes', () => {
      const result = translateFinding(
        'trivy: outdated package detected',
        'Desc',
        'low',
        null,
        null,
        'trivy',
      );

      expect(result.titleSimple).not.toMatch(/^trivy/i);
    });

    it('adds scanner context for short titles', () => {
      const result = translateFinding(
        'weak-cipher',
        'Desc',
        'medium',
        null,
        null,
        'trivy',
      );

      // Short title (<20 chars) + known scanner → context prepended
      expect(result.titleSimple).toContain('Dependency issue');
    });
  });

  describe('translateFindings (batch)', () => {
    it('translates multiple findings in batch', () => {
      const findings = [
        { title: 'SQL Injection', description: 'Desc 1', severity: 'critical' as Severity, cweId: 'CWE-89', owaspCategory: null, scanner: 'semgrep' },
        { title: 'XSS', description: 'Desc 2', severity: 'high' as Severity, cweId: 'CWE-79', owaspCategory: null, scanner: 'opengrep' },
        { title: 'Info finding', description: 'Desc 3', severity: 'info' as Severity, cweId: null, owaspCategory: null, scanner: 'trivy' },
      ];

      const results = translateFindings(findings);

      expect(results).toHaveLength(3);
      expect(results[0].descriptionSimple).toContain('SQL Injection');
      expect(results[1].descriptionSimple).toContain('Cross-Site Scripting');
      expect(results[2].descriptionSimple).toBe('Desc 3');
    });

    it('returns empty array for empty input', () => {
      const results = translateFindings([]);
      expect(results).toEqual([]);
    });
  });
});
