import { describe, it, expect, vi } from 'vitest';
import {
  calculateQualityScore,
  calculateTrend,
  getScoreColor,
  getQualityBadge,
} from './quality-score.js';

// Mock the logger to avoid console output during tests
vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

describe('Quality Score Calculation', () => {
  describe('calculateQualityScore', () => {
    it('returns perfect score of 1000 with no findings', () => {
      const findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
      const result = calculateQualityScore(findings);

      expect(result.score).toBe(1000);
      expect(result.qualityLevel).toBe('excellent');
      expect(result.breakdown.baseScore).toBe(1000);
    });

    it('penalizes critical findings heavily', () => {
      const findings = { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1 };
      const result = calculateQualityScore(findings);

      // 1 critical: penalty = 200*sqrt(1) = 200, score = 800, ceiling caps at 600
      expect(result.breakdown.criticalPenalty).toBe(200);
      expect(result.score).toBe(600);
      expect(result.qualityLevel).toBe('moderate');
    });

    it('penalizes high findings moderately', () => {
      const findings = { critical: 0, high: 2, medium: 0, low: 0, info: 0, total: 2 };
      const result = calculateQualityScore(findings);

      // 2 high: penalty = round(60*sqrt(2)) = 85, score = 915, ceiling caps at 800
      expect(result.breakdown.highPenalty).toBe(85);
      expect(result.score).toBe(800);
      expect(result.qualityLevel).toBe('good');
    });

    it('penalizes medium findings lightly', () => {
      const findings = { critical: 0, high: 0, medium: 3, low: 0, info: 0, total: 3 };
      const result = calculateQualityScore(findings);

      expect(result.score).toBeLessThan(1000);
      expect(result.score).toBeGreaterThan(950);
      expect(result.breakdown.mediumPenalty).toBeGreaterThan(0);
    });

    it('penalizes low findings minimally', () => {
      const findings = { critical: 0, high: 0, medium: 0, low: 4, info: 0, total: 4 };
      const result = calculateQualityScore(findings);

      expect(result.score).toBeLessThan(1000);
      expect(result.score).toBeGreaterThan(980);
      expect(result.breakdown.lowPenalty).toBeGreaterThan(0);
    });

    it('info findings apply minimal penalty', () => {
      const findings = { critical: 0, high: 0, medium: 0, low: 0, info: 100, total: 100 };
      const result = calculateQualityScore(findings);

      // info weight=1, cap=20: penalty = min(1*sqrt(100), 20) = min(10, 20) = 10
      expect(result.score).toBe(990);
      expect(result.qualityLevel).toBe('excellent');
    });

    it('applies diminishing returns - doubling findings does not double penalty', () => {
      // Use medium findings (no severity ceiling) to test pure sqrt scaling
      const small = calculateQualityScore({ critical: 0, high: 0, medium: 5, low: 0, info: 0, total: 5 });
      const large = calculateQualityScore({ critical: 0, high: 0, medium: 10, low: 0, info: 0, total: 10 });

      const smallPenalty = small.breakdown.mediumPenalty;  // round(18*sqrt(5))  = 40
      const largePenalty = large.breakdown.mediumPenalty;  // round(18*sqrt(10)) = 57

      // Doubling count should less than double the penalty (diminishing returns)
      expect(largePenalty).toBeLessThan(smallPenalty * 2);
      expect(largePenalty).toBeGreaterThan(smallPenalty);
    });

    it('caps critical penalty at 450', () => {
      const findings = { critical: 100, high: 0, medium: 0, low: 0, info: 0, total: 100 };
      const result = calculateQualityScore(findings);

      // 100 critical: round(200*10) = 2000, capped at 450. Score = 550, ceiling = 600 → 550
      expect(result.breakdown.criticalPenalty).toBe(450);
      expect(result.score).toBe(550);
    });

    it('caps high penalty at 300', () => {
      const findings = { critical: 0, high: 500, medium: 0, low: 0, info: 0, total: 500 };
      const result = calculateQualityScore(findings);

      // 500 high: round(60*sqrt(500)) = 1342, capped at 300. Score = 700, ceiling = 800 → 700
      expect(result.breakdown.highPenalty).toBe(300);
      expect(result.score).toBe(700);
    });

    it('caps medium penalty at 250', () => {
      const findings = { critical: 0, high: 0, medium: 500, low: 0, info: 0, total: 500 };
      const result = calculateQualityScore(findings);

      // 500 medium: round(18*sqrt(500)) = 402, capped at 250. Score = 750
      expect(result.breakdown.mediumPenalty).toBe(250);
      expect(result.score).toBe(750);
    });

    it('caps low penalty at 150', () => {
      const findings = { critical: 0, high: 0, medium: 0, low: 5000, info: 0, total: 5000 };
      const result = calculateQualityScore(findings);

      // 5000 low: round(4*sqrt(5000)) = 283, capped at 150. Score = 850
      expect(result.breakdown.lowPenalty).toBe(150);
      expect(result.score).toBe(850);
    });

    it('worst case floors at 0', () => {
      const findings = { critical: 100, high: 500, medium: 500, low: 5000, info: 0, total: 6100 };
      const result = calculateQualityScore(findings);

      // All caps hit: 450+300+250+150 = 1150 penalty, score = max(0, 1000-1150) = 0
      expect(result.score).toBe(0);
      expect(result.qualityLevel).toBe('critical');
    });

    it('never returns score below 0', () => {
      const findings = { critical: 5, high: 10, medium: 20, low: 30, info: 0, total: 65 };
      const result = calculateQualityScore(findings);

      expect(result.score).toBeGreaterThanOrEqual(0);
    });

    it('real-world project with many findings scores at floor', () => {
      // PPT2Vid-like: 9 critical, 65 high, 99 medium, 857 low
      // Penalties: crit=min(round(200*3),450)=450, high=min(round(60*8.06),300)=300,
      //   med=round(18*9.95)=179, low=round(4*29.27)=117
      // Total=1046, score=max(0,1000-1046)=0
      const findings = { critical: 9, high: 65, medium: 99, low: 857, info: 0, total: 1030 };
      const result = calculateQualityScore(findings);

      expect(result.score).toBe(0);
      expect(result.qualityLevel).toBe('critical');
    });

    describe('quality level thresholds', () => {
      it('returns "excellent" for scores >= 900', () => {
        const findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
        expect(calculateQualityScore(findings).qualityLevel).toBe('excellent');
      });

      it('returns "good" for scores >= 750 and < 900', () => {
        // 50 medium: penalty = round(18*sqrt(50)) = 127, score = 873 → "good"
        const findings = { critical: 0, high: 0, medium: 50, low: 0, info: 0, total: 50 };
        expect(calculateQualityScore(findings).qualityLevel).toBe('good');
      });

      it('returns "moderate" for scores >= 500 and < 750', () => {
        // 50 critical: penalty capped at 450, score = 550, ceiling = 600 → 550 → "moderate"
        const findings = { critical: 50, high: 0, medium: 0, low: 0, info: 0, total: 50 };
        expect(calculateQualityScore(findings).qualityLevel).toBe('moderate');
      });

      it('returns "poor" for scores >= 250 and < 500', () => {
        // crit cap 450 + high cap 300 = 750 penalty, score = 250 → "poor"
        const findings = { critical: 50, high: 100, medium: 0, low: 0, info: 0, total: 150 };
        expect(calculateQualityScore(findings).qualityLevel).toBe('poor');
      });

      it('returns "critical" for scores < 250', () => {
        // All caps: 450+300+250+150 = 1150 penalty, score = 0 → "critical"
        const findings = { critical: 500, high: 2000, medium: 50000, low: 10000, info: 0, total: 62500 };
        expect(calculateQualityScore(findings).qualityLevel).toBe('critical');
      });
    });
  });

  describe('calculateTrend', () => {
    it('returns "stable" when no previous scores', () => {
      expect(calculateTrend(800, [])).toBe('stable');
    });

    it('returns "up" when current score is significantly higher', () => {
      expect(calculateTrend(850, [800, 810, 820])).toBe('up');
    });

    it('returns "down" when current score is significantly lower', () => {
      expect(calculateTrend(750, [800, 810, 820])).toBe('down');
    });

    it('returns "stable" when difference is within threshold', () => {
      expect(calculateTrend(815, [800, 810, 820])).toBe('stable');
    });

    it('calculates average correctly with single previous score', () => {
      expect(calculateTrend(850, [800])).toBe('up');
      expect(calculateTrend(750, [800])).toBe('down');
    });
  });

  describe('getScoreColor', () => {
    it('returns green for excellent scores (>= 900)', () => {
      expect(getScoreColor(1000)).toBe('#22c55e');
      expect(getScoreColor(900)).toBe('#22c55e');
    });

    it('returns lime for good scores (>= 750)', () => {
      expect(getScoreColor(899)).toBe('#84cc16');
      expect(getScoreColor(750)).toBe('#84cc16');
    });

    it('returns yellow for moderate scores (>= 500)', () => {
      expect(getScoreColor(749)).toBe('#eab308');
      expect(getScoreColor(500)).toBe('#eab308');
    });

    it('returns orange for poor scores (>= 250)', () => {
      expect(getScoreColor(499)).toBe('#f97316');
      expect(getScoreColor(250)).toBe('#f97316');
    });

    it('returns red for critical scores (< 250)', () => {
      expect(getScoreColor(249)).toBe('#ef4444');
      expect(getScoreColor(0)).toBe('#ef4444');
    });
  });

  describe('getQualityBadge', () => {
    it('returns correct badge for excellent', () => {
      const badge = getQualityBadge('excellent');
      expect(badge.text).toBe('Excellent');
      expect(badge.color).toBe('#22c55e');
    });

    it('returns correct badge for good', () => {
      const badge = getQualityBadge('good');
      expect(badge.text).toBe('Good');
      expect(badge.color).toBe('#84cc16');
    });

    it('returns correct badge for moderate', () => {
      const badge = getQualityBadge('moderate');
      expect(badge.text).toBe('Moderate');
      expect(badge.color).toBe('#eab308');
    });

    it('returns correct badge for poor', () => {
      const badge = getQualityBadge('poor');
      expect(badge.text).toBe('Poor');
      expect(badge.color).toBe('#f97316');
    });

    it('returns correct badge for critical', () => {
      const badge = getQualityBadge('critical');
      expect(badge.text).toBe('Critical');
      expect(badge.color).toBe('#ef4444');
    });
  });

  describe('Quality Bonuses', () => {
    const noFindings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    const allBonuses = {
      hasSbom: true,
      hasSignedAttestation: true,
      cleanSecrets: true,
      cleanIac: true,
      hasSupplyChainVerification: true,
      multipleProfilesUsed: true,
      highMutationScore: true,
      cleanPackageValidation: true,
      cleanLicenseSnippets: true,
      noConfirmedExploits: true,
      allTestsPassing: true,
      highTestCoverage: true,
    };

    describe('individual bonus point values', () => {
      it('hasSbom adds 25 points', () => {
        const result = calculateQualityScore(noFindings, { hasSbom: true });
        expect(result.breakdown.bonusTotal).toBe(25);
        expect(result.breakdown.bonusDetails['SBOM Generated']).toBe(25);
      });

      it('hasSignedAttestation adds 30 points', () => {
        const result = calculateQualityScore(noFindings, { hasSignedAttestation: true });
        expect(result.breakdown.bonusTotal).toBe(30);
        expect(result.breakdown.bonusDetails['Signed Attestation']).toBe(30);
      });

      it('cleanSecrets adds 20 points', () => {
        const result = calculateQualityScore(noFindings, { cleanSecrets: true });
        expect(result.breakdown.bonusTotal).toBe(20);
        expect(result.breakdown.bonusDetails['Clean Secrets Scan']).toBe(20);
      });

      it('cleanIac adds 15 points', () => {
        const result = calculateQualityScore(noFindings, { cleanIac: true });
        expect(result.breakdown.bonusTotal).toBe(15);
        expect(result.breakdown.bonusDetails['Clean IaC Scan']).toBe(15);
      });

      it('hasSupplyChainVerification adds 25 points', () => {
        const result = calculateQualityScore(noFindings, { hasSupplyChainVerification: true });
        expect(result.breakdown.bonusTotal).toBe(25);
        expect(result.breakdown.bonusDetails['Supply Chain Verified']).toBe(25);
      });

      it('multipleProfilesUsed adds 10 points', () => {
        const result = calculateQualityScore(noFindings, { multipleProfilesUsed: true });
        expect(result.breakdown.bonusTotal).toBe(10);
        expect(result.breakdown.bonusDetails['Defense in Depth']).toBe(10);
      });

      it('highMutationScore adds 30 points', () => {
        const result = calculateQualityScore(noFindings, { highMutationScore: true });
        expect(result.breakdown.bonusTotal).toBe(30);
        expect(result.breakdown.bonusDetails['Strong Mutation Score']).toBe(30);
      });

      it('cleanPackageValidation adds 25 points', () => {
        const result = calculateQualityScore(noFindings, { cleanPackageValidation: true });
        expect(result.breakdown.bonusTotal).toBe(25);
        expect(result.breakdown.bonusDetails['All Packages Verified']).toBe(25);
      });

      it('cleanLicenseSnippets adds 20 points', () => {
        const result = calculateQualityScore(noFindings, { cleanLicenseSnippets: true });
        expect(result.breakdown.bonusTotal).toBe(20);
        expect(result.breakdown.bonusDetails['Clean License Scan']).toBe(20);
      });

      it('noConfirmedExploits adds 25 points', () => {
        const result = calculateQualityScore(noFindings, { noConfirmedExploits: true });
        expect(result.breakdown.bonusTotal).toBe(25);
        expect(result.breakdown.bonusDetails['No Confirmed Exploits']).toBe(25);
      });

      it('allTestsPassing adds 30 points', () => {
        const result = calculateQualityScore(noFindings, { allTestsPassing: true });
        expect(result.breakdown.bonusTotal).toBe(30);
        expect(result.breakdown.bonusDetails['All Tests Passing']).toBe(30);
      });

      it('highTestCoverage adds 25 points', () => {
        const result = calculateQualityScore(noFindings, { highTestCoverage: true });
        expect(result.breakdown.bonusTotal).toBe(25);
        expect(result.breakdown.bonusDetails['High Test Coverage']).toBe(25);
      });
    });

    it('all bonuses combined add 280 points', () => {
      const result = calculateQualityScore(noFindings, allBonuses);
      expect(result.breakdown.bonusTotal).toBe(280);
    });

    it('bonuses cannot push score above 1000', () => {
      // 0 findings + all bonuses = 1000 + 280 = 1280, clamped to 1000
      const result = calculateQualityScore(noFindings, allBonuses);
      expect(result.score).toBe(1000);
      expect(result.qualityLevel).toBe('excellent');
    });

    it('bonuses offset penalties from findings', () => {
      // 3 medium findings: penalty = round(18*sqrt(3)) = round(31.18) = 31
      // With cleanSecrets (+20): score = 1000 - 31 + 20 = 989
      const findings = { critical: 0, high: 0, medium: 3, low: 0, info: 0, total: 3 };
      const withoutBonus = calculateQualityScore(findings);
      const withBonus = calculateQualityScore(findings, { cleanSecrets: true });

      expect(withBonus.score).toBe(withoutBonus.score + 20);
      expect(withBonus.score).toBe(989);
      expect(withBonus.breakdown.bonusTotal).toBe(20);
    });

    it('bonuses do not override severity ceilings', () => {
      // 1 critical: penalty = 200, score = 1000 - 200 + 280 = 1080 → clamped 1000 → ceiling 600
      const findings = { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1 };
      const result = calculateQualityScore(findings, allBonuses);

      expect(result.score).toBe(600);
      expect(result.qualityLevel).toBe('moderate');
      expect(result.breakdown.bonusTotal).toBe(280);
    });

    it('empty bonuses object adds 0 points', () => {
      const result = calculateQualityScore(noFindings, {});
      expect(result.breakdown.bonusTotal).toBe(0);
      expect(result.score).toBe(1000);
      expect(Object.keys(result.breakdown.bonusDetails)).toHaveLength(0);
    });

    it('undefined bonuses parameter adds 0 points', () => {
      const result = calculateQualityScore(noFindings);
      expect(result.breakdown.bonusTotal).toBe(0);
      expect(result.score).toBe(1000);
      expect(Object.keys(result.breakdown.bonusDetails)).toHaveLength(0);
    });

    it('false bonus values add 0 points', () => {
      const result = calculateQualityScore(noFindings, {
        hasSbom: false,
        hasSignedAttestation: false,
        cleanSecrets: false,
        cleanIac: false,
        hasSupplyChainVerification: false,
        multipleProfilesUsed: false,
        highMutationScore: false,
        cleanPackageValidation: false,
        cleanLicenseSnippets: false,
        noConfirmedExploits: false,
        allTestsPassing: false,
        highTestCoverage: false,
      });
      expect(result.breakdown.bonusTotal).toBe(0);
      expect(result.score).toBe(1000);
      expect(Object.keys(result.breakdown.bonusDetails)).toHaveLength(0);
    });
  });

  describe('Scanner coverage and skip reasons', () => {
    it('skipped scanners with no findings do not penalize score', () => {
      // A scan where all scanners skip (no findings) should still get 1000
      const findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
      const result = calculateQualityScore(findings);
      expect(result.score).toBe(1000);
      expect(result.qualityLevel).toBe('excellent');
    });

    it('quality score only considers actual findings, not scanner count', () => {
      // Even if only 2 of 30 scanners ran (rest skipped), the score is based on findings
      const findings = { critical: 0, high: 0, medium: 2, low: 1, info: 5, total: 8 };
      const resultFew = calculateQualityScore(findings);

      // Same findings from a full run — score should be identical
      const resultMany = calculateQualityScore(findings, {
        hasSbom: true,
        cleanSecrets: true,
      });

      // Base penalty is the same; only bonuses differ
      expect(resultFew.breakdown.mediumPenalty).toBe(resultMany.breakdown.mediumPenalty);
      expect(resultFew.breakdown.lowPenalty).toBe(resultMany.breakdown.lowPenalty);
    });

    it('bonuses are independent of scanner skip reasons', () => {
      // A scan with many skipped scanners can still earn bonuses for the scanners that ran
      const findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
      const result = calculateQualityScore(findings, {
        hasSbom: true,
        cleanSecrets: true,
        cleanIac: true,
        noConfirmedExploits: true,
      });

      // 25 + 20 + 15 + 25 = 85
      expect(result.breakdown.bonusTotal).toBe(85);
      // Score capped at 1000 (1000 + 85 = 1085, capped)
      expect(result.score).toBe(1000);
    });

    it('score reflects only reported findings regardless of how many scanners skipped', () => {
      // Simulate: 5 scanners ran, 25 skipped. Only actual findings matter.
      const findings = { critical: 0, high: 1, medium: 3, low: 5, info: 10, total: 19 };
      const result = calculateQualityScore(findings);

      // high: 60*sqrt(1) = 60, medium: 18*sqrt(3) = 31, low: 4*sqrt(5) = 9
      expect(result.breakdown.highPenalty).toBe(60);
      expect(result.breakdown.mediumPenalty).toBe(31);
      expect(result.breakdown.lowPenalty).toBe(9);

      // Score: 1000 - 60 - 31 - 9 = 900, but high ceiling = 800
      expect(result.score).toBe(800);
      expect(result.qualityLevel).toBe('good');
    });
  });

  // REQ-LLM-015: llm-vuln-scan findings participate in the score exactly like any
  // other scanner's. calculateQualityScore is intentionally scanner-agnostic — it
  // only consumes severity counts + bonuses, so there is no place to special-case
  // a scanner name. This test pins that contract: identical severity profiles yield
  // identical scores no matter which scanner conceptually produced them.
  describe('REQ-LLM-015: no special-casing of llm-vuln-scan findings', () => {
    // REQ-LLM-015 is structurally satisfied: calculateQualityScore is
    // scanner-blind BY CONSTRUCTION — its only inputs are severity counts and the
    // bonus flags. There is no scanner-name parameter, so there is no place to
    // special-case llm-vuln-scan. We pin that contract (not a vacuous A===A) by
    // asserting the function's arity/shape and one concrete score.
    it('scoring is scanner-blind by construction: signature takes counts + optional bonuses only', () => {
      // The signature is exactly (findings, bonuses?) — two parameters, no third
      // "scanner" parameter. fn.length counts formal params up to (but not
      // including) the first one with a `=` default; `bonuses?` has no default, so
      // it still counts → arity is 2. The point: there is no place to special-case
      // a scanner name because no scanner argument exists.
      expect(calculateQualityScore.length).toBe(2);

      // Reflection on a sample call: passing a bogus extra "scanner" argument
      // cannot change the result, because the function never reads it.
      const counts = { critical: 1, high: 2, medium: 3, low: 4, info: 5, total: 15 };
      const baseline = calculateQualityScore({ ...counts });
      const withIgnoredExtraArg = (
        calculateQualityScore as unknown as (c: typeof counts, b?: unknown, scanner?: string) => typeof baseline
      )({ ...counts }, undefined, 'llm-vuln-scan');
      expect(withIgnoredExtraArg.score).toBe(baseline.score);
      expect(withIgnoredExtraArg.breakdown).toEqual(baseline.breakdown);
    });

    it('a single high finding scores 800 (high ceiling, no bonus) — same as any scanner', () => {
      const single = { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 };
      const result = calculateQualityScore({ ...single });
      expect(result.score).toBe(800); // concrete contract anchor
      expect(result.qualityLevel).toBe('good');
    });
  });
});
