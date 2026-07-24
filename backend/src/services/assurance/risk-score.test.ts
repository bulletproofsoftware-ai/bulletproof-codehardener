import { describe, it, expect, vi } from 'vitest';
import {
  calculateQualityScore as calculateRiskScore,
  calculateTrend,
  getScoreColor,
  getQualityBadge as getRiskBadge,
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

describe('Risk Score Calculation', () => {
  describe('calculateRiskScore', () => {
    it('returns perfect score of 1000 with no findings', () => {
      const findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
      const result = calculateRiskScore(findings);

      expect(result.score).toBe(1000);
      expect(result.qualityLevel).toBe('excellent');
      expect(result.breakdown.baseScore).toBe(1000);
    });

    it('penalizes critical findings heavily', () => {
      const findings = { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1 };
      const result = calculateRiskScore(findings);

      // 1 critical: penalty = 200*sqrt(1) = 200, ceiling caps score at 600
      expect(result.score).toBeLessThanOrEqual(600);
      expect(result.breakdown.criticalPenalty).toBe(200);
    });

    it('penalizes high findings moderately', () => {
      const findings = { critical: 0, high: 2, medium: 0, low: 0, info: 0, total: 2 };
      const result = calculateRiskScore(findings);

      // 2 highs: penalty = 60*sqrt(2) = 85, ceiling caps score at 800
      expect(result.score).toBeLessThanOrEqual(800);
      expect(result.breakdown.highPenalty).toBeGreaterThan(0);
    });

    it('penalizes medium findings lightly', () => {
      const findings = { critical: 0, high: 0, medium: 3, low: 0, info: 0, total: 3 };
      const result = calculateRiskScore(findings);

      expect(result.score).toBeLessThan(1000);
      expect(result.score).toBeGreaterThan(950);
      expect(result.breakdown.mediumPenalty).toBeGreaterThan(0);
    });

    it('penalizes low findings minimally', () => {
      const findings = { critical: 0, high: 0, medium: 0, low: 4, info: 0, total: 4 };
      const result = calculateRiskScore(findings);

      expect(result.score).toBeLessThan(1000);
      expect(result.score).toBeGreaterThan(980);
      expect(result.breakdown.lowPenalty).toBeGreaterThan(0);
    });

    it('info findings apply minimal penalty', () => {
      const findings = { critical: 0, high: 0, medium: 0, low: 0, info: 100, total: 100 };
      const result = calculateRiskScore(findings);

      // info weight=1, cap=20: penalty = min(1*sqrt(100), 20) = min(10, 20) = 10
      expect(result.score).toBe(990);
      expect(result.qualityLevel).toBe('excellent');
    });

    it('applies diminishing returns - doubling findings does not double penalty', () => {
      const small = calculateRiskScore({ critical: 0, high: 0, medium: 5, low: 0, info: 0, total: 5 });
      const large = calculateRiskScore({ critical: 0, high: 0, medium: 10, low: 0, info: 0, total: 10 });

      const smallPenalty = small.breakdown.mediumPenalty;
      const largePenalty = large.breakdown.mediumPenalty;

      // Doubling count should less than double the penalty (diminishing returns via sqrt)
      expect(largePenalty).toBeLessThan(smallPenalty * 2);
      expect(largePenalty).toBeGreaterThan(smallPenalty);
    });

    it('caps critical penalty at 450', () => {
      const findings = { critical: 100, high: 0, medium: 0, low: 0, info: 0, total: 100 };
      const result = calculateRiskScore(findings);

      expect(result.breakdown.criticalPenalty).toBe(450);
      // Ceiling caps score at 600 (any critical), penalty 450 → 550, but ceiling wins
      expect(result.score).toBeLessThanOrEqual(600);
    });

    it('caps high penalty at 300', () => {
      const findings = { critical: 0, high: 500, medium: 0, low: 0, info: 0, total: 500 };
      const result = calculateRiskScore(findings);

      expect(result.breakdown.highPenalty).toBeLessThanOrEqual(300);
      expect(result.breakdown.highPenalty).toBeGreaterThan(150);
      // Ceiling caps score at 800 (any highs)
      expect(result.score).toBeLessThanOrEqual(800);
    });

    it('caps medium penalty at 250', () => {
      const findings = { critical: 0, high: 0, medium: 500, low: 0, info: 0, total: 500 };
      const result = calculateRiskScore(findings);

      expect(result.breakdown.mediumPenalty).toBeLessThanOrEqual(250);
      expect(result.breakdown.mediumPenalty).toBeGreaterThan(50);
      expect(result.score).toBeGreaterThanOrEqual(750);
    });

    it('caps low penalty at 150', () => {
      const findings = { critical: 0, high: 0, medium: 0, low: 1000, info: 0, total: 1000 };
      const result = calculateRiskScore(findings);

      expect(result.breakdown.lowPenalty).toBeLessThanOrEqual(150);
      expect(result.breakdown.lowPenalty).toBeGreaterThan(10);
      expect(result.score).toBeGreaterThan(850);
    });

    it('worst case hits floor at 0', () => {
      const findings = { critical: 100, high: 500, medium: 500, low: 1000, info: 0, total: 2100 };
      const result = calculateRiskScore(findings);

      // Total caps: 450+300+250+150 = 1150 > 1000, floor at 0
      // Plus critical ceiling caps at 600, so score is 0
      expect(result.score).toBe(0);
    });

    it('never returns score below 0', () => {
      const findings = { critical: 5, high: 10, medium: 20, low: 30, info: 0, total: 65 };
      const result = calculateRiskScore(findings);

      expect(result.score).toBeGreaterThanOrEqual(0);
    });

    it('real-world project with mixed findings scores reasonably', () => {
      // PPT2Vid-like: 9 critical, 65 high, 99 medium, 857 low
      const findings = { critical: 9, high: 65, medium: 99, low: 857, info: 0, total: 1030 };
      const result = calculateRiskScore(findings);

      // Critical ceiling caps at 600, massive penalties push to 0
      expect(result.score).toBe(0);
      expect(result.qualityLevel).toBe('critical');
    });

    describe('risk level thresholds', () => {
      it('returns "excellent" for scores >= 900', () => {
        const findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
        expect(calculateRiskScore(findings).qualityLevel).toBe('excellent');
      });

      it('returns "good" for scores >= 750 and < 900', () => {
        // Need score between 750-899. high ceiling = 800. Use medium findings only.
        // medium 25: penalty = 18*sqrt(25) = 90, score = 910... too high
        // medium 50: penalty = 18*sqrt(50) = 127, score = 873
        const findings = { critical: 0, high: 0, medium: 50, low: 0, info: 0, total: 50 };
        expect(calculateRiskScore(findings).qualityLevel).toBe('good');
      });

      it('returns "moderate" for scores >= 500 and < 750', () => {
        // Critical cap (350) + high cap (250) = 600 -> score 400... too low
        // Just critical cap = 350 -> score 650
        const findings = { critical: 50, high: 0, medium: 0, low: 0, info: 0, total: 50 };
        expect(calculateRiskScore(findings).qualityLevel).toBe('moderate');
      });

      it('returns "poor" for scores >= 250 and < 500', () => {
        // Critical cap (350) + high cap (250) = 600 -> score 400
        const findings = { critical: 50, high: 100, medium: 0, low: 0, info: 0, total: 150 };
        expect(calculateRiskScore(findings).qualityLevel).toBe('poor');
      });

      it('returns "critical" for scores < 250', () => {
        // Extreme findings: need total penalty > 750 to push score below 250
        // Logarithmic scaling requires very high counts to hit caps
        const findings = { critical: 500, high: 2000, medium: 50000, low: 10000, info: 0, total: 62500 };
        // crit=350(cap), high=250(cap), med~142, low~23 -> total~765, score~235
        expect(calculateRiskScore(findings).qualityLevel).toBe('critical');
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

  describe('getRiskBadge', () => {
    it('returns correct badge for excellent', () => {
      const badge = getRiskBadge('excellent');
      expect(badge.text).toBe('Excellent');
      expect(badge.color).toBe('#22c55e');
    });

    it('returns correct badge for good', () => {
      const badge = getRiskBadge('good');
      expect(badge.text).toBe('Good');
      expect(badge.color).toBe('#84cc16');
    });

    it('returns correct badge for moderate', () => {
      const badge = getRiskBadge('moderate');
      expect(badge.text).toBe('Moderate');
      expect(badge.color).toBe('#eab308');
    });

    it('returns correct badge for poor', () => {
      const badge = getRiskBadge('poor');
      expect(badge.text).toBe('Poor');
      expect(badge.color).toBe('#f97316');
    });

    it('returns correct badge for critical', () => {
      const badge = getRiskBadge('critical');
      expect(badge.text).toBe('Critical');
      expect(badge.color).toBe('#ef4444');
    });
  });
});
