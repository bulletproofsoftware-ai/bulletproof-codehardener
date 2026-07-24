import { createLogger } from '../../utils/logger.js';
import type { QualityLevel } from '../../types/index.js';

const logger = createLogger('quality-score');

interface FindingCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

interface QualityBonuses {
  /** SBOM was generated (syft ran successfully) */
  hasSbom?: boolean;
  /** Attestation was signed (Sigstore/Ed25519) */
  hasSignedAttestation?: boolean;
  /** Secrets detection ran with no findings */
  cleanSecrets?: boolean;
  /** IaC scanning ran with no findings */
  cleanIac?: boolean;
  /** Supply chain tools ran (cosign, in-toto) */
  hasSupplyChainVerification?: boolean;
  /** Multiple scan profiles used (defense in depth) */
  multipleProfilesUsed?: boolean;
  /** Mutation testing passed with score >= 70% */
  highMutationScore?: boolean;
  /** All packages verified to exist in registries */
  cleanPackageValidation?: boolean;
  /** No copyleft license snippets detected */
  cleanLicenseSnippets?: boolean;
  /** All exploitable findings are 'theoretical' or 'unlikely' */
  noConfirmedExploits?: boolean;
  /** All test suites pass (jest/pytest ran with 0 failures) */
  allTestsPassing?: boolean;
  /** Test coverage >= 80% across all test runners */
  highTestCoverage?: boolean;
}

interface QualityScoreResult {
  score: number;
  qualityLevel: QualityLevel;
  breakdown: {
    criticalPenalty: number;
    highPenalty: number;
    mediumPenalty: number;
    lowPenalty: number;
    infoPenalty: number;
    bonusTotal: number;
    bonusDetails: Record<string, number>;
    baseScore: number;
  };
}

// Square-root penalty scaling.
// Every additional finding adds penalty, but with diminishing marginal cost.
// Unlike logarithmic scaling (which flattened too aggressively — 125 mediums
// cost only 64pts), sqrt keeps penalties meaningful at volume:
//   penalty = weight * sqrt(count), capped at cap
//
// Severity ceilings enforce hard limits: any critical finding caps the score
// at 600 ("Moderate"), any high finding caps at 800 ("Good"). You cannot have
// an "Excellent" score with open high/critical findings.
//
// Reference points (penalty only, before caps):
//   1 critical → 200pts    5 critical → 447pts
//   1 high     → 60pts     15 high    → 232pts
//   10 medium  → 57pts     125 medium → 201pts
//   50 low     → 28pts     425 low    → 82pts

const SEVERITY_CONFIG = {
  critical: { weight: 200, cap: 450 },
  high:     { weight: 60,  cap: 300 },
  medium:   { weight: 18,  cap: 250 },
  low:      { weight: 4,   cap: 150 },
  info:     { weight: 1,   cap: 20  },
};

// Hard ceilings: presence of ANY findings at this severity caps the max score
const SEVERITY_CEILINGS: Partial<Record<string, number>> = {
  critical: 600,  // Any criticals → max "Moderate"
  high:     800,  // Any highs → max "Good"
};

function sqrtPenalty(count: number, weight: number, cap: number): number {
  if (count === 0 || weight === 0) return 0;
  const raw = weight * Math.sqrt(count);
  return Math.min(Math.round(raw), cap);
}

// Bonus points for positive quality practices.
// These reward proactive measures and can partially offset penalties,
// but cannot push score above 1000.
const BONUS_CONFIG: Record<keyof QualityBonuses, { points: number; label: string }> = {
  hasSbom:                     { points: 25, label: 'SBOM Generated' },
  hasSignedAttestation:        { points: 30, label: 'Signed Attestation' },
  cleanSecrets:                { points: 20, label: 'Clean Secrets Scan' },
  cleanIac:                    { points: 15, label: 'Clean IaC Scan' },
  hasSupplyChainVerification:  { points: 25, label: 'Supply Chain Verified' },
  multipleProfilesUsed:        { points: 10, label: 'Defense in Depth' },
  highMutationScore:           { points: 30, label: 'Strong Mutation Score' },
  cleanPackageValidation:      { points: 25, label: 'All Packages Verified' },
  cleanLicenseSnippets:        { points: 20, label: 'Clean License Scan' },
  noConfirmedExploits:         { points: 25, label: 'No Confirmed Exploits' },
  allTestsPassing:             { points: 30, label: 'All Tests Passing' },
  highTestCoverage:            { points: 25, label: 'High Test Coverage' },
};

export function calculateQualityScore(
  findings: FindingCounts,
  bonuses?: QualityBonuses
): QualityScoreResult {
  const baseScore = 1000;

  const criticalPenalty = sqrtPenalty(
    findings.critical, SEVERITY_CONFIG.critical.weight, SEVERITY_CONFIG.critical.cap
  );
  const highPenalty = sqrtPenalty(
    findings.high, SEVERITY_CONFIG.high.weight, SEVERITY_CONFIG.high.cap
  );
  const mediumPenalty = sqrtPenalty(
    findings.medium, SEVERITY_CONFIG.medium.weight, SEVERITY_CONFIG.medium.cap
  );
  const lowPenalty = sqrtPenalty(
    findings.low, SEVERITY_CONFIG.low.weight, SEVERITY_CONFIG.low.cap
  );
  const infoPenalty = sqrtPenalty(
    findings.info, SEVERITY_CONFIG.info.weight, SEVERITY_CONFIG.info.cap
  );

  // Calculate bonuses
  const bonusDetails: Record<string, number> = {};
  let bonusTotal = 0;
  if (bonuses) {
    for (const [key, value] of Object.entries(bonuses)) {
      if (value && BONUS_CONFIG[key as keyof QualityBonuses]) {
        const config = BONUS_CONFIG[key as keyof QualityBonuses];
        bonusDetails[config.label] = config.points;
        bonusTotal += config.points;
      }
    }
  }

  // Calculate final score: base - penalties + bonuses (capped at 1000, floor at 0)
  const totalPenalty = criticalPenalty + highPenalty + mediumPenalty + lowPenalty + infoPenalty;
  let score = Math.max(0, Math.min(1000, baseScore - totalPenalty + bonusTotal));

  // Apply severity ceilings: critical/high findings enforce hard score caps
  const severityKeys = ['critical', 'high', 'medium', 'low'] as const;
  for (const sev of severityKeys) {
    if (findings[sev] > 0 && SEVERITY_CEILINGS[sev] !== undefined) {
      score = Math.min(score, SEVERITY_CEILINGS[sev]!);
    }
  }

  // Determine quality level
  let qualityLevel: QualityLevel;
  if (score >= 900) {
    qualityLevel = 'excellent';
  } else if (score >= 750) {
    qualityLevel = 'good';
  } else if (score >= 500) {
    qualityLevel = 'moderate';
  } else if (score >= 250) {
    qualityLevel = 'poor';
  } else {
    qualityLevel = 'critical';
  }

  logger.debug(
    { score, qualityLevel, findings, totalPenalty, bonusTotal },
    'Quality score calculated'
  );

  return {
    score,
    qualityLevel,
    breakdown: {
      criticalPenalty,
      highPenalty,
      mediumPenalty,
      lowPenalty,
      infoPenalty,
      bonusTotal,
      bonusDetails,
      baseScore,
    },
  };
}

// Calculate score trend from historical data
export function calculateTrend(
  currentScore: number,
  previousScores: number[]
): 'up' | 'down' | 'stable' {
  if (previousScores.length === 0) return 'stable';

  const avgPrevious = previousScores.reduce((a, b) => a + b, 0) / previousScores.length;
  const diff = currentScore - avgPrevious;

  if (diff > 20) return 'up';
  if (diff < -20) return 'down';
  return 'stable';
}

// Get color for score display
export function getScoreColor(score: number): string {
  if (score >= 900) return '#22c55e'; // green
  if (score >= 750) return '#84cc16'; // lime
  if (score >= 500) return '#eab308'; // yellow
  if (score >= 250) return '#f97316'; // orange
  return '#ef4444'; // red
}

// Get badge text for quality level
export function getQualityBadge(qualityLevel: QualityLevel): { text: string; color: string } {
  const badges: Record<QualityLevel, { text: string; color: string }> = {
    excellent: { text: 'Excellent', color: '#22c55e' },
    good: { text: 'Good', color: '#84cc16' },
    moderate: { text: 'Moderate', color: '#eab308' },
    poor: { text: 'Poor', color: '#f97316' },
    critical: { text: 'Critical', color: '#ef4444' },
    unknown: { text: 'No Data', color: '#6b7280' },
  };
  return badges[qualityLevel];
}
