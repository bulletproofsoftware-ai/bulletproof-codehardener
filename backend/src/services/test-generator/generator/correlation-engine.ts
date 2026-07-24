/**
 * Correlation Engine
 * Correlates findings across OWASP Top 10, CWE Top 25, and BRD requirements
 * Creates a unified view of security and functional test coverage
 */

import { createLogger } from '../../../utils/logger.js';
import type {
  GeneratedTestCase,
  ParsedRequirement,
  CodeAnalysisResult,
  ExtractedEndpoint,
  TestCaseCategory,
} from '../types.js';
import { OWASP_TOP_10_2021 } from './owasp-generator.js';
import { CWE_TOP_25_2023 } from './cwe-generator.js';

// Helper function to safely get category as object
function getCategoryObject(category: string | TestCaseCategory): TestCaseCategory {
  if (typeof category === 'string') {
    return { primary: category };
  }
  return category;
}

const logger = createLogger('correlation-engine');

/**
 * OWASP to CWE mapping (official mappings)
 */
export const OWASP_TO_CWE_MAP: Record<string, string[]> = {
  'A01:2021': ['CWE-22', 'CWE-352', 'CWE-862', 'CWE-863', 'CWE-269', 'CWE-276'],
  'A02:2021': ['CWE-287', 'CWE-306', 'CWE-798'],
  'A03:2021': ['CWE-79', 'CWE-89', 'CWE-78', 'CWE-77', 'CWE-94', 'CWE-20'],
  'A04:2021': ['CWE-434', 'CWE-362'],
  'A05:2021': ['CWE-276'],
  'A06:2021': ['CWE-787', 'CWE-416', 'CWE-125', 'CWE-476', 'CWE-190', 'CWE-119'],
  'A07:2021': ['CWE-287', 'CWE-306', 'CWE-798'],
  'A08:2021': ['CWE-502'],
  'A09:2021': [],  // Logging and Monitoring - no direct CWE mapping
  'A10:2021': ['CWE-918'],
};

/**
 * CWE to OWASP reverse mapping
 */
export const CWE_TO_OWASP_MAP: Record<string, string[]> = {};

// Build reverse mapping
for (const [owasp, cwes] of Object.entries(OWASP_TO_CWE_MAP)) {
  for (const cwe of cwes) {
    if (!CWE_TO_OWASP_MAP[cwe]) {
      CWE_TO_OWASP_MAP[cwe] = [];
    }
    CWE_TO_OWASP_MAP[cwe].push(owasp);
  }
}

export interface CorrelatedFinding {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  owaspCategories: string[];
  cweCategories: string[];
  brdRequirements: string[];
  testCases: GeneratedTestCase[];
  affectedEndpoints: ExtractedEndpoint[];
  mitigations: string[];
  references: Array<{
    source: 'owasp' | 'cwe' | 'brd';
    id: string;
    url?: string;
  }>;
}

export interface CorrelationResult {
  findings: CorrelatedFinding[];
  coverageMatrix: {
    owasp: Record<string, { covered: boolean; testCount: number }>;
    cwe: Record<string, { covered: boolean; testCount: number }>;
    brd: Record<string, { covered: boolean; testCount: number }>;
  };
  summary: {
    totalFindings: number;
    bySeverity: Record<string, number>;
    owaspCoverage: number;
    cweCoverage: number;
    brdCoverage: number;
  };
  recommendations: string[];
}

/**
 * Correlate test cases across different security frameworks
 */
export function correlateFindings(
  testCases: GeneratedTestCase[],
  requirements: ParsedRequirement[],
  analysis: CodeAnalysisResult,
  endpoints: ExtractedEndpoint[]
): CorrelationResult {
  logger.info(
    {
      testCaseCount: testCases.length,
      requirementCount: requirements.length,
      endpointCount: endpoints.length,
    },
    'Correlating findings across security frameworks'
  );

  const startTime = Date.now();
  const findings: CorrelatedFinding[] = [];

  // Build coverage matrix
  const owaspCoverage: Record<string, { covered: boolean; testCount: number }> = {};
  const cweCoverage: Record<string, { covered: boolean; testCount: number }> = {};
  const brdCoverage: Record<string, { covered: boolean; testCount: number }> = {};

  // Initialize OWASP coverage
  for (const owaspId of Object.keys(OWASP_TOP_10_2021)) {
    owaspCoverage[owaspId] = { covered: false, testCount: 0 };
  }

  // Initialize CWE coverage (only applicable ones)
  for (const cweId of Object.keys(CWE_TOP_25_2023)) {
    const cwe = CWE_TOP_25_2023[cweId as keyof typeof CWE_TOP_25_2023];
    const langs = cwe.languages as readonly string[];
    const isApplicable = langs.includes('all') ||
      analysis.languages.some(lang => langs.includes(lang.language));

    if (isApplicable) {
      cweCoverage[cweId] = { covered: false, testCount: 0 };
    }
  }

  // Initialize BRD coverage
  for (const req of requirements) {
    brdCoverage[req.id] = { covered: false, testCount: 0 };
  }

  // Process each test case
  for (const testCase of testCases) {
    // Handle category as string or object
    const cat = getCategoryObject(testCase.category);

    // Update OWASP coverage
    if (cat.owasp) {
      const owaspId = cat.owasp;
      if (owaspCoverage[owaspId]) {
        owaspCoverage[owaspId].covered = true;
        owaspCoverage[owaspId].testCount++;
      }
    }

    // Update CWE coverage
    if (cat.cwe) {
      for (const cweId of cat.cwe) {
        if (cweCoverage[cweId]) {
          cweCoverage[cweId].covered = true;
          cweCoverage[cweId].testCount++;
        }
      }
    }

    // Update BRD coverage
    if (testCase.brdRequirementId) {
      if (brdCoverage[testCase.brdRequirementId]) {
        brdCoverage[testCase.brdRequirementId].covered = true;
        brdCoverage[testCase.brdRequirementId].testCount++;
      }
    }
  }

  // Group test cases by correlation
  const correlationGroups = groupByCorrelation(testCases, requirements, endpoints);

  // Create correlated findings
  for (const group of correlationGroups) {
    const finding = createCorrelatedFinding(group, analysis);
    findings.push(finding);
  }

  // Calculate coverage percentages
  const owaspCoveredCount = Object.values(owaspCoverage).filter(c => c.covered).length;
  const cweCoveredCount = Object.values(cweCoverage).filter(c => c.covered).length;
  const brdCoveredCount = Object.values(brdCoverage).filter(c => c.covered).length;

  const result: CorrelationResult = {
    findings,
    coverageMatrix: {
      owasp: owaspCoverage,
      cwe: cweCoverage,
      brd: brdCoverage,
    },
    summary: {
      totalFindings: findings.length,
      bySeverity: countBySeverity(findings),
      owaspCoverage: Object.keys(owaspCoverage).length > 0
        ? Math.round((owaspCoveredCount / Object.keys(owaspCoverage).length) * 100)
        : 0,
      cweCoverage: Object.keys(cweCoverage).length > 0
        ? Math.round((cweCoveredCount / Object.keys(cweCoverage).length) * 100)
        : 0,
      brdCoverage: requirements.length > 0
        ? Math.round((brdCoveredCount / requirements.length) * 100)
        : 0,
    },
    recommendations: generateCorrelationRecommendations(
      owaspCoverage,
      cweCoverage,
      brdCoverage,
      analysis
    ),
  };

  logger.info(
    {
      findingCount: findings.length,
      owaspCoverage: result.summary.owaspCoverage,
      cweCoverage: result.summary.cweCoverage,
      brdCoverage: result.summary.brdCoverage,
      durationMs: Date.now() - startTime,
    },
    'Correlation completed'
  );

  return result;
}

interface CorrelationGroup {
  id: string;
  testCases: GeneratedTestCase[];
  owaspIds: Set<string>;
  cweIds: Set<string>;
  brdIds: Set<string>;
  endpoints: ExtractedEndpoint[];
}

/**
 * Group test cases by their correlations
 */
function groupByCorrelation(
  testCases: GeneratedTestCase[],
  _requirements: ParsedRequirement[],
  _endpoints: ExtractedEndpoint[]
): CorrelationGroup[] {
  const groups: CorrelationGroup[] = [];
  const processedTestIds = new Set<string>();

  for (const testCase of testCases) {
    if (processedTestIds.has(testCase.id)) continue;

    // Find related test cases
    const relatedTests = findRelatedTestCases(testCase, testCases);
    const group: CorrelationGroup = {
      id: `CORR-${groups.length + 1}`,
      testCases: [testCase, ...relatedTests],
      owaspIds: new Set<string>(),
      cweIds: new Set<string>(),
      brdIds: new Set<string>(),
      endpoints: [],
    };

    // Collect all categories
    for (const tc of group.testCases) {
      processedTestIds.add(tc.id);
      const cat = getCategoryObject(tc.category);

      if (cat.owasp) {
        group.owaspIds.add(cat.owasp);
      }
      if (cat.cwe) {
        for (const cweId of cat.cwe) {
          group.cweIds.add(cweId);
        }
      }
      if (tc.brdRequirementId) {
        group.brdIds.add(tc.brdRequirementId);
      }
      if (tc.targetEndpoint && tc.targetEndpoint.path && tc.targetEndpoint.method) {
        const exists = group.endpoints.some(e =>
          e.path === tc.targetEndpoint!.path && e.method === tc.targetEndpoint!.method
        );
        if (!exists) {
          group.endpoints.push(tc.targetEndpoint as ExtractedEndpoint);
        }
      }
    }

    // Expand correlations using mappings
    for (const owaspId of group.owaspIds) {
      const relatedCwes = OWASP_TO_CWE_MAP[owaspId] || [];
      for (const cweId of relatedCwes) {
        group.cweIds.add(cweId);
      }
    }

    for (const cweId of group.cweIds) {
      const relatedOwasps = CWE_TO_OWASP_MAP[cweId] || [];
      for (const owaspId of relatedOwasps) {
        group.owaspIds.add(owaspId);
      }
    }

    groups.push(group);
  }

  return groups;
}

/**
 * Find test cases related to a given test case
 */
function findRelatedTestCases(
  testCase: GeneratedTestCase,
  allTestCases: GeneratedTestCase[]
): GeneratedTestCase[] {
  const related: GeneratedTestCase[] = [];
  const testCat = getCategoryObject(testCase.category);

  for (const other of allTestCases) {
    if (other.id === testCase.id) continue;
    const otherCat = getCategoryObject(other.category);

    // Same OWASP category
    if (testCat.owasp && otherCat.owasp &&
        testCat.owasp === otherCat.owasp) {
      related.push(other);
      continue;
    }

    // Overlapping CWE
    if (testCat.cwe && otherCat.cwe) {
      const overlap = testCat.cwe.some((cwe: string) => otherCat.cwe!.includes(cwe));
      if (overlap) {
        related.push(other);
        continue;
      }
    }

    // Same endpoint
    if (testCase.targetEndpoint && other.targetEndpoint &&
        testCase.targetEndpoint.path === other.targetEndpoint.path &&
        testCase.targetEndpoint.method === other.targetEndpoint.method) {
      related.push(other);
      continue;
    }

    // Same BRD requirement
    if (testCase.brdRequirementId && other.brdRequirementId &&
        testCase.brdRequirementId === other.brdRequirementId) {
      related.push(other);
    }
  }

  return related;
}

/**
 * Create a correlated finding from a group
 */
function createCorrelatedFinding(
  group: CorrelationGroup,
  _analysis: CodeAnalysisResult
): CorrelatedFinding {
  const owaspCategories = [...group.owaspIds];
  const cweCategories = [...group.cweIds];

  // Determine severity from highest priority test or category
  let severity: CorrelatedFinding['severity'] = 'medium';
  for (const tc of group.testCases) {
    if (tc.priority === 'critical') severity = 'critical';
    else if (tc.priority === 'high' && severity !== 'critical') severity = 'high';
  }

  // Check CWE severity
  for (const cweId of cweCategories) {
    const cwe = CWE_TOP_25_2023[cweId as keyof typeof CWE_TOP_25_2023];
    if (cwe) {
      if (cwe.severity === 'critical') severity = 'critical';
      else if (cwe.severity === 'high' && severity !== 'critical') severity = 'high';
    }
  }

  // Collect all mitigations
  const mitigations = new Set<string>();
  for (const owaspId of owaspCategories) {
    const owasp = OWASP_TOP_10_2021[owaspId as keyof typeof OWASP_TOP_10_2021];
    if (owasp && 'mitigations' in owasp && Array.isArray(owasp.mitigations)) {
      for (const m of owasp.mitigations as string[]) {
        mitigations.add(m);
      }
    }
  }
  for (const cweId of cweCategories) {
    const cwe = CWE_TOP_25_2023[cweId as keyof typeof CWE_TOP_25_2023];
    if (cwe?.mitigations) {
      for (const m of cwe.mitigations) {
        mitigations.add(m);
      }
    }
  }

  // Build references
  const references: CorrelatedFinding['references'] = [];
  for (const owaspId of owaspCategories) {
    references.push({
      source: 'owasp',
      id: owaspId,
      url: `https://owasp.org/Top10/A01_2021-${owaspId.replace(':', '_')}/`,
    });
  }
  for (const cweId of cweCategories) {
    references.push({
      source: 'cwe',
      id: cweId,
      url: `https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`,
    });
  }
  for (const brdId of group.brdIds) {
    references.push({
      source: 'brd',
      id: brdId,
    });
  }

  // Generate name and description
  const primaryTest = group.testCases[0];
  const name = generateFindingName(owaspCategories, cweCategories, primaryTest);
  const description = generateFindingDescription(owaspCategories, cweCategories, group.testCases);

  return {
    id: group.id,
    name,
    description,
    severity,
    owaspCategories,
    cweCategories,
    brdRequirements: [...group.brdIds],
    testCases: group.testCases,
    affectedEndpoints: group.endpoints,
    mitigations: [...mitigations],
    references,
  };
}

/**
 * Generate a finding name from categories
 */
function generateFindingName(
  owaspIds: string[],
  cweIds: string[],
  primaryTest: GeneratedTestCase
): string {
  if (owaspIds.length > 0) {
    const owasp = OWASP_TOP_10_2021[owaspIds[0] as keyof typeof OWASP_TOP_10_2021];
    if (owasp) return owasp.name;
  }

  if (cweIds.length > 0) {
    const cwe = CWE_TOP_25_2023[cweIds[0] as keyof typeof CWE_TOP_25_2023];
    if (cwe) return cwe.name;
  }

  return primaryTest.name;
}

/**
 * Generate a finding description
 */
function generateFindingDescription(
  owaspIds: string[],
  cweIds: string[],
  testCases: GeneratedTestCase[]
): string {
  const parts: string[] = [];

  if (owaspIds.length > 0) {
    const owasp = OWASP_TOP_10_2021[owaspIds[0] as keyof typeof OWASP_TOP_10_2021];
    if (owasp) {
      parts.push(owasp.description);
    }
  }

  if (cweIds.length > 0 && parts.length === 0) {
    const cwe = CWE_TOP_25_2023[cweIds[0] as keyof typeof CWE_TOP_25_2023];
    if (cwe) {
      parts.push(cwe.description);
    }
  }

  if (parts.length === 0) {
    parts.push(testCases[0].description);
  }

  parts.push(`This finding is covered by ${testCases.length} test case(s).`);

  return parts.join(' ');
}

/**
 * Count findings by severity
 */
function countBySeverity(findings: CorrelatedFinding[]): Record<string, number> {
  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const finding of findings) {
    counts[finding.severity]++;
  }

  return counts;
}

/**
 * Generate recommendations based on correlation results
 */
function generateCorrelationRecommendations(
  owaspCoverage: Record<string, { covered: boolean; testCount: number }>,
  cweCoverage: Record<string, { covered: boolean; testCount: number }>,
  brdCoverage: Record<string, { covered: boolean; testCount: number }>,
  analysis: CodeAnalysisResult
): string[] {
  const recommendations: string[] = [];

  // Check uncovered OWASP categories
  const uncoveredOwasp = Object.entries(owaspCoverage)
    .filter(([_, v]) => !v.covered)
    .map(([k]) => k);

  if (uncoveredOwasp.length > 0) {
    const owaspNames = uncoveredOwasp.slice(0, 3).map(id => {
      const owasp = OWASP_TOP_10_2021[id as keyof typeof OWASP_TOP_10_2021];
      return owasp ? `${id} (${owasp.name})` : id;
    });
    recommendations.push(
      `Add test cases for uncovered OWASP categories: ${owaspNames.join(', ')}${uncoveredOwasp.length > 3 ? ` and ${uncoveredOwasp.length - 3} more` : ''}`
    );
  }

  // Check uncovered CWE categories
  const uncoveredCwe = Object.entries(cweCoverage)
    .filter(([_, v]) => !v.covered)
    .map(([k]) => k);

  // Prioritize by CWE rank
  const sortedUncoveredCwe = uncoveredCwe.sort((a, b) => {
    const cweA = CWE_TOP_25_2023[a as keyof typeof CWE_TOP_25_2023];
    const cweB = CWE_TOP_25_2023[b as keyof typeof CWE_TOP_25_2023];
    return (cweA?.rank || 99) - (cweB?.rank || 99);
  });

  if (sortedUncoveredCwe.length > 0) {
    const topUncovered = sortedUncoveredCwe.slice(0, 3);
    recommendations.push(
      `High-priority: Add tests for top CWE weaknesses: ${topUncovered.join(', ')}`
    );
  }

  // Check BRD coverage
  const uncoveredBrd = Object.entries(brdCoverage)
    .filter(([_, v]) => !v.covered)
    .map(([k]) => k);

  if (uncoveredBrd.length > 0) {
    recommendations.push(
      `${uncoveredBrd.length} BRD requirements have no test coverage`
    );
  }

  // Language-specific recommendations
  const languageNames = analysis.languages.map(l => l.language);
  if (languageNames.includes('javascript') || languageNames.includes('typescript')) {
    if (!cweCoverage['CWE-79']?.covered) {
      recommendations.push('JavaScript/TypeScript detected: Ensure XSS (CWE-79) testing is included');
    }
  }

  if (analysis.hasDatabase && !cweCoverage['CWE-89']?.covered) {
    recommendations.push('Database usage detected: Ensure SQL injection (CWE-89) testing is included');
  }

  if (analysis.hasAuthentication && !owaspCoverage['A07:2021']?.covered) {
    recommendations.push('Authentication detected: Ensure identity and authentication testing (A07:2021) is included');
  }

  return recommendations;
}

/**
 * Get unified coverage report
 */
export function getUnifiedCoverageReport(correlationResult: CorrelationResult): {
  overallScore: number;
  breakdown: Array<{
    category: string;
    coverage: number;
    uncovered: string[];
  }>;
  criticalGaps: string[];
} {
  const { coverageMatrix, summary } = correlationResult;

  // Calculate overall score (weighted average)
  const overallScore = Math.round(
    (summary.owaspCoverage * 0.4) +
    (summary.cweCoverage * 0.4) +
    (summary.brdCoverage * 0.2)
  );

  // Build breakdown
  const uncoveredOwasp = Object.entries(coverageMatrix.owasp)
    .filter(([_, v]) => !v.covered)
    .map(([k]) => k);

  const uncoveredCwe = Object.entries(coverageMatrix.cwe)
    .filter(([_, v]) => !v.covered)
    .map(([k]) => k);

  const uncoveredBrd = Object.entries(coverageMatrix.brd)
    .filter(([_, v]) => !v.covered)
    .map(([k]) => k);

  const breakdown = [
    {
      category: 'OWASP Top 10',
      coverage: summary.owaspCoverage,
      uncovered: uncoveredOwasp,
    },
    {
      category: 'CWE Top 25',
      coverage: summary.cweCoverage,
      uncovered: uncoveredCwe,
    },
    {
      category: 'BRD Requirements',
      coverage: summary.brdCoverage,
      uncovered: uncoveredBrd,
    },
  ];

  // Identify critical gaps
  const criticalGaps: string[] = [];

  // Critical OWASP gaps
  const criticalOwaspIds = ['A01:2021', 'A02:2021', 'A03:2021', 'A07:2021'];
  for (const id of criticalOwaspIds) {
    if (!coverageMatrix.owasp[id]?.covered) {
      const owasp = OWASP_TOP_10_2021[id as keyof typeof OWASP_TOP_10_2021];
      criticalGaps.push(`CRITICAL: ${id} ${owasp?.name || ''} not covered`);
    }
  }

  // Top 5 CWE gaps
  const topCweIds = ['CWE-787', 'CWE-79', 'CWE-89', 'CWE-416', 'CWE-78'];
  for (const id of topCweIds) {
    if (coverageMatrix.cwe[id] && !coverageMatrix.cwe[id].covered) {
      const cwe = CWE_TOP_25_2023[id as keyof typeof CWE_TOP_25_2023];
      criticalGaps.push(`HIGH: ${id} ${cwe?.name || ''} not covered`);
    }
  }

  return {
    overallScore,
    breakdown,
    criticalGaps,
  };
}
