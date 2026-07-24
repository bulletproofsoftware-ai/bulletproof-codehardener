/**
 * TG-003: BRD Alignment
 * Aligns generated test cases with parsed BRD requirements
 */

import { createLogger } from '../../../utils/logger.js';
import type {
  GeneratedTestCase,
  ParsedRequirement,
} from '../types.js';

const logger = createLogger('brd-alignment');

export interface RequirementAlignment {
  requirementId: string;
  requirement: ParsedRequirement;
  alignedTestCases: GeneratedTestCase[];
  coverage: {
    functional: boolean;
    security: boolean;
    performance: boolean;
    integration: boolean;
  };
  coverageScore: number; // 0-100
  gaps: string[];
  suggestions: string[];
}

export interface AlignmentResult {
  alignments: RequirementAlignment[];
  unmappedRequirements: ParsedRequirement[];
  unmappedTestCases: GeneratedTestCase[];
  overallCoverage: {
    totalRequirements: number;
    coveredRequirements: number;
    coveragePercentage: number;
    byType: Record<string, { total: number; covered: number }>;
    byPriority: Record<string, { total: number; covered: number }>;
  };
  recommendations: string[];
}

/**
 * Keywords for matching requirements to test cases
 */
const ALIGNMENT_KEYWORDS: Record<string, string[]> = {
  authentication: [
    'auth', 'login', 'logout', 'session', 'token', 'jwt', 'oauth',
    'password', 'credential', 'identity', 'sso', 'mfa', '2fa',
  ],
  authorization: [
    'permission', 'role', 'access', 'privilege', 'rbac', 'acl',
    'policy', 'authorize', 'restrict', 'allow', 'deny', 'admin',
  ],
  dataProtection: [
    'encrypt', 'hash', 'sensitive', 'pii', 'gdpr', 'privacy',
    'confidential', 'secure', 'protect', 'mask', 'redact',
  ],
  inputValidation: [
    'validate', 'sanitize', 'input', 'parameter', 'form', 'field',
    'check', 'verify', 'filter', 'escape', 'encode',
  ],
  api: [
    'api', 'endpoint', 'rest', 'graphql', 'request', 'response',
    'http', 'get', 'post', 'put', 'delete', 'patch', 'webhook',
  ],
  database: [
    'database', 'sql', 'query', 'store', 'persist', 'crud',
    'insert', 'update', 'delete', 'select', 'table', 'record',
  ],
  fileHandling: [
    'file', 'upload', 'download', 'attachment', 'document', 'image',
    'storage', 'path', 'directory', 'blob',
  ],
  errorHandling: [
    'error', 'exception', 'handling', 'catch', 'try', 'fail',
    'graceful', 'recover', 'fallback', 'retry',
  ],
  logging: [
    'log', 'audit', 'track', 'monitor', 'trace', 'record',
    'history', 'event', 'activity',
  ],
  performance: [
    'performance', 'speed', 'latency', 'throughput', 'load',
    'scalable', 'response time', 'concurrent', 'cache',
  ],
};

/**
 * Calculate text similarity using Jaccard index
 */
function calculateSimilarity(text1: string, text2: string): number {
  const words1 = new Set(text1.toLowerCase().split(/\s+/).filter(w => w.length > 2));
  const words2 = new Set(text2.toLowerCase().split(/\s+/).filter(w => w.length > 2));

  if (words1.size === 0 || words2.size === 0) {
    return 0;
  }

  const intersection = new Set([...words1].filter(x => words2.has(x)));
  const union = new Set([...words1, ...words2]);

  return intersection.size / union.size;
}

/**
 * Extract keywords from text
 */
function extractKeywords(text: string): Set<string> {
  const keywords = new Set<string>();
  const lowerText = text.toLowerCase();

  for (const [category, categoryKeywords] of Object.entries(ALIGNMENT_KEYWORDS)) {
    for (const keyword of categoryKeywords) {
      if (lowerText.includes(keyword)) {
        keywords.add(category);
        keywords.add(keyword);
      }
    }
  }

  return keywords;
}

/**
 * Check if a test case aligns with a requirement
 */
function isAligned(
  testCase: GeneratedTestCase,
  requirement: ParsedRequirement
): { aligned: boolean; confidence: number; reason: string } {
  // Direct ID reference
  if (testCase.brdRequirementId === requirement.id) {
    return { aligned: true, confidence: 1.0, reason: 'Direct ID reference' };
  }

  // Extract keywords from both
  const testKeywords = extractKeywords(
    `${testCase.name} ${testCase.description} ${testCase.steps.join(' ')}`
  );
  const reqKeywords = extractKeywords(
    `${requirement.title} ${requirement.description} ${(requirement.acceptanceCriteria || []).join(' ')}`
  );

  // Calculate keyword overlap
  const intersection = new Set([...testKeywords].filter(x => reqKeywords.has(x)));
  const union = new Set([...testKeywords, ...reqKeywords]);

  const keywordOverlap = union.size > 0 ? intersection.size / union.size : 0;

  // Calculate text similarity
  const textSimilarity = calculateSimilarity(
    `${testCase.name} ${testCase.description}`,
    `${requirement.title} ${requirement.description}`
  );

  // Security type alignment
  const isSecurityReq = requirement.type === 'security';
  const isSecurityTest = testCase.type === 'security';
  const typeMatch = (isSecurityReq && isSecurityTest) ? 0.2 : 0;

  // API type alignment
  const isApiReq = requirement.type === 'api';
  const isApiTest = testCase.type === 'api' || testCase.targetEndpoint !== undefined;
  const apiMatch = (isApiReq && isApiTest) ? 0.2 : 0;

  // Calculate combined confidence
  const confidence = Math.min(1, keywordOverlap * 0.4 + textSimilarity * 0.4 + typeMatch + apiMatch);

  // Alignment threshold
  const threshold = 0.15;

  if (confidence >= threshold) {
    const reasons: string[] = [];
    if (keywordOverlap > 0.1) reasons.push(`keyword overlap (${Math.round(keywordOverlap * 100)}%)`);
    if (textSimilarity > 0.1) reasons.push(`text similarity (${Math.round(textSimilarity * 100)}%)`);
    if (typeMatch > 0) reasons.push('type match');
    if (apiMatch > 0) reasons.push('API alignment');

    return {
      aligned: true,
      confidence,
      reason: reasons.join(', ') || 'Combined factors',
    };
  }

  return { aligned: false, confidence, reason: 'No significant alignment' };
}

/**
 * Determine coverage type for a test case
 */
function getCoverageType(testCase: GeneratedTestCase): keyof RequirementAlignment['coverage'] {
  switch (testCase.type) {
    case 'security':
      return 'security';
    case 'performance':
    case 'load':
      return 'performance';
    case 'api':
    case 'integration':
      return 'integration';
    default:
      return 'functional';
  }
}

/**
 * Generate gap analysis for a requirement
 */
function analyzeGaps(
  requirement: ParsedRequirement,
  alignedTests: GeneratedTestCase[]
): string[] {
  const gaps: string[] = [];

  // Check for acceptance criteria coverage
  if ((requirement.acceptanceCriteria?.length || 0) > 0) {
    const uncoveredCriteria = (requirement.acceptanceCriteria || []).filter(criterion => {
      const criterionLower = criterion.toLowerCase();
      return !alignedTests.some(test =>
        test.steps.some(step => calculateSimilarity(step.toLowerCase(), criterionLower) > 0.3)
      );
    });

    if (uncoveredCriteria.length > 0) {
      gaps.push(`${uncoveredCriteria.length} acceptance criteria may not be covered`);
    }
  }

  // Check for security requirement coverage
  if (requirement.type === 'security') {
    const hasSecurityTest = alignedTests.some(t => t.type === 'security');
    if (!hasSecurityTest) {
      gaps.push('Security requirement has no security-specific tests');
    }
  }

  // Check for API requirement coverage
  if (requirement.type === 'api') {
    const hasApiTest = alignedTests.some(t =>
      t.type === 'api' || t.targetEndpoint !== undefined
    );
    if (!hasApiTest) {
      gaps.push('API requirement has no API-specific tests');
    }
  }

  // Check for critical priority coverage depth
  if (requirement.priority === 'critical' && alignedTests.length < 3) {
    gaps.push('Critical requirement may need more comprehensive test coverage');
  }

  // Check for negative testing
  const hasNegativeTest = alignedTests.some(test =>
    test.steps.some(step =>
      /invalid|error|fail|reject|denied|negative/i.test(step)
    )
  );
  if (!hasNegativeTest && alignedTests.length > 0) {
    gaps.push('No negative test cases (error handling, invalid inputs)');
  }

  return gaps;
}

/**
 * Generate suggestions for improving coverage
 */
function generateSuggestions(
  requirement: ParsedRequirement,
  alignedTests: GeneratedTestCase[],
  gaps: string[]
): string[] {
  const suggestions: string[] = [];

  if (alignedTests.length === 0) {
    suggestions.push(`Create test cases specifically targeting "${requirement.title}"`);

    if (requirement.type === 'security') {
      suggestions.push('Add security test cases for authentication, authorization, and input validation');
    }
    if (requirement.type === 'api') {
      suggestions.push('Add API test cases covering success paths, error handling, and edge cases');
    }
  }

  if (gaps.includes('Security requirement has no security-specific tests')) {
    suggestions.push('Add OWASP Top 10 or CWE-based security tests');
  }

  if (gaps.some(g => g.includes('acceptance criteria'))) {
    suggestions.push('Create test cases that directly verify each acceptance criterion');
  }

  if (gaps.includes('No negative test cases')) {
    suggestions.push('Add tests for invalid inputs, error conditions, and boundary cases');
  }

  if (requirement.priority === 'critical' && alignedTests.length < 5) {
    suggestions.push('Consider adding more test cases for this critical requirement');
  }

  return suggestions;
}

/**
 * Calculate coverage score for a requirement
 */
function calculateCoverageScore(
  requirement: ParsedRequirement,
  alignedTests: GeneratedTestCase[],
  coverage: RequirementAlignment['coverage']
): number {
  if (alignedTests.length === 0) {
    return 0;
  }

  let score = 0;

  // Base coverage (up to 40 points)
  score += Math.min(40, alignedTests.length * 10);

  // Coverage type diversity (up to 20 points)
  const coverageTypes = Object.values(coverage).filter(Boolean).length;
  score += coverageTypes * 5;

  // High confidence alignments (up to 20 points)
  // Note: In a full implementation, we would track confidence scores
  score += Math.min(20, alignedTests.length * 5);

  // Acceptance criteria coverage (up to 20 points)
  const acceptanceCriteria = requirement.acceptanceCriteria || [];
  if (acceptanceCriteria.length > 0) {
    const coveredCriteria = acceptanceCriteria.filter(criterion => {
      const criterionLower = criterion.toLowerCase();
      return alignedTests.some(test =>
        test.steps.some(step => calculateSimilarity(step.toLowerCase(), criterionLower) > 0.2)
      );
    });
    const criteriaRatio = coveredCriteria.length / acceptanceCriteria.length;
    score += criteriaRatio * 20;
  } else {
    score += 10; // Partial credit if no criteria defined
  }

  return Math.min(100, Math.round(score));
}

/**
 * Align test cases with BRD requirements
 */
export function alignTestsWithRequirements(
  testCases: GeneratedTestCase[],
  requirements: ParsedRequirement[]
): AlignmentResult {
  logger.info(
    { testCaseCount: testCases.length, requirementCount: requirements.length },
    'Aligning test cases with BRD requirements'
  );

  const startTime = Date.now();
  const alignments: RequirementAlignment[] = [];
  const mappedTestIds = new Set<string>();

  // Align each requirement with test cases
  for (const requirement of requirements) {
    const alignedTestCases: GeneratedTestCase[] = [];
    const coverage: RequirementAlignment['coverage'] = {
      functional: false,
      security: false,
      performance: false,
      integration: false,
    };

    for (const testCase of testCases) {
      const alignmentResult = isAligned(testCase, requirement);

      if (alignmentResult.aligned) {
        alignedTestCases.push(testCase);
        mappedTestIds.add(testCase.id);

        // Update coverage types
        const coverageType = getCoverageType(testCase);
        coverage[coverageType] = true;
      }
    }

    const gaps = analyzeGaps(requirement, alignedTestCases);
    const suggestions = generateSuggestions(requirement, alignedTestCases, gaps);
    const coverageScore = calculateCoverageScore(requirement, alignedTestCases, coverage);

    alignments.push({
      requirementId: requirement.id,
      requirement,
      alignedTestCases,
      coverage,
      coverageScore,
      gaps,
      suggestions,
    });
  }

  // Find unmapped requirements and test cases
  const unmappedRequirements = requirements.filter(req =>
    !alignments.some(a => a.requirementId === req.id && a.alignedTestCases.length > 0)
  );

  const unmappedTestCases = testCases.filter(tc => !mappedTestIds.has(tc.id));

  // Calculate overall coverage
  const coveredRequirements = alignments.filter(a => a.alignedTestCases.length > 0);

  const byType: Record<string, { total: number; covered: number }> = {};
  const byPriority: Record<string, { total: number; covered: number }> = {};

  for (const alignment of alignments) {
    const type = alignment.requirement.type;
    const priority = alignment.requirement.priority;
    const isCovered = alignment.alignedTestCases.length > 0;

    // By type
    if (!byType[type]) {
      byType[type] = { total: 0, covered: 0 };
    }
    byType[type].total++;
    if (isCovered) byType[type].covered++;

    // By priority
    if (!byPriority[priority]) {
      byPriority[priority] = { total: 0, covered: 0 };
    }
    byPriority[priority].total++;
    if (isCovered) byPriority[priority].covered++;
  }

  // Generate recommendations
  const recommendations = generateRecommendations(alignments, unmappedRequirements, byPriority);

  const result: AlignmentResult = {
    alignments,
    unmappedRequirements,
    unmappedTestCases,
    overallCoverage: {
      totalRequirements: requirements.length,
      coveredRequirements: coveredRequirements.length,
      coveragePercentage: requirements.length > 0
        ? Math.round((coveredRequirements.length / requirements.length) * 100)
        : 0,
      byType,
      byPriority,
    },
    recommendations,
  };

  logger.info(
    {
      alignmentCount: alignments.length,
      coveredRequirements: coveredRequirements.length,
      unmappedRequirements: unmappedRequirements.length,
      unmappedTestCases: unmappedTestCases.length,
      coveragePercentage: result.overallCoverage.coveragePercentage,
      durationMs: Date.now() - startTime,
    },
    'BRD alignment completed'
  );

  return result;
}

/**
 * Generate recommendations based on alignment results
 */
function generateRecommendations(
  alignments: RequirementAlignment[],
  unmappedRequirements: ParsedRequirement[],
  byPriority: Record<string, { total: number; covered: number }>
): string[] {
  const recommendations: string[] = [];

  // Check critical priority coverage
  const criticalCoverage = byPriority['critical'];
  if (criticalCoverage && criticalCoverage.total > 0) {
    const criticalPercent = (criticalCoverage.covered / criticalCoverage.total) * 100;
    if (criticalPercent < 100) {
      recommendations.push(
        `URGENT: ${criticalCoverage.total - criticalCoverage.covered} critical requirements lack test coverage`
      );
    }
  }

  // Check high priority coverage
  const highCoverage = byPriority['high'];
  if (highCoverage && highCoverage.total > 0) {
    const highPercent = (highCoverage.covered / highCoverage.total) * 100;
    if (highPercent < 80) {
      recommendations.push(
        `${highCoverage.total - highCoverage.covered} high priority requirements need additional test coverage`
      );
    }
  }

  // Check security requirements specifically
  const securityUnmapped = unmappedRequirements.filter(r => r.type === 'security');
  if (securityUnmapped.length > 0) {
    recommendations.push(
      `${securityUnmapped.length} security requirements are not covered by any tests`
    );
  }

  // Check for low coverage scores
  const lowCoverageAlignments = alignments.filter(a => a.coverageScore > 0 && a.coverageScore < 50);
  if (lowCoverageAlignments.length > 0) {
    recommendations.push(
      `${lowCoverageAlignments.length} requirements have low test coverage scores (<50%)`
    );
  }

  // Suggest improving acceptance criteria coverage
  const missingCriteriaTests = alignments.filter(a =>
    (a.requirement.acceptanceCriteria?.length || 0) > 0 &&
    a.gaps.some(g => g.includes('acceptance criteria'))
  );
  if (missingCriteriaTests.length > 0) {
    recommendations.push(
      `${missingCriteriaTests.length} requirements have acceptance criteria that may not be tested`
    );
  }

  // General recommendations
  if (unmappedRequirements.length > 0) {
    recommendations.push(
      `Review ${unmappedRequirements.length} requirements that have no aligned test cases`
    );
  }

  return recommendations;
}

/**
 * Generate additional test cases to fill coverage gaps
 */
export function generateGapFillingTests(
  alignmentResult: AlignmentResult
): GeneratedTestCase[] {
  const gapTests: GeneratedTestCase[] = [];

  for (const unmapped of alignmentResult.unmappedRequirements) {
    // Generate a basic test case for each unmapped requirement
    gapTests.push({
      id: `GAP-${unmapped.id}-functional`,
      name: `Verify: ${unmapped.title}`,
      description: `Test case to verify requirement ${unmapped.id}: ${unmapped.description.substring(0, 100)}`,
      type: unmapped.type === 'security' ? 'security' : 'functional',
      priority: unmapped.priority,
      category: {
        primary: unmapped.id,
        brdRequirement: unmapped.id,
      },
      steps: generateStepsFromRequirement(unmapped),
      expectedResult: `Requirement ${unmapped.id} is satisfied`,
      brdRequirementId: unmapped.id,
      metadata: {
        generated: true,
        gapFilling: true,
        sourceRequirement: unmapped.id,
      },
    });

    // If it's a security requirement, add additional security tests
    if (unmapped.type === 'security') {
      gapTests.push({
        id: `GAP-${unmapped.id}-security-negative`,
        name: `Security Negative Test: ${unmapped.title}`,
        description: `Negative security test for ${unmapped.id}`,
        type: 'security',
        priority: unmapped.priority,
        category: {
          primary: unmapped.id,
          brdRequirement: unmapped.id,
        },
        steps: [
          'Attempt to bypass security controls',
          'Test with invalid/malicious inputs',
          'Verify security constraints are enforced',
          'Check for information leakage in error responses',
        ],
        expectedResult: 'Security controls prevent unauthorized access',
        brdRequirementId: unmapped.id,
        metadata: {
          generated: true,
          gapFilling: true,
          testType: 'negative',
        },
      });
    }
  }

  return gapTests;
}

/**
 * Generate test steps from requirement description and criteria
 */
function generateStepsFromRequirement(requirement: ParsedRequirement): string[] {
  const steps: string[] = [];

  // Parse user story if available
  if (requirement.userStory) {
    steps.push(`Setup: Configure system for ${requirement.userStory.role} role`);
    steps.push(`Action: ${requirement.userStory.feature}`);
    steps.push(`Verify: ${requirement.userStory.benefit}`);
  }

  // Add acceptance criteria as steps
  for (const criterion of requirement.acceptanceCriteria || []) {
    steps.push(`Verify: ${criterion}`);
  }

  // If no specific steps, generate generic ones
  if (steps.length === 0) {
    steps.push(
      'Review requirement description',
      'Identify testable conditions',
      'Execute test scenario',
      'Verify expected behavior',
      'Document results'
    );
  }

  return steps;
}

/**
 * Get coverage report as structured data
 */
export function getCoverageReport(alignmentResult: AlignmentResult): {
  summary: string;
  details: Array<{
    requirementId: string;
    title: string;
    priority: string;
    coverageScore: number;
    testCount: number;
    status: 'covered' | 'partial' | 'uncovered';
  }>;
} {
  const details = alignmentResult.alignments.map(a => ({
    requirementId: a.requirementId,
    title: a.requirement.title,
    priority: a.requirement.priority,
    coverageScore: a.coverageScore,
    testCount: a.alignedTestCases.length,
    status: (a.coverageScore >= 70 ? 'covered' :
      a.coverageScore >= 30 ? 'partial' : 'uncovered') as 'covered' | 'partial' | 'uncovered',
  }));

  const covered = details.filter(d => d.status === 'covered').length;
  const partial = details.filter(d => d.status === 'partial').length;
  const uncovered = details.filter(d => d.status === 'uncovered').length;

  const summary = `Coverage: ${covered} covered, ${partial} partial, ${uncovered} uncovered out of ${details.length} requirements (${alignmentResult.overallCoverage.coveragePercentage}%)`;

  return { summary, details };
}
