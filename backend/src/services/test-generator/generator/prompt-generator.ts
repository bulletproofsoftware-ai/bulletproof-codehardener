/**
 * Prompt Generator
 * Generates prompts for AI-assisted test case generation and refinement
 */

import { createLogger } from '../../../utils/logger.js';
import type {
  GeneratedTestCase,
  ParsedRequirement,
  CodeAnalysisResult,
  ExtractedEndpoint,
} from '../types.js';
import { getCategoryObject } from '../types.js';

const logger = createLogger('prompt-generator');

export type PromptType =
  | 'test_generation'
  | 'test_refinement'
  | 'coverage_analysis'
  | 'security_review'
  | 'requirement_mapping';

export interface PromptContext {
  analysis?: CodeAnalysisResult;
  endpoints?: ExtractedEndpoint[];
  requirements?: ParsedRequirement[];
  existingTests?: GeneratedTestCase[];
  focusAreas?: string[];
  targetFramework?: string;
}

export interface GeneratedPrompt {
  type: PromptType;
  systemPrompt: string;
  userPrompt: string;
  contextData: Record<string, unknown>;
  expectedOutputSchema?: object;
}

/**
 * Generate a prompt for AI-assisted test generation
 */
export function generatePrompt(
  type: PromptType,
  context: PromptContext
): GeneratedPrompt {
  logger.info({ type }, 'Generating AI prompt');

  switch (type) {
    case 'test_generation':
      return generateTestGenerationPrompt(context);
    case 'test_refinement':
      return generateTestRefinementPrompt(context);
    case 'coverage_analysis':
      return generateCoverageAnalysisPrompt(context);
    case 'security_review':
      return generateSecurityReviewPrompt(context);
    case 'requirement_mapping':
      return generateRequirementMappingPrompt(context);
    default:
      throw new Error(`Unknown prompt type: ${type}`);
  }
}

/**
 * Generate prompt for creating new test cases
 */
function generateTestGenerationPrompt(context: PromptContext): GeneratedPrompt {
  const { analysis, endpoints, requirements, focusAreas, targetFramework } = context;

  const systemPrompt = `You are an expert security and quality assurance engineer specializing in automated test case generation.

Your task is to generate comprehensive test cases based on the provided code analysis and requirements.

Guidelines:
1. Generate test cases that cover OWASP Top 10 and CWE Top 25 vulnerabilities
2. Include both positive (happy path) and negative (error handling, security) tests
3. Map tests to specific requirements when possible
4. Prioritize based on risk and business impact
5. Include clear, actionable steps that can be automated
6. Consider the detected languages and frameworks

Output Format:
- Each test case should have: id, name, description, type, priority, steps, expected result
- Group tests by category (security, functional, performance, integration)
- Include OWASP and CWE references where applicable`;

  const analysisContext = analysis ? `
## Code Analysis Results
- **Languages Detected:** ${analysis.languages.join(', ')}
- **Frameworks:** ${analysis.frameworks.map(f => f.name).join(', ') || 'None detected'}
- **Has Database:** ${analysis.hasDatabase}
- **Has Authentication:** ${analysis.hasAuthentication}
- **Has File Operations:** ${analysis.hasFileOperations}
- **Has User Input:** ${analysis.hasUserInput}` : '';

  const endpointContext = endpoints && endpoints.length > 0 ? `
## API Endpoints Detected
${endpoints.slice(0, 20).map(e => `- ${e.method} ${e.path}${e.auth ? ' (authenticated)' : ''}`).join('\n')}
${endpoints.length > 20 ? `\n... and ${endpoints.length - 20} more endpoints` : ''}` : '';

  const requirementContext = requirements && requirements.length > 0 ? `
## Requirements to Cover
${requirements.slice(0, 10).map(r => `- [${r.id}] ${r.title} (${r.priority})`).join('\n')}
${requirements.length > 10 ? `\n... and ${requirements.length - 10} more requirements` : ''}` : '';

  const focusContext = focusAreas && focusAreas.length > 0 ? `
## Focus Areas
${focusAreas.map(a => `- ${a}`).join('\n')}` : '';

  const frameworkContext = targetFramework ? `
## Target Test Framework
Generate tests compatible with: ${targetFramework}` : '';

  const userPrompt = `Generate comprehensive test cases for the following codebase:
${analysisContext}
${endpointContext}
${requirementContext}
${focusContext}
${frameworkContext}

Please generate test cases covering:
1. Security vulnerabilities (injection, authentication, authorization)
2. Input validation and error handling
3. API contract testing
4. Business logic verification
5. Edge cases and boundary conditions

For each test case, provide:
- Unique ID
- Clear name and description
- Test type (security, functional, api, performance)
- Priority (critical, high, medium, low)
- Step-by-step instructions
- Expected results
- OWASP/CWE mapping if applicable`;

  return {
    type: 'test_generation',
    systemPrompt,
    userPrompt,
    contextData: {
      languageCount: analysis?.languages.length || 0,
      endpointCount: endpoints?.length || 0,
      requirementCount: requirements?.length || 0,
    },
    expectedOutputSchema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          name: { type: 'string' },
          description: { type: 'string' },
          type: { type: 'string', enum: ['security', 'functional', 'api', 'performance'] },
          priority: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
          steps: { type: 'array', items: { type: 'string' } },
          expectedResult: { type: 'string' },
          owaspCategory: { type: 'string' },
          cweIds: { type: 'array', items: { type: 'string' } },
        },
        required: ['id', 'name', 'description', 'type', 'priority', 'steps', 'expectedResult'],
      },
    },
  };
}

/**
 * Generate prompt for refining existing test cases
 */
function generateTestRefinementPrompt(context: PromptContext): GeneratedPrompt {
  const { existingTests, analysis, focusAreas } = context;

  const systemPrompt = `You are an expert test engineer reviewing and improving existing test cases.

Your task is to analyze the provided test cases and suggest improvements:
1. Identify gaps in test coverage
2. Suggest additional edge cases
3. Improve test descriptions and steps for clarity
4. Add missing security considerations
5. Optimize test efficiency and reduce redundancy

Be specific and actionable in your recommendations.`;

  const testsContext = existingTests && existingTests.length > 0 ? `
## Existing Test Cases
${existingTests.slice(0, 15).map(t => {
    const tCat = getCategoryObject(t.category);
    return `
### ${t.name}
- **Type:** ${t.type}
- **Priority:** ${t.priority}
- **Steps:** ${t.steps.length} steps
- **Category:** ${tCat.primary || tCat.owasp || 'General'}
`;
  }).join('\n')}
${existingTests.length > 15 ? `\n... and ${existingTests.length - 15} more tests` : ''}` : '';

  const analysisContext = analysis ? `
## Code Context
- **Languages:** ${analysis.languages.join(', ')}
- **Has Database:** ${analysis.hasDatabase}
- **Has Auth:** ${analysis.hasAuthentication}` : '';

  const focusContext = focusAreas && focusAreas.length > 0 ? `
## Areas Needing Attention
${focusAreas.map(a => `- ${a}`).join('\n')}` : '';

  const userPrompt = `Please review and improve the following test cases:
${testsContext}
${analysisContext}
${focusContext}

Provide:
1. Specific improvements for existing tests
2. Missing test cases that should be added
3. Redundant tests that could be consolidated
4. Security gaps that need to be addressed
5. Priority recommendations for test execution`;

  return {
    type: 'test_refinement',
    systemPrompt,
    userPrompt,
    contextData: {
      testCount: existingTests?.length || 0,
    },
  };
}

/**
 * Generate prompt for coverage analysis
 */
function generateCoverageAnalysisPrompt(context: PromptContext): GeneratedPrompt {
  const { existingTests, requirements, analysis } = context;

  const systemPrompt = `You are a test coverage analyst evaluating the completeness of a test suite.

Analyze the provided test cases against requirements and code characteristics to:
1. Calculate coverage metrics
2. Identify untested areas
3. Assess risk of gaps
4. Recommend prioritized additions

Focus on both functional completeness and security coverage.`;

  const testsContext = existingTests ? `
## Test Suite Summary
- Total Tests: ${existingTests.length}
- Security Tests: ${existingTests.filter(t => t.type === 'security').length}
- Functional Tests: ${existingTests.filter(t => t.type === 'functional').length}
- API Tests: ${existingTests.filter(t => t.type === 'api').length}
- OWASP Categories Covered: ${new Set(existingTests.filter(t => getCategoryObject(t.category).owasp).map(t => getCategoryObject(t.category).owasp)).size}
- CWE Categories Covered: ${new Set(existingTests.flatMap(t => getCategoryObject(t.category).cwe || [])).size}` : '';

  const requirementsContext = requirements ? `
## Requirements Summary
- Total Requirements: ${requirements.length}
- Security Requirements: ${requirements.filter(r => r.type === 'security').length}
- Critical Priority: ${requirements.filter(r => r.priority === 'critical').length}
- With Acceptance Criteria: ${requirements.filter(r => (r.acceptanceCriteria?.length || 0) > 0).length}` : '';

  const analysisContext = analysis ? `
## Codebase Characteristics
- Languages: ${analysis.languages.join(', ')}
- Database Operations: ${analysis.hasDatabase}
- Authentication: ${analysis.hasAuthentication}
- File Handling: ${analysis.hasFileOperations}
- User Input Processing: ${analysis.hasUserInput}` : '';

  const userPrompt = `Analyze test coverage for this codebase:
${testsContext}
${requirementsContext}
${analysisContext}

Provide:
1. Overall coverage assessment (percentage estimate)
2. Critical gaps identified
3. Risk assessment for each gap
4. Prioritized list of tests to add
5. OWASP and CWE coverage status`;

  return {
    type: 'coverage_analysis',
    systemPrompt,
    userPrompt,
    contextData: {
      testCount: existingTests?.length || 0,
      requirementCount: requirements?.length || 0,
    },
  };
}

/**
 * Generate prompt for security-focused review
 */
function generateSecurityReviewPrompt(context: PromptContext): GeneratedPrompt {
  const { analysis, endpoints, existingTests } = context;

  const systemPrompt = `You are a senior application security engineer performing a security test review.

Your objectives:
1. Identify security testing gaps
2. Map tests to OWASP Top 10 and CWE Top 25
3. Assess injection attack coverage
4. Review authentication/authorization testing
5. Evaluate data protection test coverage
6. Check for cryptographic weakness testing

Be thorough and consider both common and advanced attack vectors.`;

  const analysisContext = analysis ? `
## Application Security Profile
- **Tech Stack:** ${analysis.languages.join(', ')}
- **Frameworks:** ${analysis.frameworks.map(f => f.name).join(', ') || 'Unknown'}
- **Has Database:** ${analysis.hasDatabase} ${analysis.hasDatabase ? '(SQL injection risk)' : ''}
- **Has Authentication:** ${analysis.hasAuthentication}
- **Has File Operations:** ${analysis.hasFileOperations} ${analysis.hasFileOperations ? '(path traversal risk)' : ''}
- **Processes User Input:** ${analysis.hasUserInput} ${analysis.hasUserInput ? '(injection risk)' : ''}
- **Has Shell Commands:** ${analysis.hasShellCommands} ${analysis.hasShellCommands ? '(command injection risk)' : ''}` : '';

  const endpointContext = endpoints && endpoints.length > 0 ? `
## API Attack Surface
- Total Endpoints: ${endpoints.length}
- Authenticated Endpoints: ${endpoints.filter(e => e.auth).length}
- Public Endpoints: ${endpoints.filter(e => !e.auth).length}
- File Upload Endpoints: ${endpoints.filter(e => e.path.includes('upload') || e.path.includes('file')).length}
- Admin Endpoints: ${endpoints.filter(e => e.path.includes('admin')).length}` : '';

  const securityTestsContext = existingTests ? `
## Current Security Tests
- Total Security Tests: ${existingTests.filter(t => t.type === 'security').length}
- OWASP Categories: ${[...new Set(existingTests.filter(t => getCategoryObject(t.category).owasp).map(t => getCategoryObject(t.category).owasp))].join(', ') || 'None'}
- CWE Coverage: ${[...new Set(existingTests.flatMap(t => getCategoryObject(t.category).cwe || []))].join(', ') || 'None'}` : '';

  const userPrompt = `Perform a security test gap analysis:
${analysisContext}
${endpointContext}
${securityTestsContext}

Analyze and provide:
1. OWASP Top 10 coverage status (each category)
2. CWE Top 25 coverage status (applicable items)
3. Critical security tests missing
4. Attack vectors not covered
5. Recommended security test cases to add (with steps)
6. Risk-ranked list of security gaps`;

  return {
    type: 'security_review',
    systemPrompt,
    userPrompt,
    contextData: {
      hasDatabase: analysis?.hasDatabase || false,
      hasAuth: analysis?.hasAuthentication || false,
      endpointCount: endpoints?.length || 0,
      securityTestCount: existingTests?.filter(t => t.type === 'security').length || 0,
    },
  };
}

/**
 * Generate prompt for mapping requirements to tests
 */
function generateRequirementMappingPrompt(context: PromptContext): GeneratedPrompt {
  const { requirements, existingTests } = context;

  const systemPrompt = `You are a requirements traceability expert mapping test cases to business requirements.

Your task is to:
1. Map each test case to relevant requirements
2. Identify requirements without test coverage
3. Assess coverage quality (not just presence)
4. Suggest tests for unmapped requirements
5. Identify over-tested areas

Focus on ensuring critical business and security requirements have adequate coverage.`;

  const requirementsContext = requirements ? `
## Requirements to Map
${requirements.map(r => `
- **${r.id}**: ${r.title}
  - Type: ${r.type}
  - Priority: ${r.priority}
  - Acceptance Criteria: ${r.acceptanceCriteria?.length || 0}
`).join('')}` : '';

  const testsContext = existingTests ? `
## Test Cases Available
${existingTests.map(t => `
- **${t.id}**: ${t.name}
  - Type: ${t.type}
  - Current Mapping: ${t.brdRequirementId || 'None'}
`).join('')}` : '';

  const userPrompt = `Create a requirements-to-test traceability matrix:
${requirementsContext}
${testsContext}

Provide:
1. Mapping table (requirement -> test cases)
2. Coverage assessment for each requirement
3. Requirements with no coverage
4. Requirements with insufficient coverage
5. Suggested test cases for gaps
6. Overall traceability score`;

  return {
    type: 'requirement_mapping',
    systemPrompt,
    userPrompt,
    contextData: {
      requirementCount: requirements?.length || 0,
      testCount: existingTests?.length || 0,
    },
  };
}

/**
 * Generate a summary prompt combining multiple analyses
 */
export function generateSummaryPrompt(
  testCases: GeneratedTestCase[],
  requirements: ParsedRequirement[],
  analysis: CodeAnalysisResult
): GeneratedPrompt {
  const systemPrompt = `You are a QA lead summarizing test generation results for stakeholders.

Create a clear, executive-friendly summary that:
1. Highlights key coverage metrics
2. Identifies critical gaps
3. Provides actionable recommendations
4. Prioritizes next steps

Be concise but comprehensive.`;

  const userPrompt = `Summarize the test generation results:

## Test Suite
- Total Tests: ${testCases.length}
- By Type: Security (${testCases.filter(t => t.type === 'security').length}), Functional (${testCases.filter(t => t.type === 'functional').length}), API (${testCases.filter(t => t.type === 'api').length})
- By Priority: Critical (${testCases.filter(t => t.priority === 'critical').length}), High (${testCases.filter(t => t.priority === 'high').length}), Medium (${testCases.filter(t => t.priority === 'medium').length})

## Requirements
- Total: ${requirements.length}
- Security: ${requirements.filter(r => r.type === 'security').length}
- Critical Priority: ${requirements.filter(r => r.priority === 'critical').length}

## Codebase
- Languages: ${analysis.languages.join(', ')}
- Key Features: ${[
    analysis.hasDatabase && 'Database',
    analysis.hasAuthentication && 'Authentication',
    analysis.hasFileOperations && 'File Handling',
    analysis.hasUserInput && 'User Input',
  ].filter(Boolean).join(', ')}

Provide:
1. Executive summary (2-3 sentences)
2. Key coverage metrics
3. Top 3 risks
4. Top 3 recommendations
5. Suggested timeline for addressing gaps`;

  return {
    type: 'coverage_analysis',
    systemPrompt,
    userPrompt,
    contextData: {
      testCount: testCases.length,
      requirementCount: requirements.length,
    },
  };
}

/**
 * Parse AI response into structured test cases
 */
export function parseTestCaseResponse(
  response: string,
  defaultCategory: string = 'AI-Generated'
): GeneratedTestCase[] {
  logger.info('Parsing AI response into test cases');

  const testCases: GeneratedTestCase[] = [];

  try {
    // Try parsing as JSON first
    const parsed = JSON.parse(response);
    const items = Array.isArray(parsed) ? parsed : parsed.testCases || parsed.tests || [];

    for (const item of items) {
      testCases.push({
        id: item.id || `AI-${Date.now()}-${testCases.length}`,
        name: item.name || item.title || 'Untitled Test',
        description: item.description || '',
        type: normalizeTestType(item.type),
        priority: normalizePriority(item.priority),
        category: {
          primary: defaultCategory,
          owasp: item.owaspCategory || item.owasp,
          cwe: item.cweIds || item.cwe,
        },
        steps: Array.isArray(item.steps) ? item.steps : [item.steps || 'Execute test'],
        expectedResult: item.expectedResult || item.expected || 'Test passes',
        metadata: {
          aiGenerated: true,
          sourcePromptType: 'test_generation',
        },
      });
    }
  } catch {
    // If JSON parsing fails, try to extract from markdown/text
    logger.warn('JSON parsing failed, attempting text extraction');
    // Basic extraction - could be enhanced
  }

  logger.info({ testCaseCount: testCases.length }, 'Parsed AI response');
  return testCases;
}

/**
 * Normalize test type string
 */
function normalizeTestType(type: string): GeneratedTestCase['type'] {
  const normalized = (type || '').toLowerCase();

  if (normalized.includes('security') || normalized.includes('sec')) return 'security';
  if (normalized.includes('performance') || normalized.includes('perf') || normalized.includes('load')) return 'performance';
  if (normalized.includes('api') || normalized.includes('integration')) return 'api';

  return 'functional';
}

/**
 * Normalize priority string
 */
function normalizePriority(priority: string): GeneratedTestCase['priority'] {
  const normalized = (priority || '').toLowerCase();

  if (normalized.includes('critical') || normalized.includes('p0')) return 'critical';
  if (normalized.includes('high') || normalized.includes('p1')) return 'high';
  if (normalized.includes('low') || normalized.includes('p3')) return 'low';

  return 'medium';
}
