/**
 * Template Engine
 * Generates test case output in various formats (JSON, Markdown, Gherkin, JUnit XML, etc.)
 */

import { createLogger } from '../../../utils/logger.js';
import type {
  GeneratedTestCase,
} from '../types.js';
import { getCategoryObject } from '../types.js';
import type { CorrelationResult } from './correlation-engine.js';
import type { AlignmentResult } from './brd-alignment.js';

const logger = createLogger('template-engine');

export type OutputFormat = 'json' | 'markdown' | 'gherkin' | 'junit' | 'csv' | 'html';

export interface TemplateOptions {
  format: OutputFormat;
  includeMetadata?: boolean;
  includeSteps?: boolean;
  groupBy?: 'category' | 'priority' | 'type' | 'endpoint' | 'requirement';
  maxTestCases?: number;
  customTemplate?: string;
}

export interface TemplateResult {
  format: OutputFormat;
  content: string;
  filename: string;
  mimeType: string;
  testCaseCount: number;
}

/**
 * Generate test output in the specified format
 */
export function generateOutput(
  testCases: GeneratedTestCase[],
  options: TemplateOptions
): TemplateResult {
  logger.info(
    { format: options.format, testCaseCount: testCases.length },
    'Generating test output'
  );

  const startTime = Date.now();

  // Apply max limit if specified
  const limitedTestCases = options.maxTestCases
    ? testCases.slice(0, options.maxTestCases)
    : testCases;

  let content: string;
  let filename: string;
  let mimeType: string;

  switch (options.format) {
    case 'json':
      content = generateJsonOutput(limitedTestCases, options);
      filename = 'test-cases.json';
      mimeType = 'application/json';
      break;

    case 'markdown':
      content = generateMarkdownOutput(limitedTestCases, options);
      filename = 'test-cases.md';
      mimeType = 'text/markdown';
      break;

    case 'gherkin':
      content = generateGherkinOutput(limitedTestCases, options);
      filename = 'test-cases.feature';
      mimeType = 'text/plain';
      break;

    case 'junit':
      content = generateJUnitOutput(limitedTestCases, options);
      filename = 'test-cases.xml';
      mimeType = 'application/xml';
      break;

    case 'csv':
      content = generateCsvOutput(limitedTestCases, options);
      filename = 'test-cases.csv';
      mimeType = 'text/csv';
      break;

    case 'html':
      content = generateHtmlOutput(limitedTestCases, options);
      filename = 'test-cases.html';
      mimeType = 'text/html';
      break;

    default:
      throw new Error(`Unsupported output format: ${options.format}`);
  }

  logger.info(
    {
      format: options.format,
      contentLength: content.length,
      testCaseCount: limitedTestCases.length,
      durationMs: Date.now() - startTime,
    },
    'Test output generated'
  );

  return {
    format: options.format,
    content,
    filename,
    mimeType,
    testCaseCount: limitedTestCases.length,
  };
}

/**
 * Generate JSON output
 */
function generateJsonOutput(
  testCases: GeneratedTestCase[],
  options: TemplateOptions
): string {
  const output = {
    generated: new Date().toISOString(),
    testCaseCount: testCases.length,
    testCases: testCases.map(tc => ({
      id: tc.id,
      name: tc.name,
      description: tc.description,
      type: tc.type,
      priority: tc.priority,
      category: tc.category,
      ...(options.includeSteps !== false && { steps: tc.steps }),
      expectedResult: tc.expectedResult,
      ...(tc.targetEndpoint && { targetEndpoint: tc.targetEndpoint }),
      ...(tc.brdRequirementId && { brdRequirementId: tc.brdRequirementId }),
      ...(options.includeMetadata !== false && tc.metadata && { metadata: tc.metadata }),
    })),
  };

  return JSON.stringify(output, null, 2);
}

/**
 * Generate Markdown output
 */
function generateMarkdownOutput(
  testCases: GeneratedTestCase[],
  options: TemplateOptions
): string {
  const lines: string[] = [];

  lines.push('# Generated Test Cases');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`Total Test Cases: ${testCases.length}`);
  lines.push('');

  // Group test cases if specified
  const grouped = groupTestCases(testCases, options.groupBy || 'type');

  for (const [groupName, groupTests] of Object.entries(grouped)) {
    lines.push(`## ${formatGroupName(groupName)}`);
    lines.push('');

    for (const tc of groupTests) {
      lines.push(`### ${tc.name}`);
      lines.push('');
      lines.push(`**ID:** ${tc.id}`);
      lines.push(`**Type:** ${tc.type}`);
      lines.push(`**Priority:** ${tc.priority}`);
      lines.push('');
      lines.push(`**Description:** ${tc.description}`);
      lines.push('');

      if (tc.targetEndpoint) {
        lines.push(`**Target Endpoint:** ${tc.targetEndpoint.method} ${tc.targetEndpoint.path}`);
        lines.push('');
      }

      const cat = getCategoryObject(tc.category);
      if (cat.owasp) {
        lines.push(`**OWASP Category:** ${cat.owasp}`);
      }
      if (cat.cwe && cat.cwe.length > 0) {
        lines.push(`**CWE:** ${cat.cwe.join(', ')}`);
      }
      if (tc.brdRequirementId) {
        lines.push(`**BRD Requirement:** ${tc.brdRequirementId}`);
      }
      lines.push('');

      if (options.includeSteps !== false && tc.steps.length > 0) {
        lines.push('**Steps:**');
        for (let i = 0; i < tc.steps.length; i++) {
          lines.push(`${i + 1}. ${tc.steps[i]}`);
        }
        lines.push('');
      }

      lines.push(`**Expected Result:** ${tc.expectedResult}`);
      lines.push('');
      lines.push('---');
      lines.push('');
    }
  }

  return lines.join('\n');
}

/**
 * Generate Gherkin/Cucumber output
 */
function generateGherkinOutput(
  testCases: GeneratedTestCase[],
  _options: TemplateOptions
): string {
  const lines: string[] = [];

  lines.push('# Generated Test Cases');
  lines.push(`# Generated: ${new Date().toISOString()}`);
  lines.push('');

  // Group by type for features
  const grouped = groupTestCases(testCases, 'type');

  for (const [typeName, typeTests] of Object.entries(grouped)) {
    lines.push(`Feature: ${formatGroupName(typeName)} Tests`);
    lines.push(`  As a quality assurance engineer`);
    lines.push(`  I want to verify ${typeName} requirements`);
    lines.push(`  So that the application is secure and functional`);
    lines.push('');

    for (const tc of typeTests) {
      const tcCat = getCategoryObject(tc.category);
      lines.push(`  @${tc.type} @${tc.priority}`);
      if (tcCat.owasp) {
        lines.push(`  @${tcCat.owasp.replace(':', '_')}`);
      }
      if (tcCat.cwe) {
        for (const cwe of tcCat.cwe) {
          lines.push(`  @${cwe}`);
        }
      }
      lines.push(`  Scenario: ${tc.name}`);

      // Convert steps to Given/When/Then
      const gherkinSteps = convertToGherkinSteps(tc.steps);
      for (const step of gherkinSteps) {
        lines.push(`    ${step}`);
      }

      lines.push(`    Then ${tc.expectedResult}`);
      lines.push('');
    }

    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Convert test steps to Gherkin format
 */
function convertToGherkinSteps(steps: string[]): string[] {
  const gherkinSteps: string[] = [];

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];

    if (i === 0) {
      gherkinSteps.push(`Given ${step}`);
    } else if (i === steps.length - 1) {
      gherkinSteps.push(`When ${step}`);
    } else {
      gherkinSteps.push(`And ${step}`);
    }
  }

  return gherkinSteps;
}

/**
 * Generate JUnit XML output
 */
function generateJUnitOutput(
  testCases: GeneratedTestCase[],
  _options: TemplateOptions
): string {
  const lines: string[] = [];

  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(`<testsuites name="Generated Test Cases" tests="${testCases.length}" timestamp="${new Date().toISOString()}">`);

  // Group by type for test suites
  const grouped = groupTestCases(testCases, 'type');

  for (const [typeName, typeTests] of Object.entries(grouped)) {
    lines.push(`  <testsuite name="${escapeXml(formatGroupName(typeName))}" tests="${typeTests.length}">`);

    for (const tc of typeTests) {
      const tcCat = getCategoryObject(tc.category);
      const classname = tcCat.primary || tc.type;
      lines.push(`    <testcase name="${escapeXml(tc.name)}" classname="${escapeXml(classname)}">`);

      // Add properties
      lines.push('      <properties>');
      lines.push(`        <property name="id" value="${escapeXml(tc.id)}"/>`);
      lines.push(`        <property name="priority" value="${tc.priority}"/>`);
      lines.push(`        <property name="type" value="${tc.type}"/>`);
      if (tcCat.owasp) {
        lines.push(`        <property name="owasp" value="${escapeXml(tcCat.owasp)}"/>`);
      }
      if (tcCat.cwe && tcCat.cwe.length > 0) {
        lines.push(`        <property name="cwe" value="${escapeXml(tcCat.cwe.join(','))}"/>`);
      }
      if (tc.brdRequirementId) {
        lines.push(`        <property name="brd_requirement" value="${escapeXml(tc.brdRequirementId)}"/>`);
      }
      lines.push('      </properties>');

      // Add system-out with steps
      lines.push('      <system-out><![CDATA[');
      lines.push(`Description: ${tc.description}`);
      lines.push('');
      lines.push('Steps:');
      for (let i = 0; i < tc.steps.length; i++) {
        lines.push(`${i + 1}. ${tc.steps[i]}`);
      }
      lines.push('');
      lines.push(`Expected Result: ${tc.expectedResult}`);
      lines.push(']]></system-out>');

      lines.push('    </testcase>');
    }

    lines.push('  </testsuite>');
  }

  lines.push('</testsuites>');

  return lines.join('\n');
}

/**
 * Generate CSV output
 */
function generateCsvOutput(
  testCases: GeneratedTestCase[],
  _options: TemplateOptions
): string {
  const lines: string[] = [];

  // Header
  lines.push('ID,Name,Type,Priority,OWASP,CWE,BRD Requirement,Description,Steps,Expected Result,Endpoint');

  for (const tc of testCases) {
    const tcCat = getCategoryObject(tc.category);
    const row = [
      escapeCsv(tc.id),
      escapeCsv(tc.name),
      escapeCsv(tc.type),
      escapeCsv(tc.priority),
      escapeCsv(tcCat.owasp || ''),
      escapeCsv(tcCat.cwe?.join(';') || ''),
      escapeCsv(tc.brdRequirementId || ''),
      escapeCsv(tc.description),
      escapeCsv(tc.steps.join('; ')),
      escapeCsv(tc.expectedResult),
      escapeCsv(tc.targetEndpoint ? `${tc.targetEndpoint.method} ${tc.targetEndpoint.path}` : ''),
    ];
    lines.push(row.join(','));
  }

  return lines.join('\n');
}

/**
 * Generate HTML output
 */
function generateHtmlOutput(
  testCases: GeneratedTestCase[],
  options: TemplateOptions
): string {
  const grouped = groupTestCases(testCases, options.groupBy || 'type');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Generated Test Cases</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
    h2 { color: #555; margin-top: 30px; }
    .summary { background: #fff; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .test-case { background: #fff; padding: 20px; margin-bottom: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .test-case h3 { margin-top: 0; color: #333; }
    .meta { display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 15px; }
    .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
    .badge-security { background: #dc3545; color: white; }
    .badge-functional { background: #28a745; color: white; }
    .badge-api { background: #17a2b8; color: white; }
    .badge-performance { background: #ffc107; color: black; }
    .badge-critical { background: #dc3545; color: white; }
    .badge-high { background: #fd7e14; color: white; }
    .badge-medium { background: #ffc107; color: black; }
    .badge-low { background: #6c757d; color: white; }
    .steps { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 10px 0; }
    .steps ol { margin: 0; padding-left: 20px; }
    .expected { font-style: italic; color: #28a745; }
    .category { font-size: 12px; color: #666; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background: #f8f9fa; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Generated Test Cases</h1>

    <div class="summary">
      <p><strong>Generated:</strong> ${new Date().toISOString()}</p>
      <p><strong>Total Test Cases:</strong> ${testCases.length}</p>
      <p><strong>By Type:</strong> ${Object.entries(grouped).map(([k, v]) => `${formatGroupName(k)}: ${v.length}`).join(', ')}</p>
    </div>

    ${Object.entries(grouped).map(([groupName, groupTests]) => `
    <h2>${formatGroupName(groupName)}</h2>
    ${groupTests.map(tc => {
      const tcCat = getCategoryObject(tc.category);
      return `
    <div class="test-case">
      <h3>${escapeHtml(tc.name)}</h3>
      <div class="meta">
        <span class="badge badge-${tc.type}">${tc.type}</span>
        <span class="badge badge-${tc.priority}">${tc.priority}</span>
        ${tcCat.owasp ? `<span class="category">OWASP: ${tcCat.owasp}</span>` : ''}
        ${tcCat.cwe?.length ? `<span class="category">CWE: ${tcCat.cwe.join(', ')}</span>` : ''}
      </div>
      <p><strong>ID:</strong> ${escapeHtml(tc.id)}</p>
      <p>${escapeHtml(tc.description)}</p>
      ${tc.targetEndpoint ? `<p><strong>Endpoint:</strong> ${escapeHtml(tc.targetEndpoint.method || '')} ${escapeHtml(tc.targetEndpoint.path || '')}</p>` : ''}
      <div class="steps">
        <strong>Steps:</strong>
        <ol>
          ${tc.steps.map(step => `<li>${escapeHtml(step)}</li>`).join('')}
        </ol>
      </div>
      <p class="expected"><strong>Expected:</strong> ${escapeHtml(tc.expectedResult)}</p>
    </div>
    `;
    }).join('')}
    `).join('')}
  </div>
</body>
</html>`;

  return html;
}

/**
 * Generate coverage report output
 */
export function generateCoverageReport(
  correlationResult: CorrelationResult,
  alignmentResult: AlignmentResult,
  format: OutputFormat
): TemplateResult {
  const reportData = {
    generated: new Date().toISOString(),
    summary: {
      totalFindings: correlationResult.summary.totalFindings,
      owaspCoverage: correlationResult.summary.owaspCoverage,
      cweCoverage: correlationResult.summary.cweCoverage,
      brdCoverage: correlationResult.summary.brdCoverage,
      overallCoverage: alignmentResult.overallCoverage.coveragePercentage,
    },
    recommendations: [
      ...correlationResult.recommendations,
      ...alignmentResult.recommendations,
    ],
    coverageMatrix: correlationResult.coverageMatrix,
    alignments: alignmentResult.alignments.map(a => ({
      requirementId: a.requirementId,
      title: a.requirement.title,
      coverageScore: a.coverageScore,
      testCount: a.alignedTestCases.length,
      gaps: a.gaps,
    })),
  };

  if (format === 'json') {
    return {
      format,
      content: JSON.stringify(reportData, null, 2),
      filename: 'coverage-report.json',
      mimeType: 'application/json',
      testCaseCount: 0,
    };
  }

  // Default to markdown
  const lines: string[] = [];
  lines.push('# Test Coverage Report');
  lines.push('');
  lines.push(`Generated: ${reportData.generated}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push(`- **Total Findings:** ${reportData.summary.totalFindings}`);
  lines.push(`- **OWASP Coverage:** ${reportData.summary.owaspCoverage}%`);
  lines.push(`- **CWE Coverage:** ${reportData.summary.cweCoverage}%`);
  lines.push(`- **BRD Coverage:** ${reportData.summary.brdCoverage}%`);
  lines.push(`- **Overall Coverage:** ${reportData.summary.overallCoverage}%`);
  lines.push('');
  lines.push('## Recommendations');
  lines.push('');
  for (const rec of reportData.recommendations) {
    lines.push(`- ${rec}`);
  }
  lines.push('');
  lines.push('## Requirement Coverage');
  lines.push('');
  lines.push('| Requirement | Coverage | Tests | Gaps |');
  lines.push('|-------------|----------|-------|------|');
  for (const a of reportData.alignments) {
    lines.push(`| ${a.requirementId} | ${a.coverageScore}% | ${a.testCount} | ${a.gaps.length} |`);
  }

  return {
    format: 'markdown',
    content: lines.join('\n'),
    filename: 'coverage-report.md',
    mimeType: 'text/markdown',
    testCaseCount: 0,
  };
}

/**
 * Group test cases by a specific field
 */
function groupTestCases(
  testCases: GeneratedTestCase[],
  groupBy: string
): Record<string, GeneratedTestCase[]> {
  const groups: Record<string, GeneratedTestCase[]> = {};

  for (const tc of testCases) {
    let key: string;
    const tcCat = getCategoryObject(tc.category);

    switch (groupBy) {
      case 'category':
        key = tcCat.primary || tcCat.owasp || 'other';
        break;
      case 'priority':
        key = tc.priority;
        break;
      case 'type':
        key = tc.type;
        break;
      case 'endpoint':
        key = tc.targetEndpoint ? `${tc.targetEndpoint.method} ${tc.targetEndpoint.path}` : 'general';
        break;
      case 'requirement':
        key = tc.brdRequirementId || 'unmapped';
        break;
      default:
        key = tc.type;
    }

    if (!groups[key]) {
      groups[key] = [];
    }
    groups[key].push(tc);
  }

  return groups;
}

/**
 * Format group name for display
 */
function formatGroupName(name: string): string {
  return name
    .replace(/-/g, ' ')
    .replace(/_/g, ' ')
    .split(' ')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

/**
 * Escape XML special characters
 */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Escape CSV field
 */
function escapeCsv(str: string): string {
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
