/**
 * CA-009: Code Summary Generation
 * Generates comprehensive summaries of code analysis
 */

import { createLogger } from '../../../utils/logger.js';
import type {
  CodeSummary,
  SecurityConcern,
  ExtractedEndpoint,
  AuthPattern,
  DataFlow,
  SensitiveDataPoint,
  Dependency,
  InfrastructureFile,
  CodeAnalysisResult,
} from '../types.js';

const logger = createLogger('summary-generator');

/**
 * Determine complexity based on analysis metrics
 */
function determineComplexity(
  totalFiles: number,
  totalLinesOfCode: number,
  endpointCount: number,
  languageCount: number,
  frameworkCount: number
): CodeSummary['complexity'] {
  // Scoring system for complexity
  let score = 0;

  // File count factor
  if (totalFiles > 500) score += 3;
  else if (totalFiles > 100) score += 2;
  else if (totalFiles > 50) score += 1;

  // Lines of code factor
  if (totalLinesOfCode > 100000) score += 3;
  else if (totalLinesOfCode > 20000) score += 2;
  else if (totalLinesOfCode > 5000) score += 1;

  // Endpoint count factor
  if (endpointCount > 50) score += 2;
  else if (endpointCount > 20) score += 1;

  // Language diversity factor
  if (languageCount > 5) score += 2;
  else if (languageCount > 2) score += 1;

  // Framework diversity factor
  if (frameworkCount > 3) score += 2;
  else if (frameworkCount > 1) score += 1;

  if (score >= 7) return 'complex';
  if (score >= 3) return 'moderate';
  return 'simple';
}

/**
 * Identify entry points from endpoints and infrastructure
 */
function identifyEntryPoints(
  endpoints: ExtractedEndpoint[],
  infrastructure: InfrastructureFile[]
): string[] {
  const entryPoints: Set<string> = new Set();

  // Add main route files
  const routeFiles = new Set(endpoints.map(e => e.file));
  for (const file of routeFiles) {
    if (
      file.includes('route') ||
      file.includes('controller') ||
      file.includes('handler') ||
      file.includes('api')
    ) {
      entryPoints.add(file);
    }
  }

  // Add infrastructure entry points
  for (const infra of infrastructure) {
    if (
      infra.type === 'dockerfile' ||
      infra.type === 'docker-compose' ||
      infra.type === 'github-actions'
    ) {
      entryPoints.add(infra.path);
    }
  }

  // Common entry point files
  const commonEntryPoints = [
    'index.ts', 'index.js', 'main.ts', 'main.js', 'app.ts', 'app.js',
    'server.ts', 'server.js', 'main.py', 'app.py', '__main__.py',
    'main.go', 'cmd/main.go', 'Application.java', 'main.rs',
  ];

  for (const endpoint of endpoints) {
    const filename = endpoint.file.split('/').pop() || '';
    if (commonEntryPoints.includes(filename)) {
      entryPoints.add(endpoint.file);
    }
  }

  return Array.from(entryPoints).slice(0, 10); // Limit to 10 entry points
}

/**
 * Aggregate security concerns from all analysis components
 */
function aggregateSecurityConcerns(
  authPatterns: AuthPattern[],
  dataFlows: DataFlow[],
  sensitiveData: SensitiveDataPoint[],
  dependencies: Dependency[],
  infrastructure: InfrastructureFile[]
): SecurityConcern[] {
  const concerns: SecurityConcern[] = [];

  // Auth-related concerns
  const authWithConcerns = authPatterns.filter(
    a => a.securityConcerns && a.securityConcerns.length > 0
  );
  for (const auth of authWithConcerns) {
    for (const concern of auth.securityConcerns || []) {
      concerns.push({
        concern: `Authentication: ${concern}`,
        severity: 'high',
        location: auth.file,
        recommendation: 'Review authentication implementation',
      });
    }
  }

  // Check for missing auth
  if (authPatterns.length === 0) {
    concerns.push({
      concern: 'No authentication mechanism detected',
      severity: 'high',
      recommendation: 'Implement authentication for protected endpoints',
    });
  }

  // Data flow concerns
  const criticalFlows = dataFlows.filter(f => f.riskLevel === 'critical');
  const highRiskFlows = dataFlows.filter(f => f.riskLevel === 'high');

  if (criticalFlows.length > 0) {
    concerns.push({
      concern: `${criticalFlows.length} critical data flow vulnerability(s) found`,
      severity: 'critical',
      location: criticalFlows[0].source.location,
      recommendation: 'Review and sanitize all user inputs before use in sensitive operations',
    });
  }

  if (highRiskFlows.length > 0) {
    concerns.push({
      concern: `${highRiskFlows.length} high-risk data flow(s) found`,
      severity: 'high',
      location: highRiskFlows[0].source.location,
      recommendation: 'Implement input validation and output encoding',
    });
  }

  // Tainted data flows
  const taintedFlows = dataFlows.filter(f => f.tainted);
  if (taintedFlows.length > 0) {
    concerns.push({
      concern: `${taintedFlows.length} tainted data flow(s) without sanitization`,
      severity: 'high',
      recommendation: 'Add sanitization for all user input paths',
    });
  }

  // Sensitive data concerns
  const unprotectedSensitive = sensitiveData.filter(s => !s.encrypted && !s.masked);
  const criticalSensitive = unprotectedSensitive.filter(s => s.riskLevel === 'critical');

  if (criticalSensitive.length > 0) {
    concerns.push({
      concern: `${criticalSensitive.length} unprotected critical sensitive data field(s)`,
      severity: 'critical',
      location: criticalSensitive[0].file,
      recommendation: 'Encrypt or mask all sensitive data',
    });
  }

  const credentials = sensitiveData.filter(s => s.type === 'credential' && !s.encrypted);
  if (credentials.length > 0) {
    concerns.push({
      concern: `${credentials.length} potential credential(s) found in code`,
      severity: 'critical',
      location: credentials[0].file,
      recommendation: 'Use environment variables or secret management for credentials',
    });
  }

  // Dependency concerns
  const vulnDeps = dependencies.filter(d => d.hasKnownVulnerabilities);
  if (vulnDeps.length > 0) {
    concerns.push({
      concern: `${vulnDeps.length} dependency(s) with known vulnerabilities`,
      severity: 'high',
      recommendation: 'Update vulnerable dependencies to patched versions',
    });
  }

  // Infrastructure concerns
  const infraWithConcerns = infrastructure.filter(
    i => i.securityConcerns && i.securityConcerns.length > 0
  );
  for (const infra of infraWithConcerns) {
    for (const concern of infra.securityConcerns || []) {
      concerns.push({
        concern: `Infrastructure (${infra.type}): ${concern}`,
        severity: infra.type === 'dockerfile' || infra.type === 'kubernetes' ? 'high' : 'medium',
        location: infra.path,
        recommendation: 'Review infrastructure security configuration',
      });
    }
  }

  // Deduplicate and sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const uniqueConcerns = concerns.filter(
    (concern, index, self) =>
      index === self.findIndex(c => c.concern === concern.concern && c.location === concern.location)
  );

  uniqueConcerns.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return uniqueConcerns;
}

/**
 * Generate code summary from analysis result
 */
export function generateSummary(
  result: Partial<CodeAnalysisResult>
): CodeSummary {
  logger.info('Generating code summary');

  const startTime = Date.now();

  const languages = result.languages || [];
  const frameworks = result.frameworks || [];
  const endpoints = result.endpoints || [];
  const authPatterns = result.authPatterns || [];
  const dataFlows = result.dataFlows || [];
  const sensitiveData = result.sensitiveData || [];
  const dependencies = result.dependencies || [];
  const infrastructure = result.infrastructure || [];

  // Calculate totals
  const totalFiles = languages.reduce((sum, l) => sum + l.fileCount, 0);
  const totalLinesOfCode = languages.reduce((sum, l) => sum + l.linesOfCode, 0);

  // Determine complexity
  const complexity = determineComplexity(
    totalFiles,
    totalLinesOfCode,
    endpoints.length,
    languages.length,
    frameworks.length
  );

  // Identify entry points
  const entryPoints = identifyEntryPoints(endpoints, infrastructure);

  // Aggregate security concerns
  const securityConcerns = aggregateSecurityConcerns(
    authPatterns,
    dataFlows,
    sensitiveData,
    dependencies,
    infrastructure
  );

  const summary: CodeSummary = {
    totalFiles,
    totalLinesOfCode,
    languages,
    frameworks,
    entryPoints,
    securityConcerns,
    complexity,
  };

  logger.info(
    {
      totalFiles,
      totalLinesOfCode,
      languageCount: languages.length,
      frameworkCount: frameworks.length,
      endpointCount: endpoints.length,
      securityConcernCount: securityConcerns.length,
      complexity,
      durationMs: Date.now() - startTime,
    },
    'Code summary generated'
  );

  return summary;
}

/**
 * Get summary statistics
 */
export function getSummaryStats(summary: CodeSummary): {
  totalFiles: number;
  totalLinesOfCode: number;
  languageCount: number;
  frameworkCount: number;
  entryPointCount: number;
  securityConcernCount: number;
  criticalConcerns: number;
  highConcerns: number;
  complexity: string;
} {
  return {
    totalFiles: summary.totalFiles,
    totalLinesOfCode: summary.totalLinesOfCode,
    languageCount: summary.languages.length,
    frameworkCount: summary.frameworks.length,
    entryPointCount: summary.entryPoints.length,
    securityConcernCount: summary.securityConcerns.length,
    criticalConcerns: summary.securityConcerns.filter(c => c.severity === 'critical').length,
    highConcerns: summary.securityConcerns.filter(c => c.severity === 'high').length,
    complexity: summary.complexity,
  };
}

/**
 * Get critical security concerns
 */
export function getCriticalConcerns(summary: CodeSummary): SecurityConcern[] {
  return summary.securityConcerns.filter(c => c.severity === 'critical');
}

/**
 * Get high severity concerns
 */
export function getHighSeverityConcerns(summary: CodeSummary): SecurityConcern[] {
  return summary.securityConcerns.filter(
    c => c.severity === 'critical' || c.severity === 'high'
  );
}

/**
 * Calculate security score (0-100)
 */
export function calculateSecurityScore(summary: CodeSummary): number {
  let score = 100;

  // Deduct for security concerns
  for (const concern of summary.securityConcerns) {
    switch (concern.severity) {
      case 'critical':
        score -= 20;
        break;
      case 'high':
        score -= 10;
        break;
      case 'medium':
        score -= 5;
        break;
      case 'low':
        score -= 2;
        break;
    }
  }

  return Math.max(0, Math.min(100, score));
}

/**
 * Generate a brief text summary
 */
export function generateTextSummary(summary: CodeSummary): string {
  const stats = getSummaryStats(summary);
  const score = calculateSecurityScore(summary);

  const lines = [
    `Code Analysis Summary`,
    `=====================`,
    ``,
    `Project Size: ${stats.totalFiles} files, ${stats.totalLinesOfCode.toLocaleString()} lines of code`,
    `Complexity: ${stats.complexity}`,
    ``,
    `Languages (${stats.languageCount}):`,
    ...summary.languages.slice(0, 5).map(l => `  - ${l.language}: ${l.percentage.toFixed(1)}%`),
    ``,
    `Frameworks (${stats.frameworkCount}):`,
    ...summary.frameworks.slice(0, 5).map(f => `  - ${f.framework} (${f.type})`),
    ``,
    `Security Score: ${score}/100`,
    `Security Concerns: ${stats.securityConcernCount} (${stats.criticalConcerns} critical, ${stats.highConcerns} high)`,
    ``,
  ];

  if (stats.criticalConcerns > 0) {
    lines.push(`Critical Issues:`);
    for (const concern of getCriticalConcerns(summary).slice(0, 5)) {
      lines.push(`  - ${concern.concern}`);
    }
  }

  return lines.join('\n');
}
