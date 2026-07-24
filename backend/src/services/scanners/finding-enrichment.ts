/**
 * Finding Enrichment Pipeline
 *
 * Cross-references scanner findings against code analysis results to:
 *   1. Match findings against CA-005 dataflow analysis (sanitized/unsanitized)
 *   2. Compute exploitability scores (confirmed/likely/theoretical/unlikely)
 *   3. Combine reachability, dataflow, and auth context into a single verdict
 *
 * Each finding gets an EnrichmentResult that drives:
 *   - Auto-suppression of confirmed false positives (sanitized dataflows)
 *   - Exploitability badge in the dashboard
 *   - Risk score bonus for clean exploitability profiles
 */

import type { NormalizedFinding } from '../../types/index.js';
import type { CodeAnalysisResult, DataFlow, AuthPattern, ExtractedEndpoint } from '../test-generator/types.js';
import { isReachable, getEntryPoint, type ReachabilityResult } from './reachability.js';

export type Exploitability = 'confirmed' | 'likely' | 'theoretical' | 'unlikely';
export type DataflowMatch = 'confirmed' | 'sanitized' | 'no_match';

export interface EnrichmentResult {
  reachable: boolean;
  reachableFrom?: string;
  dataflowMatch: DataflowMatch;
  sanitizationEvidence?: string;
  exploitability: Exploitability;
  suppressAsFramework: boolean;
  suppressionReason?: string;
}

/**
 * Line proximity threshold for matching findings to dataflow sinks.
 * A finding at line 42 will match a dataflow sink at lines 37-47.
 */
const LINE_PROXIMITY = 5;

/**
 * Find dataflows whose sink location matches a finding's file and line.
 */
function findMatchingDataflows(
  finding: NormalizedFinding,
  dataFlows: DataFlow[],
): DataFlow[] {
  if (!finding.filePath || !finding.lineNumber) return [];

  // Normalize file path for comparison
  const findingFile = finding.filePath.replace(/^\//, '').replace(/^scan-target\//, '');

  return dataFlows.filter(flow => {
    const sinkFile = flow.sink.location.replace(/^\//, '').replace(/^scan-target\//, '');

    // File must match
    if (sinkFile !== findingFile && !findingFile.endsWith(sinkFile) && !sinkFile.endsWith(findingFile)) {
      return false;
    }

    // Line must be within proximity
    const lineDiff = Math.abs(flow.sink.line - finding.lineNumber!);
    return lineDiff <= LINE_PROXIMITY;
  });
}

/**
 * Determine dataflow match status for a finding.
 */
function matchDataflow(
  finding: NormalizedFinding,
  dataFlows: DataFlow[],
): { match: DataflowMatch; evidence?: string } {
  const matches = findMatchingDataflows(finding, dataFlows);

  if (matches.length === 0) {
    return { match: 'no_match' };
  }

  // Check if ANY matching dataflow shows sanitization
  const sanitizedFlow = matches.find(f => f.sanitized);
  if (sanitizedFlow) {
    const evidence = `Dataflow from ${sanitizedFlow.source.type} at ${sanitizedFlow.source.location}:${sanitizedFlow.source.line} passes through sanitization before reaching sink at line ${sanitizedFlow.sink.line}`;
    return { match: 'sanitized', evidence };
  }

  // Unsanitized tainted flow confirms the finding
  const taintedFlow = matches.find(f => f.tainted && !f.sanitized);
  if (taintedFlow) {
    return { match: 'confirmed' };
  }

  // Has matching flows but not clearly tainted or sanitized
  return { match: 'no_match' };
}

/**
 * Check if a finding's file is behind authentication.
 */
function isBehindAuth(
  finding: NormalizedFinding,
  authPatterns: AuthPattern[],
  endpoints: ExtractedEndpoint[],
): boolean {
  if (!finding.filePath) return false;

  const findingFile = finding.filePath.replace(/^\//, '').replace(/^scan-target\//, '');

  // Check if the file has auth patterns
  const hasAuthInFile = authPatterns.some(ap => {
    const authFile = ap.file.replace(/^\//, '').replace(/^scan-target\//, '');
    return authFile === findingFile || findingFile.endsWith(authFile) || authFile.endsWith(findingFile);
  });

  if (hasAuthInFile) return true;

  // Check if endpoints in this file have authentication middleware
  const fileEndpoints = endpoints.filter(ep => {
    const epFile = ep.file.replace(/^\//, '').replace(/^scan-target\//, '');
    return epFile === findingFile || findingFile.endsWith(epFile) || epFile.endsWith(findingFile);
  });

  return fileEndpoints.some(ep =>
    ep.authentication || ep.auth ||
    ep.middleware?.some(m => /auth|jwt|session|token|bearer/i.test(m))
  );
}

/**
 * Check if a finding's file is exposed via an external endpoint.
 */
function isExternallyAccessible(
  finding: NormalizedFinding,
  endpoints: ExtractedEndpoint[],
): boolean {
  if (!finding.filePath) return false;

  const findingFile = finding.filePath.replace(/^\//, '').replace(/^scan-target\//, '');

  return endpoints.some(ep => {
    const epFile = ep.file.replace(/^\//, '').replace(/^scan-target\//, '');
    return epFile === findingFile || findingFile.endsWith(epFile) || epFile.endsWith(findingFile);
  });
}

/**
 * Calculate exploitability classification for a finding.
 *
 * Matrix:
 *   confirmed:   reachable + unsanitized dataflow + externally accessible
 *   likely:      reachable + no sanitization + external endpoint
 *                OR reachable + unsanitized + auth-protected
 *   theoretical: reachable but sanitized OR reachable with no dataflow match
 *   unlikely:    unreachable OR sanitized + behind auth
 */
function calculateExploitability(
  reachable: boolean,
  dataflowMatch: DataflowMatch,
  behindAuth: boolean,
  externallyAccessible: boolean,
): Exploitability {
  if (!reachable) {
    return 'unlikely';
  }

  if (dataflowMatch === 'sanitized' && behindAuth) {
    return 'unlikely';
  }

  if (dataflowMatch === 'sanitized') {
    return 'theoretical';
  }

  if (dataflowMatch === 'confirmed' && externallyAccessible && !behindAuth) {
    return 'confirmed';
  }

  if (dataflowMatch === 'confirmed' && externallyAccessible && behindAuth) {
    return 'likely';
  }

  if (dataflowMatch === 'confirmed') {
    return 'likely';
  }

  // no_match — finding exists but no dataflow data to confirm/deny
  if (externallyAccessible && !behindAuth) {
    return 'likely';
  }

  return 'theoretical';
}

/**
 * Enrich a single finding with code analysis context.
 */
export function enrichFinding(
  finding: NormalizedFinding,
  _scanner: string,
  codeAnalysis: CodeAnalysisResult,
  reachability: ReachabilityResult,
): EnrichmentResult {
  // 1. Reachability check
  const reachable = isReachable(finding.filePath, reachability);
  const reachableFrom = getEntryPoint(finding.filePath, reachability) || undefined;

  // 2. Dataflow matching
  const { match: dataflowMatch, evidence: sanitizationEvidence } = matchDataflow(
    finding,
    codeAnalysis.dataFlows,
  );

  // 3. Auth and external access checks
  const behindAuth = isBehindAuth(finding, codeAnalysis.authPatterns, codeAnalysis.endpoints);
  const externallyAccessible = isExternallyAccessible(finding, codeAnalysis.endpoints);

  // 4. Exploitability scoring
  const exploitability = calculateExploitability(reachable, dataflowMatch, behindAuth, externallyAccessible);

  return {
    reachable,
    reachableFrom,
    dataflowMatch,
    sanitizationEvidence,
    exploitability,
    suppressAsFramework: false, // Framework suppressions are handled separately
  };
}

/**
 * Determine if a finding should be auto-suppressed based on enrichment.
 *
 * Only auto-suppresses when dataflow analysis CONFIRMS sanitization.
 * Never auto-suppresses on reachability alone (too many false negatives).
 */
export function shouldAutoSuppress(enrichment: EnrichmentResult): {
  suppress: boolean;
  reason?: string;
} {
  if (enrichment.dataflowMatch === 'sanitized') {
    return {
      suppress: true,
      reason: `[Auto] Dataflow analysis confirms input is sanitized: ${enrichment.sanitizationEvidence || 'sanitization detected between source and sink'}`,
    };
  }

  return { suppress: false };
}

/**
 * Check if ALL findings in a scan have low exploitability.
 * Used for the risk score bonus.
 */
export function hasNoConfirmedExploits(
  enrichments: Map<string, EnrichmentResult>,
): boolean {
  for (const enrichment of enrichments.values()) {
    if (enrichment.exploitability === 'confirmed' || enrichment.exploitability === 'likely') {
      return false;
    }
  }
  return enrichments.size > 0; // Must have at least one enriched finding
}
