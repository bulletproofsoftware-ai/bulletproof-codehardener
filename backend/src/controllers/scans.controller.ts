import type { Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendSuccess, sendCreated, sendValidationError } from '../utils/apiResponse.js';
import { NotFoundError } from '../middleware/errorHandler.js';
import { createLogger } from '../utils/logger.js';
import { addScanJob } from '../services/queue/scan.queue.js';
import { buildScanContext } from '../services/scan-context.js';
import { calculateQualityScore } from '../services/assurance/quality-score.js';
import { getScannerAuditMeta } from '../services/scanners/scanner-registry.js';
import { refreshScanFindingsCount } from './findings.controller.js';

const logger = createLogger('scans-controller');

// Transform finding database row to API response format
function transformFinding(row: Record<string, unknown>) {
  const metadata = row.metadata as Record<string, unknown> | null;
  return {
    id: row.id,
    scanId: row.scan_id,
    severity: row.severity,
    title: row.title,
    description: row.description,
    descriptionSimple: row.description_simple || null,
    filePath: row.file_path || '',
    lineNumber: row.line_number || 0,
    columnNumber: row.column_number || 0,
    endLine: row.end_line || null,
    endColumn: row.end_column || null,
    codeSnippet: row.code_snippet || null,
    scanner: row.tool_name || row.scanner || '',
    ruleId: row.rule_id || null,
    status: row.status,
    cwe: row.cwe_id || null,
    owaspCategory: row.owasp_category || null,
    fixAvailable: row.fix_available ?? false,
    fixDescription: row.fix_description || null,
    actionRequired: metadata?.actionRequired || null,
    riskExplanation: metadata?.riskExplanation || null,
    metadata: metadata || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// Transform database row to API response format (camelCase)
function transformScan(row: Record<string, unknown>) {
  // Parse findings_count from JSONB field
  const findingsCount = row.findings_count as Record<string, number> | null;

  // Always recalculate score from findings using the logarithmic algorithm.
  // The scanner worker may store a stale score using a different formula.
  let score: number | null = null;
  let qualityLevel: string | null = null;
  if (findingsCount && (findingsCount.total > 0 || row.status === 'completed')) {
    const result = calculateQualityScore({
      critical: findingsCount.critical ?? 0,
      high: findingsCount.high ?? 0,
      medium: findingsCount.medium ?? 0,
      low: findingsCount.low ?? 0,
      info: findingsCount.info ?? 0,
      total: findingsCount.total ?? 0,
    });
    score = result.score;
    qualityLevel = result.qualityLevel;
  }

  // Map scanners_executed JSONB to scannerResults with audit evidence
  const scannersExecuted = row.scanners_executed as Array<{
    scanner: string;
    success: boolean;
    skipped?: boolean;
    skipReason?: string;
    skipHint?: string;
    findings: number;
    duration: number;
    error?: string | null;
    evidence?: {
      filesAnalyzed?: number;
      rulesEvaluated?: number;
      checksPerformed?: string[];
      scanScope?: string;
      toolVersion?: string;
      detectionMethod?: string;
      configuration?: string;
      targetsAnalyzed?: string[];
      sbomPackages?: Array<{ name: string; version: string; type: string; language: string; license: string }>;
    } | null;
  }> | null;

  // Use live per-scanner open finding counts if available
  const liveScannerCounts = row._live_scanner_counts as Record<string, number> | undefined;
  const hasLiveCounts = liveScannerCounts !== undefined;

  // Extract file inventory pseudo-scanner entry (added by pipeline for audit evidence)
  const inventoryEntry = scannersExecuted?.find(s => s.scanner === '_file_inventory');
  const fileInventory = inventoryEntry ? {
    totalFiles: inventoryEntry.evidence?.filesAnalyzed || 0,
    breakdown: inventoryEntry.evidence?.checksPerformed || [],
    extensions: inventoryEntry.evidence?.targetsAnalyzed || [],
  } : undefined;

  const scannerResults = scannersExecuted && scannersExecuted.length > 0
    ? scannersExecuted.filter(s => !s.scanner.startsWith('_')).map(s => {
        // Merge dynamic evidence with static registry metadata
        const registryMeta = getScannerAuditMeta(s.scanner);
        const evidence = s.evidence || {};

        // Use live count of open findings (0 if not in map = no open findings for this scanner)
        // Only fall back to stale JSONB when live counts weren't queried at all
        const liveCount = hasLiveCounts ? (liveScannerCounts[s.scanner] ?? 0) : (s.findings ?? 0);

        return {
          scanner: s.scanner,
          status: s.skipped ? 'skipped' as const : s.success ? 'success' as const : 'error' as const,
          findingsCount: liveCount,
          duration: s.duration || 0,
          filesScanned: evidence.filesAnalyzed || 0,
          error: s.error || undefined,
          skipReason: s.skipReason || undefined,
          skipHint: s.skipHint || undefined,
          evidence: {
            filesAnalyzed: evidence.filesAnalyzed || 0,
            rulesEvaluated: evidence.rulesEvaluated || undefined,
            checksPerformed: evidence.checksPerformed || registryMeta.checksPerformed,
            scanScope: evidence.scanScope || registryMeta.scanScope,
            toolVersion: evidence.toolVersion || undefined,
            detectionMethod: evidence.detectionMethod || undefined,
            configuration: evidence.configuration || undefined,
            targetsAnalyzed: evidence.targetsAnalyzed || undefined,
            sbomPackages: evidence.sbomPackages || undefined,
            // Static registry metadata for audit context
            methodology: registryMeta.methodology,
            standards: registryMeta.standards,
            displayName: registryMeta.displayName,
            category: registryMeta.category,
          },
        };
      })
    : undefined;

  // Map files_scanned data from subquery (attached by getScan)
  const filesScannedRaw = row.files_scanned as Array<{
    path: string;
    total_findings: number;
    open_findings: number;
    resolved_findings: number;
    scanners: string[];
  }> | null;

  const filesScanned = filesScannedRaw && filesScannedRaw.length > 0
    ? filesScannedRaw.map(f => ({
        path: f.path,
        findingsCount: Number(f.open_findings) || 0,
        totalFindings: Number(f.total_findings) || 0,
        openFindings: Number(f.open_findings) || 0,
        resolvedFindings: Number(f.resolved_findings) || 0,
        scanners: f.scanners || [],
      }))
    : undefined;

  // Map attestation data (attached by getScan)
  const attestationRow = row._attestation as { id: string; created_at: string } | null;
  const attestation = attestationRow
    ? { id: attestationRow.id, createdAt: attestationRow.created_at }
    : undefined;

  return {
    id: row.id,
    projectId: row.project_id,
    projectName: row.project_name || '',
    status: row.status,
    scanType: row.scan_type || row.profile || 'standard',
    score,
    scoreRaw: typeof row.score_raw === 'number' ? row.score_raw : (score ?? null),
    qualityLevel: qualityLevel || null,
    findingsCount: {
      critical: findingsCount?.critical ?? 0,
      high: findingsCount?.high ?? 0,
      medium: findingsCount?.medium ?? 0,
      low: findingsCount?.low ?? 0,
      info: findingsCount?.info ?? 0,
    },
    toolsExecuted: scannerResults?.length ?? (parseInt(row.tools_executed as string) || 0),
    duration: row.duration ?? null,
    branch: row.branch || null,
    commit: row.commit_sha || null,
    triggeredBy: row.trigger_type || null,
    startedAt: row.started_at || null,
    completedAt: row.completed_at || null,
    createdAt: row.created_at,
    findingsSummary: row.findings_summary || null,
    scannerResults,
    filesScanned,
    fileInventory,
    attestation,
    dispositionsSummary: (row._dispositions_summary as {
      skippedScannerCount: number;
      totalDismissed: number;
      byStatus: { false_positive: number; deferred: number; ignored: number; fixed: number };
    } | undefined) ?? undefined,
  };
}

const createScanSchema = z.object({
  projectId: z.string().uuid(),
  // Accept both 'profile' and 'scanType' for flexibility
  profile: z.enum(['auto', 'quick', 'standard', 'comprehensive', 'security', 'api', 'performance', 'frontend', 'supply-chain', 'ai-security', 'full', 'deep']).optional(),
  scanType: z.enum(['auto', 'quick', 'standard', 'comprehensive', 'security', 'api', 'performance', 'frontend', 'supply-chain', 'ai-security', 'full', 'deep']).optional(),
  branch: z.string().optional(),
  // Accept both 'commitSha' and 'commit' for flexibility
  commitSha: z.string().optional(),
  commit: z.string().optional(),
  scanners: z.array(z.string()).optional(),
  targetUrlOverride: z.string().url().optional(),
  containerImageOverride: z.string().optional(),
  openapiSpecOverride: z.string().optional(),
  options: z.object({
    depth: z.enum(['shallow', 'full']).optional(),
    excludePatterns: z.array(z.string()).optional(),
    failThreshold: z.string().optional(),
    timeout: z.number().optional(),
    parallel: z.boolean().optional(),
  }).optional(),
}).transform(data => ({
  ...data,
  // Normalize field names: prefer scanType over profile, commit over commitSha
  profile: data.scanType || data.profile || 'standard',
  commitSha: data.commit || data.commitSha,
}));

export async function listScans(req: Request, res: Response) {
  const querySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    projectId: z.string().uuid().optional(),
    status: z.string().min(1).optional(),
  }).passthrough();
  const { page, limit, projectId, status } = querySchema.parse(req.query);
  const offset = (page - 1) * limit;

  let whereClause = sql`p.user_id = ${req.user!.id}`;

  if (projectId) {
    whereClause = sql`${whereClause} AND s.project_id = ${projectId}`;
  }
  if (status) {
    whereClause = sql`${whereClause} AND s.status = ${status}`;
  }

  const [scans, countResult] = await Promise.all([
    db.execute(sql`
      SELECT s.*, p.name as project_name
      FROM scans s
      JOIN projects p ON p.id = s.project_id
      WHERE ${whereClause}
      ORDER BY s.created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `),
    db.execute(sql`
      SELECT COUNT(*) as count FROM scans s
      JOIN projects p ON p.id = s.project_id
      WHERE ${whereClause}
    `),
  ]);

  const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string);
  const transformedScans = scans.rows.map(row => transformScan(row as Record<string, unknown>));

  return sendSuccess(res, transformedScans, 200, {
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  });
}

export async function getScan(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const [scanResult, filesResult, scannerCountsResult, attestationResult, dispositionCountsResult] = await Promise.all([
    db.execute(sql`
      SELECT s.*, p.name as project_name,
        (SELECT json_agg(json_build_object(
          'id', f.id,
          'severity', f.severity,
          'title', f.title,
          'scanner', COALESCE(f.tool_name, f.scanner),
          'status', f.status
        )) FROM findings f WHERE f.scan_id = s.id AND f.status = 'open') as findings_summary
      FROM scans s
      JOIN projects p ON p.id = s.project_id
      WHERE s.id = ${id} AND p.user_id = ${req.user!.id}
    `),
    db.execute(sql`
      SELECT
        f.file_path as path,
        COUNT(*)::int as total_findings,
        COUNT(*) FILTER (WHERE f.status = 'open')::int as open_findings,
        COUNT(*) FILTER (WHERE f.status IN ('ignored', 'false_positive', 'fixed'))::int as resolved_findings,
        array_agg(DISTINCT COALESCE(f.tool_name, f.scanner)) FILTER (WHERE COALESCE(f.tool_name, f.scanner) IS NOT NULL) as scanners
      FROM findings f
      JOIN scans s ON s.id = f.scan_id
      JOIN projects p ON p.id = s.project_id
      WHERE f.scan_id = ${id} AND p.user_id = ${req.user!.id}
        AND f.file_path IS NOT NULL AND f.file_path != ''
      GROUP BY f.file_path
      ORDER BY COUNT(*) FILTER (WHERE f.status = 'open') DESC, COUNT(*) DESC
      LIMIT 500
    `),
    // Live per-scanner open finding counts
    db.execute(sql`
      SELECT COALESCE(f.tool_name, f.scanner) as scanner_name, COUNT(*)::int as open_count
      FROM findings f
      WHERE f.scan_id = ${id} AND f.status = 'open'
      GROUP BY COALESCE(f.tool_name, f.scanner)
    `),
    // Attestation for this scan
    db.execute(sql`
      SELECT id, created_at FROM attestations WHERE scan_id = ${id} LIMIT 1
    `),
    // Disposition counts: how many findings are dismissed by status, plus skipped scanner count
    db.execute(sql`
      SELECT
        COUNT(*) FILTER (WHERE f.status = 'false_positive')::int AS false_positive,
        COUNT(*) FILTER (WHERE f.status = 'deferred')::int AS deferred,
        COUNT(*) FILTER (WHERE f.status = 'ignored')::int AS ignored,
        COUNT(*) FILTER (WHERE f.status = 'fixed')::int AS fixed
      FROM findings f
      WHERE f.scan_id = ${id}
    `),
  ]);

  if (scanResult.rows.length === 0) {
    throw new NotFoundError('Scan not found');
  }

  // Build scanner -> open count map
  const liveScannerCounts: Record<string, number> = {};
  for (const row of scannerCountsResult.rows as Array<{ scanner_name: string; open_count: number }>) {
    liveScannerCounts[row.scanner_name] = row.open_count;
  }

  const scan = scanResult.rows[0] as Record<string, unknown>;
  // Attach data for transformScan to pick up
  scan.files_scanned = filesResult.rows.length > 0 ? filesResult.rows : null;
  scan._live_scanner_counts = liveScannerCounts;
  scan._attestation = attestationResult.rows.length > 0 ? attestationResult.rows[0] : null;
  // Surface disposition counts so the UI / agents see at a glance how many
  // findings were excluded and via which mechanism. Detail is on /dispositions.
  const dispCounts = (dispositionCountsResult.rows[0] as Record<string, number> | undefined) || {};
  const skippedScannersCount = Array.isArray(scan.scanners_executed)
    ? (scan.scanners_executed as Array<{ scanner: string; skipped?: boolean }>).filter(s => s.skipped && !s.scanner.startsWith('_')).length
    : 0;
  scan._dispositions_summary = {
    skippedScannerCount: skippedScannersCount,
    totalDismissed: (dispCounts.false_positive || 0) + (dispCounts.deferred || 0) + (dispCounts.ignored || 0) + (dispCounts.fixed || 0),
    byStatus: {
      false_positive: dispCounts.false_positive || 0,
      deferred: dispCounts.deferred || 0,
      ignored: dispCounts.ignored || 0,
      fixed: dispCounts.fixed || 0,
    },
  };

  return sendSuccess(res, transformScan(scan));
}

export async function createScan(req: Request, res: Response) {
  const validation = createScanSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { projectId, profile, branch, commitSha, scanners, options } = validation.data;

  // Verify project ownership
  const project = await db.execute(sql`
    SELECT id, default_branch, repo_url FROM projects
    WHERE id = ${projectId} AND user_id = ${req.user!.id}
  `);

  if (project.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  const projectData = project.rows[0] as any;

  // Create scan record
  const result = await db.execute(sql`
    INSERT INTO scans (project_id, status, profile, branch, commit_sha, trigger_type)
    VALUES (
      ${projectId},
      'pending',
      ${profile},
      ${branch || projectData.default_branch},
      ${commitSha || null},
      'api'
    )
    RETURNING *
  `);

  const scan = result.rows[0] as any;

  // Fetch DAST context (target URL, auth, registry creds) from project
  const scanContext = await buildScanContext(projectId, {
    targetUrl: validation.data.targetUrlOverride,
    containerImage: validation.data.containerImageOverride,
    openapiSpecPath: validation.data.openapiSpecOverride,
  });

  // Queue the scan job
  try {
    await addScanJob({
      scanId: scan.id,
      projectId,
      userId: req.user!.id,
      profile,
      branch: branch || projectData.default_branch,
      commitSha,
      repositoryUrl: projectData.repo_url,
      scanners: scanners || [],
      options: options || {},
      ...scanContext,
    });

    // Update status to queued
    await db.execute(sql`
      UPDATE scans SET status = 'queued' WHERE id = ${scan.id}
    `);

    scan.status = 'queued';
  } catch (error) {
    logger.error({ error, scanId: scan.id }, 'Failed to queue scan');
  }

  logger.info({ scanId: scan.id, projectId }, 'Scan created');

  return sendCreated(res, transformScan(scan as Record<string, unknown>));
}

export async function cancelScan(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    UPDATE scans s
    SET status = 'cancelled'
    FROM projects p
    WHERE s.project_id = p.id
    AND s.id = ${id}
    AND p.user_id = ${req.user!.id}
    AND s.status IN ('pending', 'queued', 'running')
    RETURNING s.*
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Scan not found or cannot be cancelled');
  }

  logger.info({ scanId: id }, 'Scan cancelled');

  return sendSuccess(res, transformScan(result.rows[0] as Record<string, unknown>));
}

export async function retryScan(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  // Get original scan
  const original = await db.execute(sql`
    SELECT s.* FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE s.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (original.rows.length === 0) {
    throw new NotFoundError('Scan not found');
  }

  const originalScan = original.rows[0] as any;

  // Create new scan with same parameters
  const result = await db.execute(sql`
    INSERT INTO scans (project_id, status, branch, commit_sha, trigger_type)
    VALUES (
      ${originalScan.project_id},
      'pending',
      ${originalScan.branch},
      ${originalScan.commit_sha},
      'retry'
    )
    RETURNING *
  `);

  const scan = result.rows[0] as any;

  // Fetch DAST context from project for retry
  const scanContext = await buildScanContext(originalScan.project_id);

  // Queue the scan job
  try {
    await addScanJob({
      scanId: scan.id,
      projectId: originalScan.project_id,
      userId: req.user!.id,
      profile: 'standard',
      branch: originalScan.branch,
      commitSha: originalScan.commit_sha,
      scanners: [],
      ...scanContext,
    });

    await db.execute(sql`
      UPDATE scans SET status = 'queued' WHERE id = ${scan.id}
    `);
    scan.status = 'queued';
  } catch (error) {
    logger.error({ error, scanId: scan.id }, 'Failed to queue retry scan');
  }

  logger.info({ scanId: scan.id, originalScanId: id }, 'Scan retried');

  return sendCreated(res, transformScan(scan as Record<string, unknown>));
}

export async function getScanAttestation(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  // Verify scan ownership
  const scan = await db.execute(sql`
    SELECT s.id FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE s.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (scan.rows.length === 0) {
    throw new NotFoundError('Scan not found');
  }

  // Get attestation for this scan
  const result = await db.execute(sql`
    SELECT * FROM attestations WHERE scan_id = ${id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Attestation not found for this scan');
  }

  const row = result.rows[0] as any;

  return sendSuccess(res, {
    id: row.id,
    scanId: row.scan_id,
    attestationType: row.attestation_type,
    subjectName: row.subject_name,
    subjectDigest: row.subject_digest,
    predicate: row.predicate,
    signature: row.signature,
    signatureAlgorithm: row.signature_algorithm,
    certificate: row.certificate,
    certificateChain: row.certificate_chain,
    rekorLogId: row.rekor_log_id,
    rekorLogIndex: row.rekor_log_index,
    transparencyLogUrl: row.transparency_log_url,
    createdAt: row.created_at,
  });
}

export async function getScanFindings(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const querySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(5000).default(50),
    severity: z.string().min(1).optional(),
    scanner: z.string().min(1).optional(),
    status: z.string().min(1).optional(),
  }).passthrough();
  const { page, limit, severity, scanner, status } = querySchema.parse(req.query);
  const offset = (page - 1) * limit;

  // Verify scan ownership
  const scan = await db.execute(sql`
    SELECT s.id FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE s.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (scan.rows.length === 0) {
    throw new NotFoundError('Scan not found');
  }

  // Default to open findings only unless explicitly requesting all
  let whereClause = sql`f.scan_id = ${id}`;
  if (status && status !== 'all') {
    whereClause = sql`${whereClause} AND f.status = ${status}`;
  } else if (!status) {
    whereClause = sql`${whereClause} AND f.status = 'open'`;
  }
  // status === 'all' → no status filter, return everything
  if (severity) {
    whereClause = sql`${whereClause} AND f.severity = ${severity}`;
  }
  if (scanner) {
    whereClause = sql`${whereClause} AND (f.tool_name = ${scanner} OR f.scanner = ${scanner})`;
  }

  const [findings, countResult] = await Promise.all([
    db.execute(sql`
      SELECT * FROM findings f
      WHERE ${whereClause}
      ORDER BY
        CASE f.severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          ELSE 5
        END,
        f.created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `),
    db.execute(sql`
      SELECT COUNT(*) as count FROM findings f WHERE ${whereClause}
    `),
  ]);

  const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string);
  const transformedFindings = findings.rows.map(row => transformFinding(row as Record<string, unknown>));

  return sendSuccess(res, transformedFindings, 200, {
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  });
}

/** Admin: recalculate all scan scores using current scoring algorithm */
export async function recalculateAllScores(_req: Request, res: Response) {
  const scansResult = await db.execute(sql`
    SELECT id FROM scans WHERE status = 'completed' ORDER BY created_at DESC
  `);

  const scanIds = scansResult.rows.map((r: any) => r.id as string);
  let updated = 0;

  for (const scanId of scanIds) {
    await refreshScanFindingsCount(scanId);
    updated++;
  }

  logger.info({ updated }, 'Recalculated all scan scores');
  return sendSuccess(res, { recalculated: updated });
}
