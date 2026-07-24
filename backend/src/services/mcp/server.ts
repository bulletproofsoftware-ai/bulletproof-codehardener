import { createLogger } from '../../utils/logger.js';
import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { addScanJob } from '../queue/scan.queue.js';
import { buildScanContext } from '../scan-context.js';
import { calculateQualityScore, getQualityBadge } from '../assurance/quality-score.js';
import { translateFinding } from '../translator/plain-language.js';
import { generateMarkdownReport } from '../reports/markdown-generator.js';
import { generateSarifReport } from '../reports/sarif-generator.js';

const logger = createLogger('mcp-server');

// MCP Tool Definitions for Claude Code integration
export const MCP_TOOLS = {
  scan: {
    name: 'codehardener_scan',
    description: 'Run a security scan on the current project or specified path',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to scan (defaults to current directory)',
        },
        profile: {
          type: 'string',
          enum: ['quick', 'standard', 'comprehensive', 'security', 'api', 'performance', 'frontend', 'supply-chain', 'ai-security', 'ai-code-quality', 'database', 'chaos', 'pr', 'pre-commit', 'compliance', 'usability', 'unit-test', 'full'],
          description: 'Scan profile: quick (5 scanners), standard (15 scanners), comprehensive (all 70+). Also: security, api, performance, frontend, supply-chain, ai-security, ai-code-quality, database, chaos, pr, pre-commit, compliance, usability, unit-test, full',
        },
        scanners: {
          type: 'array',
          items: { type: 'string' },
          description: 'Specific scanners: trivy, gitleaks, opengrep, checkov, nuclei, bandit, gosec, grype, syft, semgrep, eslint-security, pmd, zap, sqlmap, dalfox, ffuf, socket-dev, giskard, axe-core, c8, fast-check, hypothesis, lychee',
        },
      },
    },
  },
  status: {
    name: 'codehardener_status',
    description: 'Get the status of a running or completed scan',
    inputSchema: {
      type: 'object',
      properties: {
        scanId: {
          type: 'string',
          description: 'ID of the scan to check',
        },
      },
      required: ['scanId'],
    },
  },
  findings: {
    name: 'codehardener_findings',
    description: 'Get security findings from a completed scan',
    inputSchema: {
      type: 'object',
      properties: {
        scanId: {
          type: 'string',
          description: 'ID of the scan',
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'info'],
          description: 'Filter by severity level',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of findings to return (default 20)',
        },
      },
      required: ['scanId'],
    },
  },
  fix: {
    name: 'codehardener_fix',
    description: 'Get fix suggestions for a specific finding',
    inputSchema: {
      type: 'object',
      properties: {
        findingId: {
          type: 'string',
          description: 'ID of the finding to get fix suggestions for',
        },
      },
      required: ['findingId'],
    },
  },
  score: {
    name: 'codehardener_score',
    description: 'Get the security score and risk assessment for a project',
    inputSchema: {
      type: 'object',
      properties: {
        projectId: {
          type: 'string',
          description: 'ID of the project',
        },
      },
      required: ['projectId'],
    },
  },
  attestation: {
    name: 'codehardener_attestation',
    description: 'Get cryptographic attestation for a completed scan (Sigstore)',
    inputSchema: {
      type: 'object',
      properties: {
        scanId: {
          type: 'string',
          description: 'ID of the scan to get attestation for',
        },
      },
      required: ['scanId'],
    },
  },
  sbom: {
    name: 'codehardener_sbom',
    description: 'Generate Software Bill of Materials (SBOM) for a project',
    inputSchema: {
      type: 'object',
      properties: {
        projectId: {
          type: 'string',
          description: 'ID of the project',
        },
        format: {
          type: 'string',
          enum: ['spdx-json', 'cyclonedx-json', 'syft-json'],
          description: 'SBOM output format (default: cyclonedx-json)',
        },
      },
      required: ['projectId'],
    },
  },
  compare: {
    name: 'codehardener_compare',
    description: 'Compare findings between two scans to see what changed',
    inputSchema: {
      type: 'object',
      properties: {
        baseScanId: {
          type: 'string',
          description: 'ID of the base scan (older)',
        },
        headScanId: {
          type: 'string',
          description: 'ID of the head scan (newer)',
        },
      },
      required: ['baseScanId', 'headScanId'],
    },
  },
  dismiss: {
    name: 'codehardener_dismiss',
    description: 'Dismiss a finding as false positive or accepted risk',
    inputSchema: {
      type: 'object',
      properties: {
        findingId: {
          type: 'string',
          description: 'ID of the finding to dismiss',
        },
        reason: {
          type: 'string',
          enum: ['false_positive', 'deferred', 'wont_fix', 'duplicate'],
          description: 'Reason for dismissing the finding',
        },
        comment: {
          type: 'string',
          description: 'Optional explanation for the dismissal',
        },
      },
      required: ['findingId', 'reason'],
    },
  },
  history: {
    name: 'codehardener_history',
    description: 'Get scan history and score trend for a project',
    inputSchema: {
      type: 'object',
      properties: {
        projectId: {
          type: 'string',
          description: 'ID of the project',
        },
        limit: {
          type: 'number',
          description: 'Number of historical scans to retrieve (default 10)',
        },
      },
      required: ['projectId'],
    },
  },
  report: {
    name: 'codehardener_get_report',
    description: 'Get a structured security report for a completed scan. Returns markdown (AI-readable with file:line locations and fix guidance) or SARIF (machine-readable standard for IDEs and CI/CD).',
    inputSchema: {
      type: 'object',
      properties: {
        scanId: {
          type: 'string',
          description: 'ID of the completed scan',
        },
        format: {
          type: 'string',
          enum: ['markdown', 'sarif', 'json'],
          description: 'Report format: markdown (default, AI-optimized), sarif (IDE/CI standard), json (raw data)',
        },
        minSeverity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'info'],
          description: 'Minimum severity to include (default: all)',
        },
      },
      required: ['scanId'],
    },
  },
};

// MCP Tool Handlers
export async function handleMcpTool(
  toolName: string,
  args: Record<string, any>,
  userId: string
): Promise<any> {
  logger.info({ toolName, args }, 'Handling MCP tool call');

  switch (toolName) {
    case 'codehardener_scan':
      return handleScan(args, userId);
    case 'codehardener_status':
      return handleStatus(args, userId);
    case 'codehardener_findings':
      return handleFindings(args, userId);
    case 'codehardener_fix':
      return handleFix(args, userId);
    case 'codehardener_score':
      return handleScore(args, userId);
    case 'codehardener_attestation':
      return handleAttestation(args, userId);
    case 'codehardener_sbom':
      return handleSbom(args, userId);
    case 'codehardener_compare':
      return handleCompare(args, userId);
    case 'codehardener_dismiss':
      return handleDismiss(args, userId);
    case 'codehardener_history':
      return handleHistory(args, userId);
    case 'codehardener_get_report':
      return handleReport(args, userId);
    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

async function handleScan(args: Record<string, any>, userId: string) {
  const { path = '.', profile = 'standard', scanners } = args;

  // Get or create project for this path
  let projectResult = await db.execute(sql`
    SELECT id FROM projects WHERE user_id = ${userId} AND repo_url = ${path}
  `);

  let projectId: string;

  if (projectResult.rows.length === 0) {
    // Create new project
    const newProject = await db.execute(sql`
      INSERT INTO projects (user_id, name, repo_url)
      VALUES (${userId}, ${path.split('/').pop() || 'Project'}, ${path})
      RETURNING id
    `);
    projectId = (newProject.rows[0] as any).id;
  } else {
    projectId = (projectResult.rows[0] as any).id;
  }

  // Create scan
  const scanResult = await db.execute(sql`
    INSERT INTO scans (project_id, status, trigger_type)
    VALUES (${projectId}, 'pending', 'mcp')
    RETURNING id
  `);

  const scanId = (scanResult.rows[0] as any).id;

  // Fetch DAST context from project
  const scanContext = await buildScanContext(projectId);

  // Queue scan job
  await addScanJob({
    scanId,
    projectId,
    userId,
    profile,
    branch: 'main',
    scanners: scanners || ['trivy', 'gitleaks', 'opengrep', 'checkov', 'nuclei'],
    ...scanContext,
  });

  return {
    message: `Security scan started with ${profile} profile`,
    scanId,
    status: 'queued',
    estimatedTime: profile === 'quick' ? '30 seconds' : profile === 'standard' ? '2 minutes' : '5 minutes',
  };
}

async function handleStatus(args: Record<string, any>, userId: string) {
  const { scanId } = args;

  const result = await db.execute(sql`
    SELECT s.*, p.name as project_name
    FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE s.id = ${scanId} AND p.user_id = ${userId}
  `);

  if (result.rows.length === 0) {
    return { error: 'Scan not found' };
  }

  const scan = result.rows[0] as any;

  return {
    scanId: scan.id,
    status: scan.status,
    score: scan.score,
    qualityLevel: scan.quality_level,
    findingsCount: scan.findings_count,
    startedAt: scan.started_at,
    completedAt: scan.completed_at,
  };
}

async function handleFindings(args: Record<string, any>, userId: string) {
  const { scanId, severity, limit = 20 } = args;

  let whereClause = sql`f.scan_id = ${scanId}`;
  if (severity) {
    whereClause = sql`${whereClause} AND f.severity = ${severity}`;
  }

  const result = await db.execute(sql`
    SELECT f.* FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE ${whereClause} AND p.user_id = ${userId}
    ORDER BY
      CASE f.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
      END
    LIMIT ${limit}
  `);

  // Translate findings to plain language
  const findings = result.rows.map((f: any) => {
    const translated = translateFinding(
      f.title,
      f.description,
      f.severity,
      f.cwe_id,
      f.owasp_category,
      f.tool_name || 'unknown'
    );

    return {
      id: f.id,
      severity: f.severity,
      title: translated.titleSimple,
      description: translated.descriptionSimple,
      action: translated.actionRequired,
      filePath: f.file_path,
      lineNumber: f.line_number,
      fixAvailable: f.fix_available,
    };
  });

  return { findings, total: findings.length };
}

async function handleFix(args: Record<string, any>, userId: string) {
  const { findingId } = args;

  const result = await db.execute(sql`
    SELECT f.* FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE f.id = ${findingId} AND p.user_id = ${userId}
  `);

  if (result.rows.length === 0) {
    return { error: 'Finding not found' };
  }

  const finding = result.rows[0] as any;
  const translated = translateFinding(
    finding.title,
    finding.description,
    finding.severity,
    finding.cwe_id,
    finding.owasp_category,
    finding.tool_name || 'unknown'
  );

  return {
    findingId: finding.id,
    title: translated.titleSimple,
    severity: finding.severity,
    riskExplanation: translated.riskExplanation,
    actionRequired: translated.actionRequired,
    fixDescription: finding.fix_description,
    filePath: finding.file_path,
    lineNumber: finding.line_number,
    codeSnippet: finding.code_snippet,
  };
}

async function handleScore(args: Record<string, any>, userId: string) {
  const { projectId } = args;

  const result = await db.execute(sql`
    SELECT p.*,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = p.id AND f.status = 'open' AND f.severity = 'critical') as critical_count,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = p.id AND f.status = 'open' AND f.severity = 'high') as high_count,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = p.id AND f.status = 'open' AND f.severity = 'medium') as medium_count,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = p.id AND f.status = 'open' AND f.severity = 'low') as low_count,
      (SELECT MAX(completed_at) FROM scans WHERE project_id = p.id AND status = 'completed') as last_scan_at
    FROM projects p
    WHERE p.id = ${projectId} AND p.user_id = ${userId}
  `);

  if (result.rows.length === 0) {
    return { error: 'Project not found' };
  }

  const project = result.rows[0] as any;
  const findings = {
    critical: parseInt(project.critical_count) || 0,
    high: parseInt(project.high_count) || 0,
    medium: parseInt(project.medium_count) || 0,
    low: parseInt(project.low_count) || 0,
    info: 0,
    total: 0,
  };
  findings.total = findings.critical + findings.high + findings.medium + findings.low;

  const { score, qualityLevel } = calculateQualityScore(findings);
  const badge = getQualityBadge(qualityLevel);

  return {
    projectName: project.name,
    score,
    qualityLevel,
    badge: badge.text,
    findings,
    lastScanAt: project.last_scan_at,
    recommendation: findings.critical > 0
      ? 'Critical vulnerabilities found! Address these immediately.'
      : findings.high > 0
        ? 'High severity issues need attention soon.'
        : score >= 750
          ? 'Good security posture! Keep monitoring.'
          : 'Review and address open findings to improve your score.',
  };
}

async function handleAttestation(args: Record<string, any>, userId: string) {
  const { scanId } = args;

  const result = await db.execute(sql`
    SELECT a.*, s.project_id
    FROM attestations a
    JOIN scans s ON s.id = a.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE a.scan_id = ${scanId} AND p.user_id = ${userId}
  `);

  if (result.rows.length === 0) {
    return { error: 'Attestation not found for this scan' };
  }

  const attestation = result.rows[0] as any;

  return {
    id: attestation.id,
    scanId: attestation.scan_id,
    type: attestation.attestation_type,
    subject: {
      name: attestation.subject_name,
      digest: attestation.subject_digest,
    },
    signed: !!attestation.signature,
    rekorLogId: attestation.rekor_log_id,
    createdAt: attestation.created_at,
    verificationUrl: attestation.rekor_log_id
      ? `https://search.sigstore.dev/?logIndex=${attestation.rekor_log_id}`
      : null,
  };
}

async function handleSbom(args: Record<string, any>, userId: string) {
  const { projectId, format = 'cyclonedx-json' } = args;

  // Verify project access
  const projectResult = await db.execute(sql`
    SELECT id, name, repo_url FROM projects
    WHERE id = ${projectId} AND user_id = ${userId}
  `);

  if (projectResult.rows.length === 0) {
    return { error: 'Project not found' };
  }

  // Get SBOM from latest scan findings (syft scanner results)
  const sbomResult = await db.execute(sql`
    SELECT f.metadata, f.created_at
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    WHERE s.project_id = ${projectId}
      AND f.scanner = 'syft'
    ORDER BY f.created_at DESC
    LIMIT 1
  `);

  if (sbomResult.rows.length === 0) {
    return {
      error: 'No SBOM available. Run a scan with the syft scanner first.',
      suggestion: 'Use codehardener_scan with profile "standard" or "comprehensive" to generate SBOM.',
    };
  }

  return {
    projectId,
    format,
    generatedAt: (sbomResult.rows[0] as any).created_at,
    available: true,
    downloadUrl: `/api/v1/projects/${projectId}/sbom?format=${format}`,
  };
}

async function handleCompare(args: Record<string, any>, userId: string) {
  const { baseScanId, headScanId } = args;

  // Get findings from both scans
  const baseResult = await db.execute(sql`
    SELECT f.rule_id, f.severity, f.title, f.file_path
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE f.scan_id = ${baseScanId} AND p.user_id = ${userId}
  `);

  const headResult = await db.execute(sql`
    SELECT f.rule_id, f.severity, f.title, f.file_path
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE f.scan_id = ${headScanId} AND p.user_id = ${userId}
  `);

  const baseFindings = new Map(
    (baseResult.rows as any[]).map(f => [`${f.rule_id}:${f.file_path}`, f])
  );
  const headFindings = new Map(
    (headResult.rows as any[]).map(f => [`${f.rule_id}:${f.file_path}`, f])
  );

  const introduced: any[] = [];
  const resolved: any[] = [];
  const unchanged: any[] = [];

  // Find introduced (in head but not in base)
  for (const [key, finding] of headFindings) {
    if (!baseFindings.has(key)) {
      introduced.push(finding);
    } else {
      unchanged.push(finding);
    }
  }

  // Find resolved (in base but not in head)
  for (const [key, finding] of baseFindings) {
    if (!headFindings.has(key)) {
      resolved.push(finding);
    }
  }

  return {
    baseScanId,
    headScanId,
    summary: {
      introduced: introduced.length,
      resolved: resolved.length,
      unchanged: unchanged.length,
    },
    introduced: introduced.slice(0, 10),
    resolved: resolved.slice(0, 10),
    trend: resolved.length > introduced.length ? 'improving' :
           introduced.length > resolved.length ? 'degrading' : 'stable',
  };
}

/** Recompute scan scores after finding status change (used by MCP dismiss) */
async function refreshScanScores(scanId: string): Promise<void> {
  // Raw counts: ALL findings regardless of status
  const rawResult = await db.execute(sql`
    SELECT
      COUNT(*) FILTER (WHERE f.severity = 'critical') as critical,
      COUNT(*) FILTER (WHERE f.severity = 'high') as high,
      COUNT(*) FILTER (WHERE f.severity = 'medium') as medium,
      COUNT(*) FILTER (WHERE f.severity = 'low') as low,
      COUNT(*) FILTER (WHERE f.severity = 'info') as info,
      COUNT(*) as total
    FROM findings f WHERE f.scan_id = ${scanId}
  `);
  const rawRow = rawResult.rows[0] as Record<string, unknown>;
  const rawCounts = {
    critical: parseInt(rawRow.critical as string) || 0,
    high: parseInt(rawRow.high as string) || 0,
    medium: parseInt(rawRow.medium as string) || 0,
    low: parseInt(rawRow.low as string) || 0,
    info: parseInt(rawRow.info as string) || 0,
    total: parseInt(rawRow.total as string) || 0,
  };
  const { score: scoreRaw } = calculateQualityScore(rawCounts);

  // Adjusted counts: only open findings
  const adjResult = await db.execute(sql`
    SELECT
      COUNT(*) FILTER (WHERE f.severity = 'critical' AND f.status = 'open') as critical,
      COUNT(*) FILTER (WHERE f.severity = 'high'     AND f.status = 'open') as high,
      COUNT(*) FILTER (WHERE f.severity = 'medium'   AND f.status = 'open') as medium,
      COUNT(*) FILTER (WHERE f.severity = 'low'      AND f.status = 'open') as low,
      COUNT(*) FILTER (WHERE f.severity = 'info'     AND f.status = 'open') as info,
      COUNT(*) FILTER (WHERE f.status = 'open') as total
    FROM findings f WHERE f.scan_id = ${scanId}
  `);
  const adjRow = adjResult.rows[0] as Record<string, unknown>;
  const adjCounts = {
    critical: parseInt(adjRow.critical as string) || 0,
    high: parseInt(adjRow.high as string) || 0,
    medium: parseInt(adjRow.medium as string) || 0,
    low: parseInt(adjRow.low as string) || 0,
    info: parseInt(adjRow.info as string) || 0,
    total: parseInt(adjRow.total as string) || 0,
  };
  const { score, qualityLevel } = calculateQualityScore(adjCounts);

  await db.execute(sql`
    UPDATE scans
    SET score_raw = ${scoreRaw}, score = ${score}, quality_level = ${qualityLevel},
        findings_count = ${JSON.stringify({ ...adjCounts, raw: rawCounts })}::jsonb, updated_at = NOW()
    WHERE id = ${scanId}
  `);
  await db.execute(sql`
    UPDATE projects SET last_score = ${score}, updated_at = NOW()
    WHERE id = (SELECT project_id FROM scans WHERE id = ${scanId}) AND last_scan_id = ${scanId}
  `);
}

async function handleDismiss(args: Record<string, any>, userId: string) {
  const { findingId, reason, comment } = args;

  // Map reason to proper finding status
  const statusMap: Record<string, string> = {
    false_positive: 'false_positive',
    deferred: 'deferred',
    wont_fix: 'ignored',
    duplicate: 'ignored',
  };
  const targetStatus = statusMap[reason] || 'ignored';

  // Verify finding belongs to user's project and update
  const result = await db.execute(sql`
    UPDATE findings f
    SET status = ${targetStatus},
        dismissed_reason = ${reason},
        dismissed_comment = ${comment || null},
        dismissed_by = (SELECT id FROM users WHERE id = ${userId}::uuid),
        dismissed_at = NOW()
    FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE f.id = ${findingId}
      AND f.scan_id = s.id
      AND p.user_id = ${userId}
    RETURNING f.id, f.title, f.status, f.scan_id
  `);

  if (result.rows.length === 0) {
    return { error: 'Finding not found or access denied' };
  }

  // Refresh scan scores (both raw and adjusted)
  const scanId = (result.rows[0] as Record<string, unknown>).scan_id as string;
  await refreshScanScores(scanId);

  return {
    findingId,
    status: targetStatus,
    reason,
    comment,
    message: 'Finding has been dismissed and will not affect your adjusted security score.',
  };
}

async function handleHistory(args: Record<string, any>, userId: string) {
  const { projectId, limit = 10 } = args;

  const result = await db.execute(sql`
    SELECT s.id, s.status, s.score, s.quality_level, s.findings_count,
           s.started_at, s.completed_at, s.duration
    FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE s.project_id = ${projectId}
      AND p.user_id = ${userId}
      AND s.status = 'completed'
    ORDER BY s.completed_at DESC
    LIMIT ${limit}
  `);

  const scans = result.rows as any[];
  const scores = scans.map(s => s.score).filter(Boolean);

  return {
    projectId,
    scans: scans.map(s => ({
      scanId: s.id,
      score: s.score,
      qualityLevel: s.quality_level,
      findingsCount: s.findings_count,
      completedAt: s.completed_at,
      duration: s.duration,
    })),
    trend: {
      current: scores[0] || 0,
      previous: scores[1] || 0,
      average: scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0,
      direction: scores.length >= 2 ? (scores[0] > scores[1] ? 'up' : scores[0] < scores[1] ? 'down' : 'stable') : 'stable',
    },
  };
}

async function handleReport(args: Record<string, any>, userId: string) {
  const { scanId, format = 'markdown', minSeverity } = args;

  if (format === 'sarif') {
    const sarif = await generateSarifReport(scanId, userId);
    return {
      format: 'sarif',
      scanId,
      content: sarif,
    };
  }

  if (format === 'json') {
    // Raw findings data
    const result = await db.execute(sql`
      SELECT f.* FROM findings f
      JOIN scans s ON s.id = f.scan_id
      JOIN projects p ON p.id = s.project_id
      WHERE f.scan_id = ${scanId} AND p.user_id = ${userId}
      ORDER BY
        CASE f.severity
          WHEN 'critical' THEN 1 WHEN 'high' THEN 2
          WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
        END
    `);
    return {
      format: 'json',
      scanId,
      findings: result.rows,
    };
  }

  // Default: markdown — AI-consumable report
  const markdown = await generateMarkdownReport({
    scanId,
    userId,
    minSeverity,
  });

  return {
    format: 'markdown',
    scanId,
    content: markdown,
    hint: 'This report contains file:line locations, code snippets, CWE references, and fix guidance. Use it to navigate to each finding and apply the suggested fixes.',
  };
}

// MCP Server Protocol Handler (legacy)
export function createMcpProtocolHandler() {
  return {
    listTools: () => Object.values(MCP_TOOLS),
    executeTool: async (toolName: string, args: Record<string, any>, context: { userId: string }) => {
      return handleMcpTool(toolName, args, context.userId);
    },
  };
}

// ============================================================================
// MCP SDK-Compatible Exports
// ============================================================================

// Import high-level orchestrated tools
import { scanProjectTools } from './tools/scan-project.js';
import { scanTargetedTools } from './tools/scan-targeted.js';
import { autoFixTools } from './tools/auto-fix.js';
import { queryDefectdojoTools } from './tools/query-defectdojo.js';
import { workflowTools } from './tools/workflows.js';

/**
 * Get all MCP tool definitions in SDK format.
 * Combines existing low-level tools with high-level orchestrated tools.
 */
export function getMcpToolDefinitions() {
  const baseDefs = Object.values(MCP_TOOLS).map(tool => ({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
  }));

  return [
    ...baseDefs,
    ...scanProjectTools,
    ...scanTargetedTools,
    ...autoFixTools,
    ...queryDefectdojoTools,
    ...workflowTools,
  ];
}

/**
 * Execute an MCP tool by name.
 * Routes to the appropriate handler.
 */
export async function executeMcpTool(
  name: string,
  args: Record<string, unknown>
): Promise<unknown> {
  // Default user context for stdio (single-user mode)
  const userId = (args._userId as string) || 'mcp-default-user';

  // Check high-level tools first
  const highLevelHandlers: Record<string, (args: Record<string, unknown>) => Promise<unknown>> = {
    codehardener_scan_project: async (a) => {
      const { handleScanProject } = await import('./tools/scan-project.js');
      return handleScanProject(a, userId);
    },
    codehardener_get_findings: async (a) => {
      const { handleGetFindings } = await import('./tools/query-defectdojo.js');
      return handleGetFindings(a, userId);
    },
    codehardener_get_quality_score: async (a) => {
      const { handleGetQualityScore } = await import('./tools/query-defectdojo.js');
      return handleGetQualityScore(a, userId);
    },
    codehardener_get_trends: async (a) => {
      const { handleGetTrends } = await import('./tools/query-defectdojo.js');
      return handleGetTrends(a, userId);
    },
    codehardener_run_tests: async (a) => {
      const { handleRunTests } = await import('./tools/workflows.js');
      return handleRunTests(a);
    },
    codehardener_workflow_status: async (a) => {
      const { handleWorkflowStatus } = await import('./tools/workflows.js');
      return handleWorkflowStatus(a);
    },
    codehardener_get_report: async (a) => {
      return handleReport(a as Record<string, any>, userId);
    },
    codehardener_scan_file: async (a) => {
      const { handleScanFile } = await import('./tools/scan-targeted.js');
      return handleScanFile(a, userId);
    },
    codehardener_scan_diff: async (a) => {
      const { handleScanDiff } = await import('./tools/scan-targeted.js');
      return handleScanDiff(a, userId);
    },
    codehardener_auto_fix: async (a) => {
      const { handleAutoFix } = await import('./tools/auto-fix.js');
      return handleAutoFix(a, userId);
    },
    codehardener_bulk_fix: async (a) => {
      const { handleBulkFix } = await import('./tools/auto-fix.js');
      return handleBulkFix(a, userId);
    },
  };

  if (highLevelHandlers[name]) {
    return highLevelHandlers[name](args);
  }

  // Fall back to existing handlers
  return handleMcpTool(name, args as Record<string, any>, userId);
}
