import { db } from '../../../db/client.js';
import { sql } from 'drizzle-orm';
import { addScanJob } from '../../queue/scan.queue.js';
import { buildScanContext } from '../../scan-context.js';
import { generateMarkdownReport } from '../../reports/markdown-generator.js';
export const scanProjectTools = [
  {
    name: 'codehardener_scan_project',
    description:
      'One-shot security scan: creates project if needed, runs scan, waits for results, and returns findings summary. This is the recommended way to scan from an AI agent.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: {
          type: 'string',
          description: 'Path or repository URL to scan',
        },
        name: {
          type: 'string',
          description: 'Project name (auto-detected from path if omitted)',
        },
        profile: {
          type: 'string',
          enum: ['quick', 'standard', 'comprehensive'],
          description: 'Scan profile (default: standard)',
        },
        waitForResults: {
          type: 'boolean',
          description: 'Wait for scan to complete and return findings (default: true). Set false for async.',
        },
      },
    },
  },
];

export async function handleScanProject(
  args: Record<string, unknown>,
  userId: string
): Promise<unknown> {
  const path = (args.path as string) || '.';
  const name = (args.name as string) || path.split('/').pop() || 'Project';
  const profile = (args.profile as string) || 'standard';
  const waitForResults = args.waitForResults !== false;

  // Get or create project
  let projectResult = await db.execute(sql`
    SELECT id FROM projects WHERE user_id = ${userId} AND (repo_url = ${path} OR name = ${name})
  `);

  let projectId: string;
  if (projectResult.rows.length === 0) {
    const newProject = await db.execute(sql`
      INSERT INTO projects (user_id, name, repo_url)
      VALUES (${userId}, ${name}, ${path})
      RETURNING id
    `);
    projectId = (newProject.rows[0] as Record<string, unknown>).id as string;
  } else {
    projectId = (projectResult.rows[0] as Record<string, unknown>).id as string;
  }

  // Create scan
  const scanResult = await db.execute(sql`
    INSERT INTO scans (project_id, status, trigger_type, profile)
    VALUES (${projectId}, 'pending', 'mcp', ${profile})
    RETURNING id
  `);
  const scanId = (scanResult.rows[0] as Record<string, unknown>).id as string;

  // Determine scanners for profile
  const profileScanners: Record<string, string[]> = {
    quick: ['gitleaks', 'trivy'],
    standard: ['trivy', 'gitleaks', 'opengrep', 'checkov', 'grype', 'syft'],
    comprehensive: [
      'opengrep', 'bandit', 'gosec', 'eslint-security', 'pmd',
      'nuclei', 'trivy', 'grype', 'gitleaks',
      'checkov', 'syft', 'cosign', 'opa', 'conftest',
    ],
  };

  // Fetch DAST context from project
  const scanContext = await buildScanContext(projectId);

  // Queue scan
  await addScanJob({
    scanId,
    projectId,
    userId,
    profile: profile as 'quick' | 'standard' | 'comprehensive',
    branch: 'main',
    scanners: profileScanners[profile] || profileScanners.standard,
    ...scanContext,
  });

  if (!waitForResults) {
    return {
      message: `Scan started with ${profile} profile`,
      scanId,
      projectId,
      status: 'queued',
      checkWith: 'Use codehardener_status to check progress',
    };
  }

  // Poll for completion (max 5 minutes)
  const maxWait = 300000;
  const pollInterval = 3000;
  const startTime = Date.now();

  while (Date.now() - startTime < maxWait) {
    await new Promise(resolve => setTimeout(resolve, pollInterval));

    const status = await db.execute(sql`
      SELECT status, score, quality_level, findings_count, duration
      FROM scans WHERE id = ${scanId}
    `);

    const scan = status.rows[0] as Record<string, unknown>;
    if (!scan) break;

    if (scan.status === 'completed') {
      // Generate full markdown report for AI consumption
      let report: string | undefined;
      try {
        report = await generateMarkdownReport({ scanId, userId });
      } catch {
        // Non-fatal — return results without report
      }

      // Get top findings as structured data backup
      const findings = await db.execute(sql`
        SELECT id, severity, title, description, file_path, line_number, fix_available
        FROM findings
        WHERE scan_id = ${scanId}
        ORDER BY
          CASE severity
            WHEN 'critical' THEN 1 WHEN 'high' THEN 2
            WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
          END
        LIMIT 15
      `);

      return {
        status: 'completed',
        scanId,
        projectId,
        score: scan.score,
        qualityLevel: scan.quality_level,
        findingsCount: scan.findings_count,
        duration: scan.duration,
        topFindings: findings.rows,
        report,
        reportHint: report
          ? 'The report field contains a full markdown security report with file:line locations and fix guidance. Parse it to auto-fix issues.'
          : undefined,
        viewDetails: `Use codehardener_get_report with scanId "${scanId}" for the full report, or codehardener_findings for structured data`,
      };
    }

    if (scan.status === 'failed') {
      return {
        status: 'failed',
        scanId,
        message: 'Scan failed. Check logs for details.',
      };
    }
  }

  return {
    status: 'timeout',
    scanId,
    projectId,
    message: 'Scan is still running. Use codehardener_status to check progress.',
  };
}
