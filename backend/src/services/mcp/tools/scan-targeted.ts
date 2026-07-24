import { db } from '../../../db/client.js';
import { sql } from 'drizzle-orm';
import { addScanJob } from '../../queue/scan.queue.js';
import { buildScanContext } from '../../scan-context.js';
import { createLogger } from '../../../utils/logger.js';

const logger = createLogger('mcp-scan-targeted');

// ============================================================================
// Tool Definitions
// ============================================================================

export const scanTargetedTools = [
  {
    name: 'codehardener_scan_file',
    description:
      'Scan a single file for security issues. Useful during development for quick feedback on a specific file you just wrote or modified. Runs relevant SAST scanners for the file type.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        filePath: {
          type: 'string',
          description: 'Absolute path to the file to scan',
        },
        projectId: {
          type: 'string',
          description: 'Project ID (optional — auto-detected from path if omitted)',
        },
        scanners: {
          type: 'array',
          items: { type: 'string' },
          description: 'Specific scanners to run (auto-selected from file type if omitted)',
        },
      },
      required: ['filePath'],
    },
  },
  {
    name: 'codehardener_scan_diff',
    description:
      'Scan a git diff for newly introduced security issues. Compares current changes against the base branch and reports only findings in changed lines. Perfect for pre-commit or PR review.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        projectId: {
          type: 'string',
          description: 'Project ID',
        },
        baseBranch: {
          type: 'string',
          description: 'Base branch to diff against (default: main)',
        },
        diff: {
          type: 'string',
          description: 'Raw unified diff content to scan (alternative to baseBranch — for piping `git diff` output directly)',
        },
        scanners: {
          type: 'array',
          items: { type: 'string' },
          description: 'Specific scanners to run (auto-selected if omitted)',
        },
      },
    },
  },
];

// ============================================================================
// File extension → scanner mapping for targeted scans
// ============================================================================

const EXT_SCANNER_MAP: Record<string, string[]> = {
  '.py':   ['bandit', 'opengrep', 'gitleaks'],
  '.pyw':  ['bandit', 'opengrep', 'gitleaks'],
  '.js':   ['eslint-security', 'opengrep', 'gitleaks'],
  '.jsx':  ['eslint-security', 'opengrep', 'gitleaks'],
  '.mjs':  ['eslint-security', 'opengrep', 'gitleaks'],
  '.ts':   ['eslint-security', 'opengrep', 'gitleaks'],
  '.tsx':  ['eslint-security', 'opengrep', 'gitleaks'],
  '.go':   ['gosec', 'opengrep', 'gitleaks'],
  '.java': ['pmd', 'opengrep', 'gitleaks'],
  '.kt':   ['pmd', 'opengrep', 'gitleaks'],
  '.rb':   ['opengrep', 'gitleaks'],
  '.rs':   ['opengrep', 'gitleaks'],
  '.cs':   ['opengrep', 'gitleaks'],
  '.php':  ['opengrep', 'gitleaks'],
  '.sh':   ['opengrep', 'gitleaks'],
  '.tf':   ['checkov', 'conftest', 'gitleaks'],
  '.hcl':  ['checkov', 'conftest', 'gitleaks'],
  '.yml':  ['checkov', 'gitleaks'],
  '.yaml': ['checkov', 'gitleaks'],
  '.sql':  ['opengrep', 'gitleaks'],
  '.html': ['opengrep', 'gitleaks'],
};

function getScannersForFile(filePath: string): string[] {
  const ext = filePath.match(/(\.[^.]+)$/)?.[1]?.toLowerCase() || '';
  return EXT_SCANNER_MAP[ext] || ['opengrep', 'gitleaks'];
}

function getScannersForDiff(changedFiles: string[]): string[] {
  const scannerSet = new Set<string>();
  for (const file of changedFiles) {
    for (const scanner of getScannersForFile(file)) {
      scannerSet.add(scanner);
    }
  }
  // Always include secrets detection for diffs
  scannerSet.add('gitleaks');
  // detect-secrets removed: Gitleaks covers secrets detection
  return [...scannerSet];
}

/** Extract changed file paths from a unified diff */
function parseChangedFiles(diff: string): string[] {
  const files: string[] = [];
  for (const line of diff.split('\n')) {
    const match = line.match(/^\+\+\+ b\/(.+)$/);
    if (match) {
      files.push(match[1]);
    }
  }
  return files;
}

// ============================================================================
// Handlers
// ============================================================================

export async function handleScanFile(
  args: Record<string, unknown>,
  userId: string
): Promise<unknown> {
  const filePath = args.filePath as string;
  let projectId = args.projectId as string | undefined;
  const requestedScanners = args.scanners as string[] | undefined;

  if (!filePath) {
    return { error: 'filePath is required' };
  }

  // Auto-detect or create project
  if (!projectId) {
    const existing = await db.execute(sql`
      SELECT id FROM projects WHERE user_id = ${userId}
      ORDER BY updated_at DESC LIMIT 1
    `);
    if (existing.rows.length > 0) {
      projectId = (existing.rows[0] as Record<string, unknown>).id as string;
    } else {
      const newProject = await db.execute(sql`
        INSERT INTO projects (user_id, name, repo_url)
        VALUES (${userId}, 'Targeted Scan', ${filePath})
        RETURNING id
      `);
      projectId = (newProject.rows[0] as Record<string, unknown>).id as string;
    }
  }

  const scanners = requestedScanners || getScannersForFile(filePath);

  // Create scan record
  const scanResult = await db.execute(sql`
    INSERT INTO scans (project_id, status, trigger_type, profile)
    VALUES (${projectId}, 'pending', 'mcp', 'file')
    RETURNING id
  `);
  const scanId = (scanResult.rows[0] as Record<string, unknown>).id as string;

  logger.info({ scanId, filePath, scanners }, 'Starting targeted file scan');

  // Fetch DAST context from project
  const scanContext = await buildScanContext(projectId);

  // Queue with file-specific options
  await addScanJob({
    scanId,
    projectId,
    userId,
    profile: 'quick',
    branch: 'main',
    scanners,
    options: {
      depth: 'shallow',
    },
    ...scanContext,
  });

  // Poll for completion (max 60s for single file)
  const maxWait = 60000;
  const pollInterval = 2000;
  const startTime = Date.now();

  while (Date.now() - startTime < maxWait) {
    await new Promise(resolve => setTimeout(resolve, pollInterval));

    const status = await db.execute(sql`
      SELECT status, score, findings_count, duration
      FROM scans WHERE id = ${scanId}
    `);
    const scan = status.rows[0] as Record<string, unknown>;
    if (!scan) break;

    if (scan.status === 'completed') {
      const findings = await db.execute(sql`
        SELECT severity, title, description, file_path, line_number,
               rule_id, fix_available, fix_description
        FROM findings
        WHERE scan_id = ${scanId}
        ORDER BY
          CASE severity
            WHEN 'critical' THEN 1 WHEN 'high' THEN 2
            WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
          END
      `);

      return {
        status: 'completed',
        scanId,
        filePath,
        scannersUsed: scanners,
        score: scan.score,
        findingsCount: scan.findings_count,
        duration: scan.duration,
        findings: findings.rows,
        hint: findings.rows.length === 0
          ? 'No security issues found in this file.'
          : `Found ${findings.rows.length} issue(s). Review the findings and apply fixes.`,
      };
    }

    if (scan.status === 'failed') {
      return { status: 'failed', scanId, message: 'File scan failed.' };
    }
  }

  return {
    status: 'timeout',
    scanId,
    message: 'File scan is still running. Use codehardener_status to check.',
  };
}

export async function handleScanDiff(
  args: Record<string, unknown>,
  userId: string
): Promise<unknown> {
  let projectId = args.projectId as string | undefined;
  const baseBranch = (args.baseBranch as string) || 'main';
  const rawDiff = args.diff as string | undefined;
  const requestedScanners = args.scanners as string[] | undefined;

  // Auto-detect project
  if (!projectId) {
    const existing = await db.execute(sql`
      SELECT id FROM projects WHERE user_id = ${userId}
      ORDER BY updated_at DESC LIMIT 1
    `);
    if (existing.rows.length > 0) {
      projectId = (existing.rows[0] as Record<string, unknown>).id as string;
    } else {
      return { error: 'No project found. Create a project first or provide projectId.' };
    }
  }

  // Determine scanners from diff content
  let scanners: string[];
  if (requestedScanners) {
    scanners = requestedScanners;
  } else if (rawDiff) {
    const changedFiles = parseChangedFiles(rawDiff);
    scanners = getScannersForDiff(changedFiles);
  } else {
    // Default: run SAST + secrets scanners
    scanners = ['opengrep', 'eslint-security', 'bandit', 'gitleaks'];
  }

  // Create scan record
  const scanResult = await db.execute(sql`
    INSERT INTO scans (project_id, status, trigger_type, profile)
    VALUES (${projectId}, 'pending', 'mcp', 'diff')
    RETURNING id
  `);
  const scanId = (scanResult.rows[0] as Record<string, unknown>).id as string;

  logger.info({ scanId, baseBranch, scanners, hasDiff: !!rawDiff }, 'Starting diff scan');

  // Fetch DAST context from project
  const diffScanContext = await buildScanContext(projectId);

  // Queue scan
  await addScanJob({
    scanId,
    projectId,
    userId,
    profile: 'quick',
    branch: baseBranch,
    scanners,
    options: {
      depth: 'shallow',
    },
    ...diffScanContext,
  });

  // Poll for completion (max 90s for diff)
  const maxWait = 90000;
  const pollInterval = 2000;
  const startTime = Date.now();

  while (Date.now() - startTime < maxWait) {
    await new Promise(resolve => setTimeout(resolve, pollInterval));

    const status = await db.execute(sql`
      SELECT status, score, findings_count, duration
      FROM scans WHERE id = ${scanId}
    `);
    const scan = status.rows[0] as Record<string, unknown>;
    if (!scan) break;

    if (scan.status === 'completed') {
      const findings = await db.execute(sql`
        SELECT severity, title, description, file_path, line_number,
               rule_id, fix_available, fix_description
        FROM findings
        WHERE scan_id = ${scanId}
        ORDER BY
          CASE severity
            WHEN 'critical' THEN 1 WHEN 'high' THEN 2
            WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
          END
      `);

      const findingsList = findings.rows as Array<Record<string, unknown>>;
      const criticalOrHigh = findingsList.filter(
        f => f.severity === 'critical' || f.severity === 'high'
      );

      return {
        status: 'completed',
        scanId,
        baseBranch,
        scannersUsed: scanners,
        score: scan.score,
        findingsCount: scan.findings_count,
        duration: scan.duration,
        findings: findingsList,
        verdict: criticalOrHigh.length > 0
          ? 'BLOCK — critical/high severity issues found in diff'
          : findingsList.length > 0
            ? 'WARN — non-critical issues found, review recommended'
            : 'PASS — no security issues found in diff',
        hint: 'Use codehardener_fix with a findingId to get detailed fix guidance.',
      };
    }

    if (scan.status === 'failed') {
      return { status: 'failed', scanId, message: 'Diff scan failed.' };
    }
  }

  return {
    status: 'timeout',
    scanId,
    message: 'Diff scan is still running. Use codehardener_status to check.',
  };
}
