import type { Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendSuccess } from '../utils/apiResponse.js';
import { calculateQualityScore } from '../services/assurance/quality-score.js';

export async function getDashboardSummary(req: Request, res: Response) {
  const userId = req.user!.id;

  // Get aggregated dashboard data
  const [projectStats, scanStats, findingStats, recentScans, recentProjects] = await Promise.all([
    // Project count
    db.execute(sql`
      SELECT COUNT(*) as count FROM projects WHERE user_id = ${userId}
    `),
    // Scan stats this month
    db.execute(sql`
      SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE s.status = 'completed') as completed,
        AVG(s.score) FILTER (WHERE s.score IS NOT NULL) as avg_score
      FROM scans s
      JOIN projects p ON p.id = s.project_id
      WHERE p.user_id = ${userId}
      AND s.created_at >= date_trunc('month', CURRENT_DATE)
    `),
    // Finding stats — scoped to latest completed scan per project
    db.execute(sql`
      SELECT
        COUNT(*) FILTER (WHERE f.status = 'open') as open_total,
        COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'critical') as critical,
        COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'high') as high,
        COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'medium') as medium,
        COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'low') as low
      FROM findings f
      JOIN (
        SELECT DISTINCT ON (s.project_id) s.id
        FROM scans s
        JOIN projects p ON p.id = s.project_id
        WHERE p.user_id = ${userId} AND s.status = 'completed'
        ORDER BY s.project_id, s.created_at DESC
      ) latest ON latest.id = f.scan_id
    `),
    // Recent scans — compute live open-finding counts instead of stale JSONB
    db.execute(sql`
      SELECT s.id, s.status, s.score, s.score_raw, s.quality_level, s.created_at, s.project_id,
             p.name as project_name,
             (SELECT jsonb_build_object(
               'critical', COUNT(*) FILTER (WHERE f.severity = 'critical' AND f.status = 'open'),
               'high',     COUNT(*) FILTER (WHERE f.severity = 'high'     AND f.status = 'open'),
               'medium',   COUNT(*) FILTER (WHERE f.severity = 'medium'   AND f.status = 'open'),
               'low',      COUNT(*) FILTER (WHERE f.severity = 'low'      AND f.status = 'open'),
               'info',     COUNT(*) FILTER (WHERE f.severity = 'info'     AND f.status = 'open')
             ) FROM findings f WHERE f.scan_id = s.id) as findings_count
      FROM scans s
      JOIN projects p ON p.id = s.project_id
      WHERE p.user_id = ${userId}
      ORDER BY s.created_at DESC
      LIMIT 5
    `),
    // Recent projects
    db.execute(sql`
      SELECT p.id, p.name, p.updated_at,
        (SELECT score FROM scans WHERE project_id = p.id ORDER BY created_at DESC LIMIT 1) as last_score,
        (SELECT MAX(created_at) FROM scans WHERE project_id = p.id) as last_scan_at
      FROM projects p
      WHERE p.user_id = ${userId}
      ORDER BY p.updated_at DESC
      LIMIT 5
    `),
  ]);

  const projectCount = parseInt((projectStats.rows[0] as any).count);
  const scans = scanStats.rows[0] as any;
  const findings = findingStats.rows[0] as any;

  // Security score = computed from the same aggregated findings the dashboard displays
  // This ensures the score and open findings counts are always consistent
  const openCounts = {
    critical: parseInt(findings.critical) || 0,
    high: parseInt(findings.high) || 0,
    medium: parseInt(findings.medium) || 0,
    low: parseInt(findings.low) || 0,
    info: 0,
    total: parseInt(findings.open_total) || 0,
  };
  const { score: qualityScore } = calculateQualityScore(openCounts);

  // Determine score trend based on recent scans
  let scoreTrend: 'up' | 'down' | 'stable' = 'stable';
  if (recentScans.rows.length >= 2) {
    const latest = (recentScans.rows[0] as any).score;
    const previous = (recentScans.rows[1] as any).score;
    if (latest !== null && previous !== null) {
      if (latest > previous + 10) scoreTrend = 'up';
      else if (latest < previous - 10) scoreTrend = 'down';
    }
  }

  // Score history for trendline chart (last 10 completed scans, chronological)
  const scoreHistoryResult = await db.execute(sql`
    SELECT s.score, s.created_at, p.name as project_name
    FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE p.user_id = ${userId}
      AND s.score IS NOT NULL
      AND s.status = 'completed'
    ORDER BY s.created_at ASC
    LIMIT 20
  `);
  const scoreHistory = scoreHistoryResult.rows.map((row: any) => ({
    score: row.score,
    date: row.created_at,
    project: row.project_name,
  }));

  // Get critical findings — scoped to latest completed scan per project
  const criticalFindings = await db.execute(sql`
    SELECT f.id, f.title, f.severity, f.tool_name as scanner,
           f.file_path, f.line_number, f.fix_available, f.created_at,
           p.id as project_id, p.name as project_name
    FROM findings f
    JOIN (
      SELECT DISTINCT ON (s.project_id) s.id, s.project_id
      FROM scans s
      JOIN projects p ON p.id = s.project_id
      WHERE p.user_id = ${userId} AND s.status = 'completed'
      ORDER BY s.project_id, s.created_at DESC
    ) latest ON latest.id = f.scan_id
    JOIN projects p ON p.id = latest.project_id
    WHERE f.status = 'open'
    AND f.severity = 'critical'
    ORDER BY f.created_at DESC
    LIMIT 5
  `);

  // Transform recent scans to expected format
  const transformedScans = recentScans.rows.map((row: any) => {
    const findingsCount = row.findings_count as Record<string, number> | null;
    return {
      id: row.id,
      projectId: row.project_id,
      projectName: row.project_name,
      status: row.status,
      score: row.score,
      scoreRaw: row.score_raw ?? row.score,
      qualityLevel: row.quality_level,
      createdAt: row.created_at,
      findingsCount: {
        critical: findingsCount?.critical ?? 0,
        high: findingsCount?.high ?? 0,
        medium: findingsCount?.medium ?? 0,
        low: findingsCount?.low ?? 0,
        info: findingsCount?.info ?? 0,
      },
    };
  });

  // Transform recent projects to expected format
  const transformedProjects = recentProjects.rows.map((row: any) => ({
    id: row.id,
    name: row.name,
    updatedAt: row.updated_at,
    lastScore: row.last_score,
    lastScanAt: row.last_scan_at,
  }));

  // Transform critical findings to expected format
  const transformedCriticalFindings = criticalFindings.rows.map((row: any) => ({
    id: row.id,
    title: row.title,
    titleSimple: row.title, // Use title as titleSimple for now
    severity: row.severity,
    scanner: row.scanner,
    filePath: row.file_path || '',
    lineNumber: row.line_number || 0,
    fixAvailable: row.fix_available || false,
    createdAt: row.created_at,
    project: {
      id: row.project_id,
      name: row.project_name,
    },
  }));

  const summary = {
    qualityScore,
    scoreTrend,
    projectCount,
    openFindings: {
      total: parseInt(findings.open_total) || 0,
      critical: parseInt(findings.critical) || 0,
      high: parseInt(findings.high) || 0,
      medium: parseInt(findings.medium) || 0,
      low: parseInt(findings.low) || 0,
    },
    scansThisMonth: parseInt(scans.total) || 0,
    scanLimit: null, // No limit for now
    scoreHistory,
    recentScans: transformedScans,
    recentProjects: transformedProjects,
    criticalFindings: transformedCriticalFindings,
  };

  return sendSuccess(res, summary);
}

export async function getSecurityTrend(req: Request, res: Response) {
  const userId = req.user!.id;
  const { days } = z.object({
    days: z.coerce.number().int().min(1).max(90).default(30),
  }).passthrough().parse(req.query);

  const result = await db.execute(sql`
    SELECT
      date_trunc('day', s.created_at)::date as date,
      AVG(s.score) FILTER (WHERE s.score IS NOT NULL) as avg_score,
      COUNT(*) as scan_count,
      SUM(CASE WHEN s.status = 'completed' THEN 1 ELSE 0 END) as completed_count
    FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE p.user_id = ${userId}
    AND s.created_at >= CURRENT_DATE - ${days}::integer
    GROUP BY date_trunc('day', s.created_at)::date
    ORDER BY date
  `);

  return sendSuccess(res, result.rows);
}

export async function getScannerBreakdown(req: Request, res: Response) {
  const userId = req.user!.id;

  // Scoped to latest completed scan per project
  const result = await db.execute(sql`
    SELECT
      f.tool_name as scanner,
      COUNT(*) as total,
      COUNT(*) FILTER (WHERE f.status = 'open') as open,
      COUNT(*) FILTER (WHERE f.severity = 'critical') as critical,
      COUNT(*) FILTER (WHERE f.severity = 'high') as high
    FROM findings f
    JOIN (
      SELECT DISTINCT ON (s.project_id) s.id
      FROM scans s
      JOIN projects p ON p.id = s.project_id
      WHERE p.user_id = ${userId} AND s.status = 'completed'
      ORDER BY s.project_id, s.created_at DESC
    ) latest ON latest.id = f.scan_id
    GROUP BY f.tool_name
    ORDER BY total DESC
  `);

  return sendSuccess(res, result.rows);
}

export async function getActivityFeed(req: Request, res: Response) {
  const userId = req.user!.id;
  const { limit } = z.object({
    limit: z.coerce.number().int().min(1).max(50).default(20),
  }).passthrough().parse(req.query);

  // Combine scans and finding status changes into activity feed
  const result = await db.execute(sql`
    (
      SELECT
        'scan' as type,
        s.id,
        s.status,
        s.score,
        s.created_at as timestamp,
        p.name as project_name,
        NULL as finding_title
      FROM scans s
      JOIN projects p ON p.id = s.project_id
      WHERE p.user_id = ${userId}
      ORDER BY s.created_at DESC
      LIMIT ${limit}
    )
    UNION ALL
    (
      SELECT
        'finding_resolved' as type,
        f.id,
        f.status,
        NULL::integer as score,
        f.dismissed_at as timestamp,
        p.name as project_name,
        f.title as finding_title
      FROM findings f
      JOIN scans sc ON sc.id = f.scan_id
      JOIN projects p ON p.id = sc.project_id
      WHERE p.user_id = ${userId}
      AND f.status = 'fixed'
      AND f.dismissed_at IS NOT NULL
      ORDER BY f.dismissed_at DESC
      LIMIT ${limit}
    )
    ORDER BY timestamp DESC
    LIMIT ${limit}
  `);

  return sendSuccess(res, result.rows);
}
