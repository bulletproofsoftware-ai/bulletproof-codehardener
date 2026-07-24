import { db } from '../../../db/client.js';
import { sql } from 'drizzle-orm';
import { getDefectDojoClient } from '../../defectdojo/client.js';
export const queryDefectdojoTools = [
  {
    name: 'codehardener_get_findings',
    description:
      'Query security findings with filters. Returns findings from DefectDojo if available, otherwise from local database.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        projectId: {
          type: 'string',
          description: 'Filter by project ID',
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'info'],
          description: 'Filter by severity',
        },
        status: {
          type: 'string',
          enum: ['open', 'fixed', 'ignored', 'false_positive', 'deferred'],
          description: 'Filter by status (default: open)',
        },
        limit: {
          type: 'number',
          description: 'Max findings to return (default: 25)',
        },
      },
    },
  },
  {
    name: 'codehardener_get_quality_score',
    description:
      'Get the current quality score and finding breakdown for a project.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        projectId: {
          type: 'string',
          description: 'Project ID',
        },
      },
      required: ['projectId'],
    },
  },
  {
    name: 'codehardener_get_trends',
    description:
      'Get historical scan data and score trends for a project.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        projectId: {
          type: 'string',
          description: 'Project ID',
        },
        days: {
          type: 'number',
          description: 'Number of days to look back (default: 30)',
        },
      },
      required: ['projectId'],
    },
  },
];

export async function handleGetFindings(
  args: Record<string, unknown>,
  userId: string
): Promise<unknown> {
  const projectId = args.projectId as string | undefined;
  const severity = args.severity as string | undefined;
  const status = (args.status as string) || 'open';
  const limit = (args.limit as number) || 25;

  // Try DefectDojo first
  const client = getDefectDojoClient();
  if (client.isEnabled() && projectId) {
    const productResult = await db.execute(sql`
      SELECT defectdojo_product_id FROM projects
      WHERE id = ${projectId} AND user_id = ${userId}
    `);

    const row = productResult.rows[0] as Record<string, unknown> | undefined;
    if (row?.defectdojo_product_id) {
      const ddFindings = await client.getFindings(
        row.defectdojo_product_id as number,
        { severity: severity ? severity.charAt(0).toUpperCase() + severity.slice(1) : undefined, active: status === 'open', limit }
      );

      if (ddFindings) {
        return {
          source: 'defectdojo',
          total: ddFindings.count,
          findings: ddFindings.results.map(f => ({
            id: f.id,
            title: f.title,
            severity: f.severity.toLowerCase(),
            description: f.description,
            filePath: f.file_path,
            line: f.line,
            active: f.active,
          })),
        };
      }
    }
  }

  // Fallback to local DB
  const conditions = [sql`p.user_id = ${userId}`];
  if (projectId) conditions.push(sql`f.project_id = ${projectId}`);
  if (severity) conditions.push(sql`f.severity = ${severity}`);
  if (status === 'open') conditions.push(sql`f.status = 'open'`);
  else if (status) conditions.push(sql`f.status = ${status}`);

  const whereClause = conditions.reduce((acc, cond, i) => i === 0 ? cond : sql`${acc} AND ${cond}`);

  const result = await db.execute(sql`
    SELECT f.id, f.severity, f.title, f.description, f.file_path, f.line_number,
           f.scanner, f.status, f.fix_available, f.created_at
    FROM findings f
    JOIN projects p ON p.id = f.project_id
    WHERE ${whereClause}
    ORDER BY
      CASE f.severity
        WHEN 'critical' THEN 1 WHEN 'high' THEN 2
        WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
      END
    LIMIT ${limit}
  `);

  return {
    source: 'local',
    total: result.rows.length,
    findings: result.rows,
  };
}

export async function handleGetQualityScore(
  args: Record<string, unknown>,
  userId: string
): Promise<unknown> {
  const projectId = args.projectId as string;

  // Try DefectDojo metrics
  const client = getDefectDojoClient();
  if (client.isEnabled()) {
    const productResult = await db.execute(sql`
      SELECT defectdojo_product_id, name, last_score FROM projects
      WHERE id = ${projectId} AND user_id = ${userId}
    `);

    const row = productResult.rows[0] as Record<string, unknown> | undefined;
    if (row?.defectdojo_product_id) {
      const metrics = await client.getProductMetrics(row.defectdojo_product_id as number);
      if (metrics) {
        return {
          source: 'defectdojo',
          projectName: row.name,
          score: row.last_score,
          findings: {
            critical: metrics.critical,
            high: metrics.high,
            medium: metrics.medium,
            low: metrics.low,
            info: metrics.info,
            total: metrics.total,
          },
        };
      }
    }
  }

  // Fallback to local
  const result = await db.execute(sql`
    SELECT p.name, p.last_score,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = p.id AND f.status = 'open' AND f.severity = 'critical') as critical,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = p.id AND f.status = 'open' AND f.severity = 'high') as high,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = p.id AND f.status = 'open' AND f.severity = 'medium') as medium,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = p.id AND f.status = 'open' AND f.severity = 'low') as low
    FROM projects p
    WHERE p.id = ${projectId} AND p.user_id = ${userId}
  `);

  if (result.rows.length === 0) {
    return { error: 'Project not found' };
  }

  const p = result.rows[0] as Record<string, unknown>;
  return {
    source: 'local',
    projectName: p.name,
    score: p.last_score,
    findings: {
      critical: parseInt(p.critical as string) || 0,
      high: parseInt(p.high as string) || 0,
      medium: parseInt(p.medium as string) || 0,
      low: parseInt(p.low as string) || 0,
    },
  };
}

export async function handleGetTrends(
  args: Record<string, unknown>,
  userId: string
): Promise<unknown> {
  const projectId = args.projectId as string;
  const days = (args.days as number) || 30;

  const result = await db.execute(sql`
    SELECT s.id, s.score, s.quality_level, s.findings_count, s.duration,
           s.completed_at, s.profile
    FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE s.project_id = ${projectId}
      AND p.user_id = ${userId}
      AND s.status = 'completed'
      AND s.completed_at >= NOW() - INTERVAL '1 day' * ${days}
    ORDER BY s.completed_at DESC
  `);

  const scans = result.rows as Record<string, unknown>[];
  const scores = scans.map(s => s.score as number).filter(Boolean);

  return {
    projectId,
    period: `${days} days`,
    totalScans: scans.length,
    scans: scans.map(s => ({
      scanId: s.id,
      score: s.score,
      qualityLevel: s.quality_level,
      findingsCount: s.findings_count,
      completedAt: s.completed_at,
      profile: s.profile,
    })),
    trend: {
      current: scores[0] || 0,
      average: scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0,
      best: scores.length > 0 ? Math.max(...scores) : 0,
      worst: scores.length > 0 ? Math.min(...scores) : 0,
      direction: scores.length >= 2 ? (scores[0] > scores[1] ? 'improving' : scores[0] < scores[1] ? 'degrading' : 'stable') : 'insufficient_data',
    },
  };
}
