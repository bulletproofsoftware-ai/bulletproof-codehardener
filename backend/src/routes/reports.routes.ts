import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendSuccess, sendCreated, sendNoContent, sendValidationError } from '../utils/apiResponse.js';
import { NotFoundError } from '../middleware/errorHandler.js';
import { authenticate } from '../middleware/auth.js';
import { createLogger } from '../utils/logger.js';
import { generateMarkdownReport } from '../services/reports/markdown-generator.js';
import { generateSarifReport } from '../services/reports/sarif-generator.js';
import { getScanDispositions } from '../services/reports/disposition-data.js';

const router = Router();
const logger = createLogger('reports');

function transformReport(row: Record<string, unknown>) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    reportType: row.report_type,
    format: row.format,
    status: row.file_url ? 'completed' : 'pending',
    fileUrl: row.file_url,
    fileSize: row.file_size,
    projectId: row.project_id,
    projectName: row.project_name,
    scanId: row.scan_id,
    generatedAt: row.generated_at,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

// List reports
router.get('/', authenticate, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const userId = req.user!.id;
    const querySchema = z.object({
      page: z.coerce.number().int().positive().default(1),
      limit: z.coerce.number().int().min(1).max(100).default(20),
    }).passthrough();
    const { page, limit } = querySchema.parse(req.query);
    const offset = (page - 1) * limit;

    const [reports, countResult] = await Promise.all([
      db.execute(sql`
        SELECT r.*, p.name as project_name
        FROM reports r
        LEFT JOIN projects p ON p.id = r.project_id
        WHERE r.user_id = ${userId}
        ORDER BY r.created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `),
      db.execute(sql`
        SELECT COUNT(*) as count FROM reports WHERE user_id = ${userId}
      `),
    ]);

    const total = Number((countResult.rows[0] as Record<string, unknown>).count);

    sendSuccess(res, reports.rows.map(r => transformReport(r as Record<string, unknown>)), 200, {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    });
  } catch (error) {
    next(error);
  }
});

// Get single report
router.get('/:id', authenticate, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const userId = req.user!.id;
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const result = await db.execute(sql`
      SELECT r.*, p.name as project_name
      FROM reports r
      LEFT JOIN projects p ON p.id = r.project_id
      WHERE r.id = ${id} AND r.user_id = ${userId}
    `);

    if (result.rows.length === 0) {
      throw new NotFoundError('Report not found');
    }

    const report = transformReport(result.rows[0] as Record<string, unknown>);

    // If this is a scan report, include findings summary
    if (report.scanId) {
      const findingsResult = await db.execute(sql`
        SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE severity = 'critical') as critical,
          COUNT(*) FILTER (WHERE severity = 'high') as high,
          COUNT(*) FILTER (WHERE severity = 'medium') as medium,
          COUNT(*) FILTER (WHERE severity = 'low') as low,
          COUNT(*) FILTER (WHERE severity = 'info') as info
        FROM findings
        WHERE scan_id = ${report.scanId}
      `);
      (report as Record<string, unknown>).findingsSummary = findingsResult.rows[0];
    }

    sendSuccess(res, report);
  } catch (error) {
    next(error);
  }
});

const generateReportSchema = z.object({
  title: z.string().min(1).max(255),
  reportType: z.enum(['security_summary', 'compliance', 'vulnerability', 'executive', 'scan_detail']),
  format: z.enum(['pdf', 'html', 'json', 'csv', 'markdown', 'sarif']).default('pdf'),
  description: z.string().max(1000).optional(),
  projectId: z.string().uuid().optional(),
  scanId: z.string().uuid().optional(),
});

// Generate report
router.post('/', authenticate, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const parsed = generateReportSchema.safeParse(req.body);
    if (!parsed.success) {
      sendValidationError(res, parsed.error.errors.map(e => e.message).join(', '));
      return;
    }

    const userId = req.user!.id;
    const { title, reportType, format, description, projectId, scanId } = parsed.data;

    // Verify project belongs to user if specified
    if (projectId) {
      const proj = await db.execute(sql`
        SELECT id FROM projects WHERE id = ${projectId} AND user_id = ${userId}
      `);
      if (proj.rows.length === 0) {
        throw new NotFoundError('Project not found');
      }
    }

    // Verify scan belongs to user if specified
    if (scanId) {
      const scan = await db.execute(sql`
        SELECT s.id FROM scans s
        JOIN projects p ON p.id = s.project_id
        WHERE s.id = ${scanId} AND p.user_id = ${userId}
      `);
      if (scan.rows.length === 0) {
        throw new NotFoundError('Scan not found');
      }
    }

    // Generate report content based on format
    let reportContent: string;
    let contentType: string;

    if (format === 'markdown' && scanId) {
      reportContent = await generateMarkdownReport({ scanId, userId });
      contentType = 'text/markdown';
    } else if (format === 'sarif' && scanId) {
      const sarif = await generateSarifReport(scanId, userId);
      reportContent = JSON.stringify(sarif, null, 2);
      contentType = 'application/sarif+json';
    } else {
      // JSON / legacy formats — build report data from DB
      let reportData: Record<string, unknown> = {};

      if (reportType === 'scan_detail' && scanId) {
        const [scanResult, findingsResult, dispositions] = await Promise.all([
          db.execute(sql`
            SELECT s.*, p.name as project_name
            FROM scans s JOIN projects p ON p.id = s.project_id
            WHERE s.id = ${scanId}
          `),
          db.execute(sql`
            SELECT severity, scanner, title, file_path, line_number, status, rule_id, owasp_category,
              dismissed_reason, dismissed_comment, dismissed_at
            FROM findings WHERE scan_id = ${scanId}
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
          `),
          getScanDispositions(scanId),
        ]);
        reportData = {
          scan: scanResult.rows[0],
          findings: findingsResult.rows,
          // Full audit trail of skipped scanners + suppressed/dismissed findings
          // so the JSON report is self-contained evidence for compliance review.
          dispositions,
        };
      } else if (projectId) {
        const [scansResult, findingsResult] = await Promise.all([
          db.execute(sql`
            SELECT id, status, score, quality_level, findings_count, created_at
            FROM scans WHERE project_id = ${projectId}
            ORDER BY created_at DESC LIMIT 10
          `),
          db.execute(sql`
            SELECT
              COUNT(*) as total,
              COUNT(*) FILTER (WHERE severity = 'critical') as critical,
              COUNT(*) FILTER (WHERE severity = 'high') as high,
              COUNT(*) FILTER (WHERE severity = 'medium') as medium,
              COUNT(*) FILTER (WHERE severity = 'low') as low,
              COUNT(*) FILTER (WHERE f.status = 'open') as open,
              COUNT(*) FILTER (WHERE f.status = 'fixed') as fixed
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE s.project_id = ${projectId}
          `),
        ]);
        reportData = { recentScans: scansResult.rows, findingsSummary: findingsResult.rows[0] };
      } else {
        const summaryResult = await db.execute(sql`
          SELECT
            COUNT(DISTINCT p.id) as project_count,
            COUNT(DISTINCT s.id) as scan_count,
            COUNT(f.id) as total_findings,
            COUNT(f.id) FILTER (WHERE f.severity = 'critical') as critical,
            COUNT(f.id) FILTER (WHERE f.severity = 'high') as high,
            AVG(s.score) FILTER (WHERE s.score IS NOT NULL) as avg_score
          FROM projects p
          LEFT JOIN scans s ON s.project_id = p.id
          LEFT JOIN findings f ON f.scan_id = s.id
          WHERE p.user_id = ${userId}
        `);
        reportData = { summary: summaryResult.rows[0] };
      }

      reportContent = JSON.stringify(reportData);
      contentType = 'application/json';
    }

    // Insert the report record with content
    const result = await db.execute(sql`
      INSERT INTO reports (user_id, project_id, scan_id, report_type, format, title, description,
        file_url, file_size, report_content, content_type, generated_at)
      VALUES (${userId}, ${projectId || null}, ${scanId || null}, ${reportType}, ${format}, ${title}, ${description || null},
        ${`/reports/${Date.now()}-report.${format}`}, ${Buffer.byteLength(reportContent)},
        ${reportContent}, ${contentType}, NOW())
      RETURNING *
    `);

    const report = transformReport(result.rows[0] as Record<string, unknown>);
    logger.info({ reportId: report.id, reportType, format }, 'Report generated');

    sendCreated(res, report);
  } catch (error) {
    next(error);
  }
});

// Download report content
router.get('/:id/download', authenticate, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const userId = req.user!.id;
    const { id: reportId } = z.object({ id: z.string().uuid() }).parse(req.params);
    const result = await db.execute(sql`
      SELECT report_content, content_type, format, title
      FROM reports
      WHERE id = ${reportId} AND user_id = ${userId}
    `);

    if (result.rows.length === 0) {
      throw new NotFoundError('Report not found');
    }

    const row = result.rows[0] as Record<string, unknown>;
    const content = row.report_content as string;

    if (!content) {
      throw new NotFoundError('Report content not available');
    }

    // Allowlist safe content types to prevent XSS via content-type manipulation
    const SAFE_CONTENT_TYPES: Record<string, string> = {
      'text/markdown': 'text/markdown',
      'text/plain': 'text/plain',
      'application/json': 'application/json',
      'application/sarif+json': 'application/sarif+json',
      'application/octet-stream': 'application/octet-stream',
    };
    const rawContentType = (row.content_type as string) || 'application/octet-stream';
    const contentType = SAFE_CONTENT_TYPES[rawContentType] || 'application/octet-stream';
    const ext = row.format === 'markdown' ? 'md' : row.format === 'sarif' ? 'sarif.json' : row.format;
    const filename = `${(row.title as string || 'report').replace(/[^a-zA-Z0-9-_ ]/g, '')}.${ext}`;

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.send(content);
  } catch (error) {
    next(error);
  }
});

// Delete report
router.delete('/:id', authenticate, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const userId = req.user!.id;
    const { id: deleteId } = z.object({ id: z.string().uuid() }).parse(req.params);
    const result = await db.execute(sql`
      DELETE FROM reports WHERE id = ${deleteId} AND user_id = ${userId} RETURNING id
    `);

    if (result.rows.length === 0) {
      throw new NotFoundError('Report not found');
    }

    sendNoContent(res);
  } catch (error) {
    next(error);
  }
});

export { router as reportsRoutes };
