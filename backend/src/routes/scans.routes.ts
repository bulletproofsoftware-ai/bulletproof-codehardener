import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';
import { authenticate } from '../middleware/auth.js';
import { scanRateLimiter } from '../middleware/rateLimiter.js';
import { enforceScanLimit } from '../middleware/tierEnforcement.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  listScans,
  getScan,
  createScan,
  cancelScan,
  retryScan,
  getScanFindings,
  getScanAttestation,
  recalculateAllScores,
} from '../controllers/scans.controller.js';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { generateMarkdownReport } from '../services/reports/markdown-generator.js';
import { generateSarifReport } from '../services/reports/sarif-generator.js';
import { getScanDispositions } from '../services/reports/disposition-data.js';
import { sendSuccess } from '../utils/apiResponse.js';
import { NotFoundError } from '../middleware/errorHandler.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

router.get('/', asyncHandler(listScans));
router.post('/', scanRateLimiter, enforceScanLimit, asyncHandler(createScan));
router.get('/:id', asyncHandler(getScan));
router.post('/:id/cancel', asyncHandler(cancelScan));
router.post('/:id/retry', scanRateLimiter, enforceScanLimit, asyncHandler(retryScan));
router.get('/:id/findings', asyncHandler(getScanFindings));
router.get('/:id/attestation', asyncHandler(getScanAttestation));

// Dispositions: full audit trail of skipped scanners + suppressed/dismissed findings
// for this scan. Designed for coding agents and CI integrations to programmatically
// understand WHY a scan looks clean (or what was excluded).
router.get('/:id/dispositions', asyncHandler(async (req: Request, res: Response) => {
  const { id: scanId } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  // Ownership check
  const ownership = await db.execute(sql`
    SELECT s.id FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE s.id = ${scanId} AND p.user_id = ${userId}
  `);
  if (ownership.rows.length === 0) {
    throw new NotFoundError('Scan not found');
  }

  const dispositions = await getScanDispositions(scanId);
  return sendSuccess(res, dispositions);
}));
router.post('/recalculate-scores', asyncHandler(recalculateAllScores));

// Report shortcut — generate report directly from scan
router.get('/:id/report', asyncHandler(async (req: Request, res: Response) => {
  const { id: scanId } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;
  const reportQuerySchema = z.object({
    format: z.enum(['markdown', 'sarif']).default('markdown'),
    minSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    includeInfo: z.enum(['true', 'false']).optional(),
  }).passthrough();
  const { format, minSeverity, includeInfo } = reportQuerySchema.parse(req.query);

  if (format === 'sarif') {
    const sarif = await generateSarifReport(scanId, userId);
    res.setHeader('Content-Type', 'application/sarif+json');
    return res.json(sarif);
  }

  // Default: markdown
  const markdown = await generateMarkdownReport({
    scanId,
    userId,
    minSeverity,
    includeInfo: includeInfo === 'true',
  });

  res.setHeader('Content-Type', 'text/markdown');
  return res.send(markdown);
}));

export { router as scanRoutes };
