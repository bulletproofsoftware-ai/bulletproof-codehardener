import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  listFindings,
  getFinding,
  updateFinding,
  bulkUpdateFindings,
  getFindingStats,
  getTopFindings,
  getFindingPatches,
} from '../controllers/findings.controller.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

router.get('/', asyncHandler(listFindings));
router.get('/stats', asyncHandler(getFindingStats));
router.get('/top', asyncHandler(getTopFindings));
router.get('/:id', asyncHandler(getFinding));
router.get('/:id/patches', asyncHandler(getFindingPatches));
router.patch('/:id', asyncHandler(updateFinding));
router.patch('/:id/status', asyncHandler(updateFinding));  // Alias for status-only updates
router.post('/bulk-status', asyncHandler(bulkUpdateFindings));

export { router as findingRoutes };
