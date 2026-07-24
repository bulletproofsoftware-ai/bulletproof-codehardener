import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  getDashboardSummary,
  getSecurityTrend,
  getScannerBreakdown,
  getActivityFeed,
} from '../controllers/dashboard.controller.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

router.get('/summary', asyncHandler(getDashboardSummary));
router.get('/trend', asyncHandler(getSecurityTrend));
router.get('/scanners', asyncHandler(getScannerBreakdown));
router.get('/activity', asyncHandler(getActivityFeed));

export { router as dashboardRoutes };
