import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import {
  runTests,
  getTestStatus,
  getTestHistory,
  getTestDetails,
} from '../controllers/tests.controller.js';

const router = Router();

// Run tests (requires auth for audit trail)
router.post('/run', authenticate, asyncHandler(runTests));

// Get test run status
router.get('/status/:runId', authenticate, asyncHandler(getTestStatus));

// Get test history
router.get('/history', authenticate, asyncHandler(getTestHistory));

// Get specific test run details
router.get('/:runId', authenticate, asyncHandler(getTestDetails));

export { router as testsRoutes };
