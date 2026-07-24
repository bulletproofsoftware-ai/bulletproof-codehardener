import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  listTools,
  getTool,
  listProfiles,
  getProfile,
  getToolsForLanguage,
  getCategories,
  checkToolHealth,
  recommendTools,
} from '../controllers/tools.controller.js';

const router = Router();

// Public routes - tool info doesn't require auth
router.get('/', asyncHandler(listTools));
router.get('/categories', asyncHandler(getCategories));
router.get('/profiles', asyncHandler(listProfiles));
router.get('/profiles/:profileId', asyncHandler(getProfile));
router.get('/language/:language', asyncHandler(getToolsForLanguage));
router.get('/:toolId', asyncHandler(getTool));
router.get('/:toolId/health', asyncHandler(checkToolHealth));

// Authenticated routes
router.use(authenticate);
router.post('/recommend', asyncHandler(recommendTools));

export { router as toolsRoutes };
