import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { enforceProjectLimit } from '../middleware/tierEnforcement.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  listProjects,
  getProject,
  createProject,
  updateProject,
  deleteProject,
  getProjectStats,
  updateAuthConfig,
  deleteAuthConfig,
} from '../controllers/projects.controller.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

router.get('/', asyncHandler(listProjects));
router.post('/', enforceProjectLimit, asyncHandler(createProject));
router.get('/:id', asyncHandler(getProject));
router.patch('/:id', asyncHandler(updateProject));
router.delete('/:id', asyncHandler(deleteProject));
router.get('/:id/stats', asyncHandler(getProjectStats));
router.put('/:id/auth-config', asyncHandler(updateAuthConfig));
router.delete('/:id/auth-config', asyncHandler(deleteAuthConfig));

export { router as projectRoutes };
