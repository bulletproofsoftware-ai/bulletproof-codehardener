import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  getAvailablePermissions,
  listApiKeys,
  getApiKey,
  createApiKey,
  updateApiKey,
  deleteApiKey,
  regenerateApiKey,
} from '../controllers/api-keys.controller.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

router.get('/permissions', asyncHandler(getAvailablePermissions));
router.get('/', asyncHandler(listApiKeys));
router.post('/', asyncHandler(createApiKey));
router.get('/:id', asyncHandler(getApiKey));
router.patch('/:id', asyncHandler(updateApiKey));
router.delete('/:id', asyncHandler(deleteApiKey));
router.post('/:id/regenerate', asyncHandler(regenerateApiKey));

export { router as apiKeyRoutes };
