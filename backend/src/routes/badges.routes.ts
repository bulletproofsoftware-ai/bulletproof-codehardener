import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  getPublicBadge,
  listBadges,
  getBadge,
  createBadge,
  updateBadge,
  deleteBadge,
  regenerateBadgeToken,
  previewBadge,
} from '../controllers/badges.controller.js';

const router = Router();

// Public route (no auth required)
router.get('/public/:token', asyncHandler(getPublicBadge));

// All other routes require authentication
router.use(authenticate);

router.get('/', asyncHandler(listBadges));
router.post('/', asyncHandler(createBadge));
router.get('/:id', asyncHandler(getBadge));
router.patch('/:id', asyncHandler(updateBadge));
router.delete('/:id', asyncHandler(deleteBadge));
router.post('/:id/regenerate-token', asyncHandler(regenerateBadgeToken));
router.get('/:id/preview', asyncHandler(previewBadge));

export { router as badgeRoutes };
