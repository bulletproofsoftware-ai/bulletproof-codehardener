import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  listSuppressions,
  createSuppression,
  updateSuppression,
  deleteSuppression,
} from '../controllers/suppressions.controller.js';

const router = Router();

router.use(authenticate);

router.get('/', asyncHandler(listSuppressions));
router.post('/', asyncHandler(createSuppression));
router.patch('/:id', asyncHandler(updateSuppression));
router.delete('/:id', asyncHandler(deleteSuppression));

export { router as suppressionRoutes };
