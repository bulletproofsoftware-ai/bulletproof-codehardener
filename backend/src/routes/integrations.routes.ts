import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  listIntegrations,
  getIntegration,
  connectIntegration,
  disconnectIntegration,
  updateIntegration,
} from '../controllers/integrations.controller.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

router.get('/', asyncHandler(listIntegrations));
router.get('/:provider', asyncHandler(getIntegration));
router.post('/:provider/connect', asyncHandler(connectIntegration));
router.post('/:provider/disconnect', asyncHandler(disconnectIntegration));
router.put('/:provider', asyncHandler(updateIntegration));

export { router as integrationRoutes };
