import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  createRegistryCredential,
  listRegistryCredentials,
  deleteRegistryCredential,
} from '../controllers/registry-credentials.controller.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

router.post('/', asyncHandler(createRegistryCredential));
router.get('/', asyncHandler(listRegistryCredentials));
router.delete('/:id', asyncHandler(deleteRegistryCredential));

export { router as registryCredentialRoutes };
