import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import {
  listPolicies,
  getPolicy,
  createPolicy,
  updatePolicy,
  deletePolicy,
} from '../controllers/policies.controller.js';

const router = Router();

router.get('/', authenticate, listPolicies);
router.get('/:id', authenticate, getPolicy);
router.post('/', authenticate, createPolicy);
router.patch('/:id', authenticate, updatePolicy);
router.delete('/:id', authenticate, deletePolicy);

export { router as policiesRoutes };
