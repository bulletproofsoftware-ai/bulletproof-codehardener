import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  getAvailableEvents,
  listWebhooks,
  getWebhook,
  createWebhook,
  updateWebhook,
  deleteWebhook,
  regenerateWebhookSecret,
  getWebhookDeliveries,
  retryWebhookDelivery,
  testWebhook,
} from '../controllers/webhooks.controller.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

router.get('/events', asyncHandler(getAvailableEvents));
router.get('/', asyncHandler(listWebhooks));
router.post('/', asyncHandler(createWebhook));
router.get('/:id', asyncHandler(getWebhook));
router.patch('/:id', asyncHandler(updateWebhook));
router.delete('/:id', asyncHandler(deleteWebhook));
router.post('/:id/regenerate-secret', asyncHandler(regenerateWebhookSecret));
router.get('/:id/deliveries', asyncHandler(getWebhookDeliveries));
router.post('/:id/deliveries/:deliveryId/retry', asyncHandler(retryWebhookDelivery));
router.post('/:id/test', asyncHandler(testWebhook));

export { router as webhookRoutes };
