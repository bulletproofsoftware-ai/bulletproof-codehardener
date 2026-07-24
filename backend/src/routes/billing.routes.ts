import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  getPlans,
  getSubscription,
  getUsage,
  getBillingHistory,
  getPaymentMethods,
  createCheckoutSession,
  createPortalSession,
  cancelSubscription,
  resumeSubscription,
  handleStripeWebhook,
} from '../controllers/billing.controller.js';

const router = Router();

// Stripe webhook - uses req.rawBody captured by the global body parser verify callback
// Must be before authenticate middleware since Stripe sends unauthenticated POST requests
router.post('/webhook', asyncHandler(handleStripeWebhook));

// Plans endpoint is public
router.get('/plans', asyncHandler(getPlans));

// All other routes require authentication
router.use(authenticate);

router.get('/subscription', asyncHandler(getSubscription));
router.get('/usage', asyncHandler(getUsage));
router.get('/history', asyncHandler(getBillingHistory));
router.get('/payment-methods', asyncHandler(getPaymentMethods));
router.post('/checkout', asyncHandler(createCheckoutSession));
router.post('/portal', asyncHandler(createPortalSession));
router.post('/cancel', asyncHandler(cancelSubscription));
router.post('/resume', asyncHandler(resumeSubscription));

export { router as billingRoutes };
