import { Request, Response } from 'express';
import Stripe from 'stripe';
import { pool } from '../db/client.js';
import { env, stripeEnabled } from '../config/env.js';
import { createLogger } from '../utils/logger.js';
import { apiSuccess, apiError } from '../utils/apiResponse.js';

// Initialize Stripe lazily
let stripeClient: Stripe | null = null;
function getStripe(): Stripe {
  if (!stripeClient) {
    if (!env.STRIPE_SECRET_KEY) throw new Error('Stripe not configured');
    stripeClient = new Stripe(env.STRIPE_SECRET_KEY, { apiVersion: '2024-12-18.acacia' as Stripe.LatestApiVersion });
  }
  return stripeClient;
}

const logger = createLogger('billing-controller');

// Plan definitions
const PLANS = {
  free: {
    id: 'free',
    name: 'Free',
    price: 0,
    interval: 'month',
    limits: {
      projects: 3,
      scansPerMonth: 200,
      teamMembers: 1,
      retention: 30, // days
    },
    features: [
      '3 projects',
      '200 scans/month',
      '30-day retention',
      'Community support',
      'Basic reports',
    ],
  },
  pro: {
    id: 'pro',
    name: 'Pro',
    price: 1900, // cents
    interval: 'month',
    limits: {
      projects: 10,
      scansPerMonth: -1, // unlimited
      teamMembers: 1,
      retention: 90,
    },
    features: [
      '10 projects',
      'Unlimited scans',
      '90-day retention',
      'Email support',
      'Advanced reports',
      'API access',
      'Custom policies',
    ],
  },
  team: {
    id: 'team',
    name: 'Team',
    price: 3900, // cents per seat
    interval: 'month',
    limits: {
      projects: 50,
      scansPerMonth: -1,
      teamMembers: -1, // unlimited
      retention: 180,
    },
    features: [
      '50 projects',
      'Unlimited scans',
      '180-day retention',
      'Priority support',
      'SSO/SAML',
      'Slack integration',
      'Custom policies',
      'Team management',
      'Audit logs',
    ],
  },
  enterprise: {
    id: 'enterprise',
    name: 'Enterprise',
    price: -1, // custom
    interval: 'month',
    limits: {
      projects: -1,
      scansPerMonth: -1,
      teamMembers: -1,
      retention: 365,
    },
    features: [
      'Unlimited projects',
      'Unlimited scans',
      '1-year retention',
      'Dedicated support',
      'Self-hosted option',
      'FedRAMP compliance',
      'Custom SLA',
      'Advanced integrations',
      'Custom training',
    ],
  },
};

// Get available plans
export async function getPlans(_req: Request, res: Response) {
  const plans = Object.values(PLANS).map((plan) => ({
    id: plan.id,
    name: plan.name,
    price: plan.price,
    interval: plan.interval,
    limits: plan.limits,
    features: plan.features,
  }));

  return apiSuccess(res, plans);
}

// Get current subscription
export async function getSubscription(req: Request, res: Response) {
  const userId = req.user!.id;

  const result = await pool.query<{
    id: string;
    plan_id: string;
    status: string;
    current_period_start: Date;
    current_period_end: Date;
    cancel_at_period_end: boolean;
    seats: number;
    created_at: Date;
  }>(
    `SELECT id, plan_id, status, current_period_start, current_period_end,
            cancel_at_period_end, seats, created_at
     FROM subscriptions
     WHERE user_id = $1 AND status IN ('active', 'trialing', 'past_due')
     ORDER BY created_at DESC
     LIMIT 1`,
    [userId]
  );

  if (result.rows.length === 0) {
    // Return free plan by default
    const freePlan = PLANS.free;
    return apiSuccess(res, {
      plan: {
        id: freePlan.id,
        name: freePlan.name,
        price: freePlan.price,
        interval: freePlan.interval,
      },
      status: 'active',
      limits: freePlan.limits,
      features: freePlan.features,
      seats: 1,
      currentPeriodStart: null,
      currentPeriodEnd: null,
      cancelAtPeriodEnd: false,
    });
  }

  const sub = result.rows[0];
  const plan = PLANS[sub.plan_id as keyof typeof PLANS] || PLANS.free;

  return apiSuccess(res, {
    id: sub.id,
    plan: {
      id: plan.id,
      name: plan.name,
      price: plan.price,
      interval: plan.interval,
    },
    status: sub.status,
    limits: plan.limits,
    features: plan.features,
    seats: sub.seats,
    currentPeriodStart: sub.current_period_start?.toISOString(),
    currentPeriodEnd: sub.current_period_end?.toISOString(),
    cancelAtPeriodEnd: sub.cancel_at_period_end,
  });
}

// Get usage stats
export async function getUsage(req: Request, res: Response) {
  const userId = req.user!.id;

  // Get current plan limits
  const subResult = await pool.query<{ plan_id: string }>(
    `SELECT plan_id FROM subscriptions
     WHERE user_id = $1 AND status IN ('active', 'trialing')
     LIMIT 1`,
    [userId]
  );

  const planId = subResult.rows[0]?.plan_id || 'free';
  const plan = PLANS[planId as keyof typeof PLANS] || PLANS.free;

  // Count projects
  const projectsResult = await pool.query<{ count: string }>(
    `SELECT COUNT(*) as count FROM projects WHERE user_id = $1`,
    [userId]
  );

  // Count scans this month (scans link to projects, not directly to users)
  const scansResult = await pool.query<{ count: string }>(
    `SELECT COUNT(*) as count FROM scans s
     JOIN projects p ON p.id = s.project_id
     WHERE p.user_id = $1
     AND s.created_at >= date_trunc('month', CURRENT_DATE)`,
    [userId]
  );

  // Count team members
  const teamResult = await pool.query<{ team_id: string }>(
    `SELECT team_id FROM team_members WHERE user_id = $1 AND status = 'active'`,
    [userId]
  );

  let teamMemberCount = 1;
  if (teamResult.rows.length > 0) {
    const countResult = await pool.query<{ count: string }>(
      `SELECT COUNT(*) as count FROM team_members
       WHERE team_id = $1 AND status = 'active'`,
      [teamResult.rows[0].team_id]
    );
    teamMemberCount = parseInt(countResult.rows[0].count, 10);
  }

  const projectCount = parseInt(projectsResult.rows[0].count, 10);
  const scanCount = parseInt(scansResult.rows[0].count, 10);

  return apiSuccess(res, {
    projects: {
      used: projectCount,
      limit: plan.limits.projects,
      percentage: plan.limits.projects > 0 ? Math.round((projectCount / plan.limits.projects) * 100) : 0,
    },
    scans: {
      used: scanCount,
      limit: plan.limits.scansPerMonth,
      percentage: plan.limits.scansPerMonth > 0 ? Math.round((scanCount / plan.limits.scansPerMonth) * 100) : 0,
    },
    teamMembers: {
      used: teamMemberCount,
      limit: plan.limits.teamMembers,
      percentage: plan.limits.teamMembers > 0 ? Math.round((teamMemberCount / plan.limits.teamMembers) * 100) : 0,
    },
    retention: {
      days: plan.limits.retention,
    },
  });
}

// Get billing history
export async function getBillingHistory(req: Request, res: Response) {
  const userId = req.user!.id;

  const result = await pool.query<{
    id: string;
    amount: number;
    currency: string;
    status: string;
    description: string;
    invoice_url: string | null;
    created_at: Date;
  }>(
    `SELECT id, amount, currency, status, description, invoice_url, created_at
     FROM invoices
     WHERE user_id = $1
     ORDER BY created_at DESC
     LIMIT 24`,
    [userId]
  );

  const invoices = result.rows.map((row) => ({
    id: row.id,
    amount: row.amount,
    currency: row.currency,
    status: row.status,
    description: row.description,
    invoiceUrl: row.invoice_url,
    date: row.created_at.toISOString(),
  }));

  return apiSuccess(res, invoices);
}

// Get payment methods
export async function getPaymentMethods(req: Request, res: Response) {
  const userId = req.user!.id;

  const result = await pool.query<{
    id: string;
    type: string;
    last4: string;
    brand: string;
    exp_month: number;
    exp_year: number;
    is_default: boolean;
  }>(
    `SELECT id, type, last4, brand, exp_month, exp_year, is_default
     FROM payment_methods
     WHERE user_id = $1
     ORDER BY is_default DESC, created_at DESC`,
    [userId]
  );

  const methods = result.rows.map((row) => ({
    id: row.id,
    type: row.type,
    last4: row.last4,
    brand: row.brand,
    expiryMonth: row.exp_month,
    expiryYear: row.exp_year,
    isDefault: row.is_default,
  }));

  return apiSuccess(res, methods);
}

// Create checkout session with Stripe
export async function createCheckoutSession(req: Request, res: Response) {
  const userId = req.user!.id;
  const { planId, seats } = req.body;

  if (!planId || !PLANS[planId as keyof typeof PLANS]) {
    return apiError(res, 'Invalid plan', 400);
  }

  const plan = PLANS[planId as keyof typeof PLANS];

  if (plan.price === -1) {
    return apiError(res, 'Please contact sales for Enterprise pricing', 400);
  }

  if (plan.price === 0) {
    return apiError(res, 'Free plan does not require checkout', 400);
  }

  if (!stripeEnabled) {
    return apiError(res, 'Stripe billing not configured. Set STRIPE_SECRET_KEY to enable.', 503);
  }

  const priceId = planId === 'pro'
    ? env.STRIPE_PRICE_PRO_MONTHLY
    : planId === 'team'
      ? env.STRIPE_PRICE_TEAM_MONTHLY
      : null;

  if (!priceId) {
    return apiError(res, `No Stripe price configured for plan: ${planId}`, 503);
  }

  logger.info({ userId, planId, seats }, 'Creating Stripe checkout session');

  const lineItem: Stripe.Checkout.SessionCreateParams.LineItem = {
    price: priceId,
    quantity: planId === 'team' ? (seats || 1) : 1,
  };

  const session = await getStripe().checkout.sessions.create({
    mode: 'subscription',
    line_items: [lineItem],
    metadata: { userId, planId },
    success_url: `${req.headers.origin}/settings/billing?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${req.headers.origin}/settings/billing`,
  });

  logger.info({ userId, sessionId: session.id }, 'Stripe checkout session created');

  return apiSuccess(res, {
    sessionId: session.id,
    url: session.url,
  });
}

// Create Stripe customer portal session
export async function createPortalSession(req: Request, res: Response) {
  const userId = req.user!.id;

  if (!stripeEnabled) {
    return apiError(res, 'Stripe billing not configured. Set STRIPE_SECRET_KEY to enable.', 503);
  }

  const result = await pool.query<{ stripe_customer_id: string }>(
    `SELECT stripe_customer_id FROM subscriptions
     WHERE user_id = $1 AND stripe_customer_id IS NOT NULL
     ORDER BY created_at DESC
     LIMIT 1`,
    [userId]
  );

  if (result.rows.length === 0 || !result.rows[0].stripe_customer_id) {
    return apiError(res, 'No billing account found', 404);
  }

  logger.info({ userId }, 'Creating Stripe portal session');

  const session = await getStripe().billingPortal.sessions.create({
    customer: result.rows[0].stripe_customer_id,
    return_url: `${req.headers.origin}/settings/billing`,
  });

  return apiSuccess(res, { url: session.url });
}

// Cancel subscription
export async function cancelSubscription(req: Request, res: Response) {
  const userId = req.user!.id;

  const result = await pool.query<{
    id: string;
    current_period_end: Date;
    stripe_subscription_id: string | null;
  }>(
    `UPDATE subscriptions
     SET cancel_at_period_end = true, updated_at = NOW()
     WHERE user_id = $1 AND status IN ('active', 'trialing')
     RETURNING id, current_period_end, stripe_subscription_id`,
    [userId]
  );

  if (result.rows.length === 0) {
    return apiError(res, 'No active subscription found', 404);
  }

  const sub = result.rows[0];

  // Cancel at period end in Stripe if connected
  if (stripeEnabled && sub.stripe_subscription_id) {
    try {
      await getStripe().subscriptions.update(sub.stripe_subscription_id, {
        cancel_at_period_end: true,
      });
      logger.info({ userId, stripeSubId: sub.stripe_subscription_id }, 'Stripe subscription set to cancel at period end');
    } catch (err) {
      logger.error({ err, stripeSubId: sub.stripe_subscription_id }, 'Failed to cancel Stripe subscription');
    }
  }

  logger.info({ userId, subscriptionId: sub.id }, 'Subscription cancelled');

  return apiSuccess(res, {
    message: 'Subscription will be cancelled at the end of the billing period',
    cancelAt: sub.current_period_end?.toISOString(),
  });
}

// Resume subscription
export async function resumeSubscription(req: Request, res: Response) {
  const userId = req.user!.id;

  const result = await pool.query<{
    id: string;
    stripe_subscription_id: string | null;
  }>(
    `UPDATE subscriptions
     SET cancel_at_period_end = false, updated_at = NOW()
     WHERE user_id = $1 AND status IN ('active', 'trialing') AND cancel_at_period_end = true
     RETURNING id, stripe_subscription_id`,
    [userId]
  );

  if (result.rows.length === 0) {
    return apiError(res, 'No cancelled subscription found', 404);
  }

  const sub = result.rows[0];

  // Resume in Stripe if connected
  if (stripeEnabled && sub.stripe_subscription_id) {
    try {
      await getStripe().subscriptions.update(sub.stripe_subscription_id, {
        cancel_at_period_end: false,
      });
      logger.info({ userId, stripeSubId: sub.stripe_subscription_id }, 'Stripe subscription resumed');
    } catch (err) {
      logger.error({ err, stripeSubId: sub.stripe_subscription_id }, 'Failed to resume Stripe subscription');
    }
  }

  logger.info({ userId, subscriptionId: sub.id }, 'Subscription resumed');

  return apiSuccess(res, {
    message: 'Subscription has been resumed',
  });
}

// --- Stripe Webhook Handling ---

export async function handleStripeWebhook(req: Request, res: Response) {
  if (!stripeEnabled || !env.STRIPE_WEBHOOK_SECRET) {
    return apiError(res, 'Stripe webhooks not configured', 503);
  }

  const sig = req.headers['stripe-signature'] as string;
  let event: Stripe.Event;

  // Use rawBody captured by the global body parser verify callback.
  // This is necessary because express.json() consumes the stream before
  // route-level middleware can access it, and Stripe needs the raw body
  // for signature verification.
  const rawBody = req.rawBody || req.body;

  try {
    event = getStripe().webhooks.constructEvent(rawBody, sig, env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    logger.error({ err }, 'Stripe webhook signature verification failed');
    return res.status(400).send('Webhook signature verification failed');
  }

  logger.info({ eventType: event.type, eventId: event.id }, 'Stripe webhook received');

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session;
      await handleCheckoutCompleted(session);
      break;
    }
    case 'customer.subscription.updated': {
      const subscription = event.data.object as Stripe.Subscription;
      await handleSubscriptionUpdated(subscription);
      break;
    }
    case 'customer.subscription.deleted': {
      const subscription = event.data.object as Stripe.Subscription;
      await handleSubscriptionDeleted(subscription);
      break;
    }
    case 'invoice.payment_failed': {
      const invoice = event.data.object as Stripe.Invoice;
      await handlePaymentFailed(invoice);
      break;
    }
    default:
      logger.debug({ eventType: event.type }, 'Unhandled Stripe event');
  }

  return res.json({ received: true });
}

async function handleCheckoutCompleted(session: Stripe.Checkout.Session): Promise<void> {
  const userId = session.metadata?.userId;
  const planId = session.metadata?.planId;

  if (!userId || !planId) {
    logger.error({ sessionId: session.id, metadata: session.metadata }, 'Checkout session missing userId or planId in metadata');
    return;
  }

  const stripeSubscriptionId = typeof session.subscription === 'string'
    ? session.subscription
    : session.subscription?.id;
  const stripeCustomerId = typeof session.customer === 'string'
    ? session.customer
    : session.customer?.id;

  if (!stripeSubscriptionId) {
    logger.error({ sessionId: session.id }, 'Checkout session has no subscription ID');
    return;
  }

  // Fetch the full subscription to get period dates
  // Cast needed: Stripe SDK v20 removed current_period_start/end from TS types
  // but the API still returns them
  const stripeSub = await getStripe().subscriptions.retrieve(stripeSubscriptionId) as Stripe.Subscription & {
    current_period_start?: number;
    current_period_end?: number;
  };

  await pool.query(
    `INSERT INTO subscriptions (
       user_id, plan_id, status, stripe_subscription_id, stripe_customer_id,
       current_period_start, current_period_end, seats, created_at, updated_at
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
     ON CONFLICT (user_id)
     DO UPDATE SET
       plan_id = EXCLUDED.plan_id,
       status = EXCLUDED.status,
       stripe_subscription_id = EXCLUDED.stripe_subscription_id,
       stripe_customer_id = EXCLUDED.stripe_customer_id,
       current_period_start = EXCLUDED.current_period_start,
       current_period_end = EXCLUDED.current_period_end,
       seats = EXCLUDED.seats,
       updated_at = NOW()`,
    [
      userId,
      planId,
      'active',
      stripeSubscriptionId,
      stripeCustomerId || null,
      stripeSub.current_period_start ? new Date(stripeSub.current_period_start * 1000) : new Date(),
      stripeSub.current_period_end ? new Date(stripeSub.current_period_end * 1000) : new Date(),
      stripeSub.items.data[0]?.quantity || 1,
    ]
  );

  logger.info({ userId, planId, stripeSubscriptionId }, 'Subscription created from checkout');
}

async function handleSubscriptionUpdated(subscription: Stripe.Subscription): Promise<void> {
  const stripeSubscriptionId = subscription.id;
  // Cast: Stripe SDK v20 removed current_period_start/end from TS types
  const sub = subscription as Stripe.Subscription & {
    current_period_start?: number;
    current_period_end?: number;
  };

  await pool.query(
    `UPDATE subscriptions SET
       status = $1,
       current_period_start = $2,
       current_period_end = $3,
       cancel_at_period_end = $4,
       seats = $5,
       updated_at = NOW()
     WHERE stripe_subscription_id = $6`,
    [
      subscription.status,
      sub.current_period_start ? new Date(sub.current_period_start * 1000) : null,
      sub.current_period_end ? new Date(sub.current_period_end * 1000) : null,
      subscription.cancel_at_period_end,
      subscription.items.data[0]?.quantity || 1,
      stripeSubscriptionId,
    ]
  );

  logger.info({ stripeSubscriptionId, status: subscription.status }, 'Subscription updated from webhook');
}

async function handleSubscriptionDeleted(subscription: Stripe.Subscription): Promise<void> {
  const stripeSubscriptionId = subscription.id;

  await pool.query(
    `UPDATE subscriptions SET status = 'cancelled', updated_at = NOW()
     WHERE stripe_subscription_id = $1`,
    [stripeSubscriptionId]
  );

  logger.info({ stripeSubscriptionId }, 'Subscription cancelled from webhook');
}

async function handlePaymentFailed(invoice: Stripe.Invoice): Promise<void> {
  // Cast: Stripe SDK v20 changed invoice.subscription typing
  const invoiceSub = (invoice as unknown as Record<string, unknown>).subscription;
  const stripeSubscriptionId = typeof invoiceSub === 'string'
    ? invoiceSub
    : (invoiceSub as { id?: string } | null)?.id;

  if (!stripeSubscriptionId) {
    logger.warn({ invoiceId: invoice.id }, 'Payment failed invoice has no subscription ID');
    return;
  }

  // Mark subscription as past_due
  const result = await pool.query<{ user_id: string }>(
    `UPDATE subscriptions SET status = 'past_due', updated_at = NOW()
     WHERE stripe_subscription_id = $1
     RETURNING user_id`,
    [stripeSubscriptionId]
  );

  if (result.rows.length > 0) {
    const userId = result.rows[0].user_id;

    // Create a notification for the user
    await pool.query(
      `INSERT INTO notifications (user_id, type, title, message, created_at)
       VALUES ($1, 'billing', 'Payment Failed', 'Your latest payment failed. Please update your payment method to avoid service interruption.', NOW())`,
      [userId]
    );

    logger.warn({ userId, stripeSubscriptionId, invoiceId: invoice.id }, 'Payment failed, subscription marked past_due');
  }
}
