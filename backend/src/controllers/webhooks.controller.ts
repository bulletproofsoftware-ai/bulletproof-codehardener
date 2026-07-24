import { Request, Response } from 'express';
import { z } from 'zod';
import crypto from 'node:crypto';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../utils/logger.js';
import { apiSuccess, apiError } from '../utils/apiResponse.js';
import { queueWebhookRetry } from '../services/queue/webhook.queue.js';

const logger = createLogger('webhooks-controller');

/** Row shape for COUNT(*) aggregate queries */
interface CountRow {
  count: string;
}

/** Row shape for webhook with project join and lateral delivery */
interface WebhookListRow {
  id: string;
  name: string;
  url: string;
  secret: string;
  events: string[];
  headers: Record<string, string>;
  project_id: string | null;
  project_name: string | null;
  is_active: boolean;
  last_delivery_at: string | null;
  last_delivery_success: boolean | null;
  created_at: string;
  updated_at: string;
  user_id: string;
}

/** Row shape for webhook delivery records */
interface WebhookDeliveryRow {
  id: string;
  event: string;
  response_status: number | null;
  attempts: number;
  success: boolean;
  created_at: string;
  delivered_at: string | null;
  webhook_id: string;
  request_body: string | null;
  response_body: string | null;
}

// Available webhook events
const AVAILABLE_EVENTS = [
  'scan.started',
  'scan.completed',
  'scan.failed',
  'finding.created',
  'finding.resolved',
  'attestation.created',
  'policy.violation',
  'project.created',
  'project.deleted',
];

// Get available events
export async function getAvailableEvents(_req: Request, res: Response) {
  return apiSuccess(res, { events: AVAILABLE_EVENTS });
}

// List webhooks
export async function listWebhooks(req: Request, res: Response) {
  const userId = req.user!.id;
  const querySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    projectId: z.string().uuid().optional(),
  }).passthrough();
  const { page, limit, projectId } = querySchema.parse(req.query);
  const offset = (page - 1) * limit;

  const whereClause = projectId
    ? sql`WHERE w.user_id = ${userId} AND w.project_id = ${projectId}`
    : sql`WHERE w.user_id = ${userId}`;

  const countResult = await db.execute(sql`
    SELECT COUNT(*) as count FROM webhooks w ${whereClause}
  `);
  const total = parseInt((countResult.rows[0] as unknown as CountRow)?.count ?? '0', 10);

  const webhooksResult = await db.execute(sql`
    SELECT w.*, p.name as project_name,
            wd.delivered_at as last_delivery_at,
            wd.success as last_delivery_success
    FROM webhooks w
    LEFT JOIN projects p ON p.id = w.project_id
    LEFT JOIN LATERAL (
      SELECT delivered_at, success FROM webhook_deliveries
      WHERE webhook_id = w.id
      ORDER BY created_at DESC
      LIMIT 1
    ) wd ON true
    ${whereClause}
    ORDER BY w.created_at DESC
    LIMIT ${limit} OFFSET ${offset}
  `);

  const webhooks = (webhooksResult.rows as unknown as WebhookListRow[]).map((w) => ({
    id: w.id,
    name: w.name,
    url: w.url,
    events: w.events,
    projectId: w.project_id,
    projectName: w.project_name,
    isActive: w.is_active,
    lastDeliveryAt: w.last_delivery_at ? new Date(w.last_delivery_at).toISOString() : null,
    lastDeliverySuccess: w.last_delivery_success,
    createdAt: new Date(w.created_at).toISOString(),
  }));

  return apiSuccess(res, {
    data: webhooks,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

// Get single webhook
export async function getWebhook(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const webhookResult = await db.execute(sql`
    SELECT w.*, p.name as project_name
    FROM webhooks w
    LEFT JOIN projects p ON p.id = w.project_id
    WHERE w.id = ${id} AND w.user_id = ${userId}
  `);

  const w = webhookResult.rows[0] as unknown as WebhookListRow | undefined;
  if (!w) {
    return apiError(res, 'Webhook not found', 404);
  }

  return apiSuccess(res, {
    id: w.id,
    name: w.name,
    url: w.url,
    secret: w.secret,
    events: w.events,
    headers: w.headers,
    projectId: w.project_id,
    projectName: w.project_name,
    isActive: w.is_active,
    createdAt: new Date(w.created_at).toISOString(),
    updatedAt: new Date(w.updated_at).toISOString(),
  });
}

// Create webhook
export async function createWebhook(req: Request, res: Response) {
  const userId = req.user!.id;
  const { name, url, events, projectId, headers } = req.body;

  if (!name || !url || !events || !Array.isArray(events) || events.length === 0) {
    return apiError(res, 'Name, URL, and events are required', 400);
  }

  // Validate events
  const invalidEvents = events.filter((e: string) => !AVAILABLE_EVENTS.includes(e));
  if (invalidEvents.length > 0) {
    return apiError(res, `Invalid events: ${invalidEvents.join(', ')}`, 400);
  }

  // Verify project ownership if specified
  if (projectId) {
    const projectResult = await db.execute(sql`
      SELECT id FROM projects WHERE id = ${projectId} AND user_id = ${userId}
    `);

    if (projectResult.rows.length === 0) {
      return apiError(res, 'Project not found', 404);
    }
  }

  // Generate webhook secret
  const secret = `whsec_${crypto.randomBytes(32).toString('hex')}`;

  const result = await db.execute(sql`
    INSERT INTO webhooks (user_id, project_id, name, url, secret, events, headers)
    VALUES (${userId}, ${projectId ?? null}, ${name}, ${url}, ${secret}, ${JSON.stringify(events)}, ${JSON.stringify(headers ?? {})})
    RETURNING *
  `);

  const webhook = result.rows[0] as unknown as WebhookListRow | undefined;
  if (!webhook) {
    return apiError(res, 'Failed to create webhook', 500);
  }

  logger.info({ webhookId: webhook.id, userId }, 'Webhook created');

  return apiSuccess(res, {
    id: webhook.id,
    name: webhook.name,
    url: webhook.url,
    secret: webhook.secret,
    events: webhook.events,
    projectId: webhook.project_id,
    isActive: webhook.is_active,
    createdAt: new Date(webhook.created_at).toISOString(),
  }, 201);
}

// Update webhook
export async function updateWebhook(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;
  const { name, url, events, headers, isActive } = req.body;

  const existingResult = await db.execute(sql`
    SELECT id FROM webhooks WHERE id = ${id} AND user_id = ${userId}
  `);

  if (existingResult.rows.length === 0) {
    return apiError(res, 'Webhook not found', 404);
  }

  // Validate events if provided
  if (events) {
    const invalidEvents = events.filter((e: string) => !AVAILABLE_EVENTS.includes(e));
    if (invalidEvents.length > 0) {
      return apiError(res, `Invalid events: ${invalidEvents.join(', ')}`, 400);
    }
  }

  // Build dynamic SET clause using sql template fragments
  const setClauses: ReturnType<typeof sql>[] = [];

  if (name !== undefined) {
    setClauses.push(sql`name = ${name}`);
  }
  if (url !== undefined) {
    setClauses.push(sql`url = ${url}`);
  }
  if (events !== undefined) {
    setClauses.push(sql`events = ${JSON.stringify(events)}`);
  }
  if (headers !== undefined) {
    setClauses.push(sql`headers = ${JSON.stringify(headers)}`);
  }
  if (isActive !== undefined) {
    setClauses.push(sql`is_active = ${isActive}`);
  }

  if (setClauses.length === 0) {
    return apiError(res, 'No fields to update', 400);
  }

  setClauses.push(sql`updated_at = NOW()`);

  // Join SET clauses with commas
  const setFragment = sql.join(setClauses, sql`, `);

  const result = await db.execute(sql`
    UPDATE webhooks SET ${setFragment} WHERE id = ${id} RETURNING *
  `);

  const webhook = result.rows[0] as unknown as WebhookListRow;
  logger.info({ webhookId: id, userId }, 'Webhook updated');

  return apiSuccess(res, {
    id: webhook.id,
    name: webhook.name,
    url: webhook.url,
    events: webhook.events,
    isActive: webhook.is_active,
    updatedAt: new Date(webhook.updated_at).toISOString(),
  });
}

// Delete webhook
export async function deleteWebhook(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const existingResult = await db.execute(sql`
    SELECT id FROM webhooks WHERE id = ${id} AND user_id = ${userId}
  `);

  if (existingResult.rows.length === 0) {
    return apiError(res, 'Webhook not found', 404);
  }

  await db.execute(sql`DELETE FROM webhooks WHERE id = ${id}`);

  logger.info({ webhookId: id, userId }, 'Webhook deleted');

  return apiSuccess(res, { message: 'Webhook deleted successfully' });
}

// Regenerate webhook secret
export async function regenerateWebhookSecret(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const existingResult = await db.execute(sql`
    SELECT id FROM webhooks WHERE id = ${id} AND user_id = ${userId}
  `);

  if (existingResult.rows.length === 0) {
    return apiError(res, 'Webhook not found', 404);
  }

  const secret = `whsec_${crypto.randomBytes(32).toString('hex')}`;

  await db.execute(sql`
    UPDATE webhooks SET secret = ${secret}, updated_at = NOW() WHERE id = ${id}
  `);

  logger.info({ webhookId: id, userId }, 'Webhook secret regenerated');

  return apiSuccess(res, { secret });
}

// Get webhook deliveries
export async function getWebhookDeliveries(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;
  const deliveryQuerySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    success: z.enum(['true', 'false']).optional(),
  }).passthrough();
  const { page, limit, success: successStr } = deliveryQuerySchema.parse(req.query);
  const success = successStr === 'true' ? true : successStr === 'false' ? false : undefined;
  const offset = (page - 1) * limit;

  // Verify ownership
  const webhookResult = await db.execute(sql`
    SELECT id FROM webhooks WHERE id = ${id} AND user_id = ${userId}
  `);

  if (webhookResult.rows.length === 0) {
    return apiError(res, 'Webhook not found', 404);
  }

  const whereClause = success !== undefined
    ? sql`WHERE webhook_id = ${id} AND success = ${success}`
    : sql`WHERE webhook_id = ${id}`;

  const countResult = await db.execute(sql`
    SELECT COUNT(*) as count FROM webhook_deliveries ${whereClause}
  `);
  const total = parseInt((countResult.rows[0] as unknown as CountRow)?.count ?? '0', 10);

  const deliveriesResult = await db.execute(sql`
    SELECT * FROM webhook_deliveries ${whereClause}
    ORDER BY created_at DESC
    LIMIT ${limit} OFFSET ${offset}
  `);

  const deliveries = (deliveriesResult.rows as unknown as WebhookDeliveryRow[]).map((d) => ({
    id: d.id,
    event: d.event,
    responseStatus: d.response_status,
    attempts: d.attempts,
    success: d.success,
    createdAt: new Date(d.created_at).toISOString(),
    deliveredAt: d.delivered_at ? new Date(d.delivered_at).toISOString() : null,
  }));

  return apiSuccess(res, {
    data: deliveries,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

// Retry failed delivery
export async function retryWebhookDelivery(req: Request, res: Response) {
  const { id, deliveryId } = z.object({ id: z.string().uuid(), deliveryId: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  // Verify webhook ownership
  const webhookResult = await db.execute(sql`
    SELECT * FROM webhooks WHERE id = ${id} AND user_id = ${userId}
  `);

  if (webhookResult.rows.length === 0) {
    return apiError(res, 'Webhook not found', 404);
  }

  // Get delivery
  const deliveryResult = await db.execute(sql`
    SELECT * FROM webhook_deliveries WHERE id = ${deliveryId} AND webhook_id = ${id}
  `);

  const delivery = deliveryResult.rows[0] as unknown as WebhookDeliveryRow | undefined;
  if (!delivery) {
    return apiError(res, 'Delivery not found', 404);
  }

  if (delivery.success) {
    return apiError(res, 'Cannot retry successful delivery', 400);
  }

  // Queue delivery retry via BullMQ
  try {
    await queueWebhookRetry(deliveryId, id);
  } catch (err) {
    logger.error({ webhookId: id, deliveryId, err }, 'Failed to queue webhook retry');
    return apiError(res, 'Failed to queue delivery retry', 500);
  }
  logger.info({ webhookId: id, deliveryId, userId }, 'Webhook delivery retry queued');

  return apiSuccess(res, { message: 'Delivery retry queued' });
}

// Test webhook
export async function testWebhook(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const webhookResult = await db.execute(sql`
    SELECT * FROM webhooks WHERE id = ${id} AND user_id = ${userId}
  `);

  const webhook = webhookResult.rows[0] as unknown as WebhookListRow | undefined;
  if (!webhook) {
    return apiError(res, 'Webhook not found', 404);
  }

  const payload = {
    event: 'test',
    timestamp: new Date().toISOString(),
    data: {
      message: 'This is a test webhook delivery from Code Hardener',
    },
  };

  const signature = crypto
    .createHmac('sha256', webhook.secret)
    .update(JSON.stringify(payload))
    .digest('hex');

  try {
    const response = await fetch(webhook.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Signature': `sha256=${signature}`,
        'X-Webhook-Event': 'test',
        ...webhook.headers,
      },
      body: JSON.stringify(payload),
    });

    logger.info({ webhookId: id, statusCode: response.status, userId }, 'Webhook test completed');

    return apiSuccess(res, {
      success: response.ok,
      statusCode: response.status,
      message: response.ok ? 'Webhook test successful' : `Webhook returned ${response.status}`,
    });
  } catch (error) {
    logger.error({ webhookId: id, error, userId }, 'Webhook test failed');

    return apiSuccess(res, {
      success: false,
      statusCode: null,
      message: `Failed to deliver webhook: ${(error as Error).message}`,
    });
  }
}
