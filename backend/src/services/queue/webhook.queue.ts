import { Queue, Worker, Job } from 'bullmq';
import crypto from 'node:crypto';
import { redisUrl } from '../../config/env.js';
import { createLogger } from '../../utils/logger.js';
import { pool } from '../../db/client.js';

const logger = createLogger('webhook-queue');

export interface WebhookJobData {
  webhookId: string;
  deliveryId: string;
  url: string;
  secret: string;
  event: string;
  payload: Record<string, unknown>;
  headers?: Record<string, string>;
  attempt: number;
}

function getRedisConnection() {
  const url = new URL(redisUrl);
  return {
    host: url.hostname,
    port: parseInt(url.port) || 6379,
    password: url.password || undefined,
  };
}

const connection = getRedisConnection();

export const webhookQueue = new Queue<WebhookJobData>('webhook-deliveries', {
  connection,
  defaultJobOptions: {
    attempts: 5,
    backoff: {
      type: 'exponential',
      delay: 10000, // 10s, 20s, 40s, 80s, 160s
    },
    removeOnComplete: 100,
    removeOnFail: 200,
  },
});

// Add a webhook delivery job
export async function queueWebhookDelivery(data: WebhookJobData): Promise<string> {
  const job = await webhookQueue.add('deliver', data, {
    jobId: data.deliveryId,
  });
  logger.info({ webhookId: data.webhookId, deliveryId: data.deliveryId }, 'Webhook delivery queued');
  return job.id!;
}

// Add a retry job for an existing delivery
export async function queueWebhookRetry(deliveryId: string, webhookId: string): Promise<string> {
  // Fetch webhook and delivery details from DB
  const webhookResult = await pool.query(
    'SELECT id, url, secret, headers FROM webhooks WHERE id = $1',
    [webhookId]
  );
  const webhook = webhookResult.rows[0];
  if (!webhook) throw new Error(`Webhook ${webhookId} not found`);

  const deliveryResult = await pool.query(
    'SELECT id, event_type, payload FROM webhook_deliveries WHERE id = $1 AND webhook_id = $2',
    [deliveryId, webhookId]
  );
  const delivery = deliveryResult.rows[0];
  if (!delivery) throw new Error(`Delivery ${deliveryId} not found`);

  const job = await webhookQueue.add('deliver', {
    webhookId: webhook.id,
    deliveryId: delivery.id,
    url: webhook.url,
    secret: webhook.secret,
    event: delivery.event_type,
    payload: delivery.payload,
    headers: webhook.headers,
    attempt: 1,
  }, {
    jobId: `retry-${deliveryId}-${Date.now()}`,
  });

  logger.info({ webhookId, deliveryId }, 'Webhook delivery retry queued');
  return job.id!;
}

// Worker that processes webhook deliveries
export function startWebhookWorker() {
  const worker = new Worker<WebhookJobData>(
    'webhook-deliveries',
    async (job: Job<WebhookJobData>) => {
      const { webhookId, deliveryId, url, secret, event, payload, headers } = job.data;

      logger.info({ webhookId, deliveryId, attempt: job.attemptsMade + 1 }, 'Processing webhook delivery');

      const body = JSON.stringify(payload);
      const signature = crypto
        .createHmac('sha256', secret)
        .update(body)
        .digest('hex');

      const startTime = Date.now();

      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Webhook-Signature': `sha256=${signature}`,
            'X-Webhook-Event': event,
            'X-Webhook-Delivery': deliveryId,
            ...headers,
          },
          body,
          signal: AbortSignal.timeout(30000), // 30s timeout
        });

        const responseTime = Date.now() - startTime;
        const responseBody = await response.text().catch(() => '');

        // Update delivery record
        await pool.query(
          `UPDATE webhook_deliveries
           SET response_status = $1, response_body = $2, response_time_ms = $3, delivered_at = NOW()
           WHERE id = $4`,
          [response.status, responseBody.slice(0, 10000), responseTime, deliveryId]
        );

        // Update webhook last triggered
        await pool.query(
          `UPDATE webhooks SET last_triggered_at = NOW(), last_status_code = $1, failure_count = CASE WHEN $2 THEN 0 ELSE failure_count + 1 END
           WHERE id = $3`,
          [response.status, response.ok, webhookId]
        );

        if (!response.ok) {
          throw new Error(`Webhook returned ${response.status}: ${responseBody.slice(0, 200)}`);
        }

        logger.info({ webhookId, deliveryId, statusCode: response.status, responseTime }, 'Webhook delivered successfully');
      } catch (error) {
        const responseTime = Date.now() - startTime;
        logger.error({ webhookId, deliveryId, error, attempt: job.attemptsMade + 1 }, 'Webhook delivery failed');

        // Update delivery with error
        await pool.query(
          `UPDATE webhook_deliveries
           SET response_status = 0, response_body = $1, response_time_ms = $2
           WHERE id = $3`,
          [error instanceof Error ? error.message : 'Unknown error', responseTime, deliveryId]
        );

        // Update webhook failure count
        await pool.query(
          `UPDATE webhooks SET failure_count = failure_count + 1 WHERE id = $1`,
          [webhookId]
        );

        throw error; // Re-throw so BullMQ retries
      }
    },
    {
      connection,
      concurrency: 10,
      limiter: {
        max: 50,
        duration: 1000, // 50 deliveries per second max
      },
    }
  );

  worker.on('failed', (job, err) => {
    if (job) {
      logger.error({ jobId: job.id, webhookId: job.data.webhookId, err: err.message }, 'Webhook delivery job failed');
    }
  });

  worker.on('completed', (job) => {
    logger.debug({ jobId: job.id, webhookId: job.data.webhookId }, 'Webhook delivery job completed');
  });

  return worker;
}
