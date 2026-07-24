import { Router } from 'express';
import type { Request, Response } from 'express';
import { sendSuccess, sendError } from '../utils/apiResponse.js';
import { checkDbConnection } from '../db/client.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('health');
const router = Router();

interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  uptime: number;
  timestamp: string;
  checks: {
    database: 'connected' | 'disconnected';
    redis?: 'connected' | 'disconnected';
  };
}

// Simple health check - always returns 200 if server is running
router.get('/health', (_req: Request, res: Response) => {
  return sendSuccess(res, {
    status: 'healthy',
    timestamp: new Date().toISOString(),
  });
});

// Detailed readiness check - verifies all dependencies
router.get('/ready', async (_req: Request, res: Response) => {
  const startTime = process.hrtime();

  try {
    const dbConnected = await checkDbConnection();

    const [seconds, nanoseconds] = process.hrtime(startTime);
    const responseTime = seconds * 1000 + nanoseconds / 1e6;

    const health: HealthStatus = {
      status: dbConnected ? 'healthy' : 'degraded',
      version: process.env.npm_package_version || '0.1.0',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      checks: {
        database: dbConnected ? 'connected' : 'disconnected',
      },
    };

    if (!dbConnected) {
      logger.warn('Database not connected during health check');
      return sendError(res, 'SERVICE_DEGRADED', 'Database not connected', 503, health);
    }

    return sendSuccess(res, { ...health, responseTime: `${responseTime.toFixed(2)}ms` });
  } catch (error) {
    logger.error({ error }, 'Health check failed');
    return sendError(res, 'HEALTH_CHECK_FAILED', 'Health check failed', 503);
  }
});

// Liveness probe - simple check that the process is alive
router.get('/live', (_req: Request, res: Response) => {
  return res.status(200).send('OK');
});

export { router as healthRoutes };
