import type { Request, Response, NextFunction } from 'express';
import { createLogger } from '../utils/logger.js';
import { randomUUID } from 'crypto';

const logger = createLogger('http');

declare global {
  namespace Express {
    interface Request {
      id: string;
      startTime: [number, number];
    }
  }
}

export const requestLogger = (req: Request, res: Response, next: NextFunction): void => {
  // Generate request ID
  req.id = (req.headers['x-request-id'] as string) || randomUUID();
  req.startTime = process.hrtime();

  // Add request ID to response headers
  res.setHeader('X-Request-ID', req.id);

  // Log on response finish
  res.on('finish', () => {
    const [seconds, nanoseconds] = process.hrtime(req.startTime);
    const durationMs = (seconds * 1000 + nanoseconds / 1e6).toFixed(2);

    const logData = {
      requestId: req.id,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      durationMs,
      userAgent: req.headers['user-agent'],
      ip: req.ip || req.socket.remoteAddress,
    };

    if (res.statusCode >= 500) {
      logger.error(logData, 'Request completed with server error');
    } else if (res.statusCode >= 400) {
      logger.warn(logData, 'Request completed with client error');
    } else {
      logger.info(logData, 'Request completed');
    }
  });

  next();
};
