/**
 * GitHub OAuth Rate Limiting Middleware (security-h001)
 *
 * Implements rate limiting for GitHub OAuth operations:
 * - IP-based: 10 requests/minute for callback endpoint
 * - User-based: 5 OAuth flows/minute
 * - Exponential backoff on failed state validations
 */

import rateLimit from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis';
import { sendError } from '../utils/apiResponse.js';
import { redisUrl } from '../config/env.js';
import { logger } from '../utils/logger.js';
import type { BackoffResult } from '../types/github.types.js';

// Redis client for backoff tracking
let redis: Redis | null = null;

try {
  if (redisUrl) {
    redis = new Redis(redisUrl);
    redis.on('error', (err) => {
      logger.error({ error: err }, 'Redis connection error in rate limiter');
    });
  }
} catch (error) {
  logger.warn({ error }, 'Redis not available for OAuth rate limiting');
}

const BACKOFF_PREFIX = 'gh:oauth:backoff:';
const BACKOFF_BASE_SECONDS = 1;
const BACKOFF_MAX_SECONDS = 300; // 5 minutes max
const BACKOFF_TTL_MULTIPLIER = 2; // TTL is 2x the backoff time

/**
 * IP-based rate limiter for OAuth callback endpoint
 * 10 requests per minute per IP
 */
export const oauthCallbackRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use X-Forwarded-For if behind proxy, otherwise use direct IP
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      return forwarded.split(',')[0].trim();
    }
    return req.ip || req.socket.remoteAddress || 'unknown';
  },
  handler: (req, res) => {
    // Window is 60 seconds; tell client to retry after window resets
    res.set('Retry-After', '60');
    logger.warn({ ip: req.ip, path: req.path }, 'OAuth callback rate limited');
    sendError(
      res,
      'RATE_LIMIT_EXCEEDED',
      'Too many OAuth callback requests. Please try again later.',
      429
    );
  },
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/health' || req.path === '/live' || req.path === '/ready';
  },
});

/**
 * User-based rate limiter for OAuth initiation
 * 5 OAuth flows per minute per user
 */
export const oauthInitRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 OAuth flows per minute
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    // Use user ID if authenticated, otherwise fall back to IP
    const user = req.user;
    if (user?.id) {
      return `user:${user.id}`;
    }
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      return `ip:${forwarded.split(',')[0].trim()}`;
    }
    return `ip:${req.ip || req.socket.remoteAddress || 'unknown'}`;
  },
  handler: (req, res) => {
    // Window is 60 seconds; tell client to retry after window resets
    res.set('Retry-After', '60');
    logger.warn({ userId: req.user?.id, ip: req.ip }, 'OAuth init rate limited');
    sendError(
      res,
      'RATE_LIMIT_EXCEEDED',
      'Too many OAuth authorization requests. Please try again in a minute.',
      429
    );
  },
});

/**
 * Check if user is in exponential backoff due to failed state validations
 */
export async function checkOAuthBackoff(userId: string): Promise<BackoffResult> {
  if (!redis) {
    return { blocked: false };
  }

  const key = `${BACKOFF_PREFIX}${userId}`;

  try {
    const data = await redis.get(key);
    if (!data) {
      return { blocked: false };
    }

    const { blockedUntil } = JSON.parse(data) as { failures?: number; blockedUntil?: number };
    const now = Date.now();

    if (blockedUntil && now < blockedUntil) {
      const waitSeconds = Math.ceil((blockedUntil - now) / 1000);
      return {
        blocked: true,
        waitSeconds,
      };
    }

    return { blocked: false };
  } catch (error) {
    logger.error({ error, userId }, 'Error checking OAuth backoff');
    return { blocked: false };
  }
}

/**
 * Record a failed OAuth state validation and apply exponential backoff
 */
export async function recordOAuthFailure(userId: string): Promise<void> {
  if (!redis) {
    return;
  }

  const key = `${BACKOFF_PREFIX}${userId}`;

  try {
    // Get current failure count
    const existing = await redis.get(key);
    let failures = 1;

    if (existing) {
      const data = JSON.parse(existing);
      failures = (data.failures || 0) + 1;
    }

    // Calculate backoff time using exponential backoff
    // 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s, 300s (max)
    const backoffSeconds = Math.min(
      BACKOFF_BASE_SECONDS * Math.pow(2, failures - 1),
      BACKOFF_MAX_SECONDS
    );

    const blockedUntil = Date.now() + backoffSeconds * 1000;
    const ttl = backoffSeconds * BACKOFF_TTL_MULTIPLIER;

    await redis.set(
      key,
      JSON.stringify({ failures, blockedUntil }),
      'EX',
      ttl
    );

    logger.warn({
      userId,
      failures,
      backoffSeconds,
    }, 'OAuth failure recorded with backoff');
  } catch (error) {
    logger.error({ error, userId }, 'Error recording OAuth failure');
  }
}

/**
 * Clear OAuth backoff for a user (after successful authentication)
 */
export async function clearOAuthBackoff(userId: string): Promise<void> {
  if (!redis) {
    return;
  }

  const key = `${BACKOFF_PREFIX}${userId}`;

  try {
    await redis.del(key);
  } catch (error) {
    logger.error({ error, userId }, 'Error clearing OAuth backoff');
  }
}

/**
 * Middleware to check OAuth backoff before processing callback
 */
export async function oauthBackoffMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const user = req.user;
  if (!user?.id) {
    // If no user ID, use IP-based key
    const forwarded = req.headers['x-forwarded-for'];
    const ip = typeof forwarded === 'string'
      ? forwarded.split(',')[0].trim()
      : req.ip || req.socket.remoteAddress || 'unknown';

    const backoffResult = await checkOAuthBackoff(`ip:${ip}`);

    if (backoffResult.blocked) {
      res.set('Retry-After', String(backoffResult.waitSeconds));
      sendError(
        res,
        'RATE_LIMIT_EXCEEDED',
        `Too many failed attempts. Please wait ${backoffResult.waitSeconds} seconds.`,
        429
      );
      return;
    }
  } else {
    const backoffResult = await checkOAuthBackoff(user.id);

    if (backoffResult.blocked) {
      res.set('Retry-After', String(backoffResult.waitSeconds));
      sendError(
        res,
        'RATE_LIMIT_EXCEEDED',
        `Too many failed attempts. Please wait ${backoffResult.waitSeconds} seconds.`,
        429
      );
      return;
    }
  }

  next();
}

/**
 * Cleanup function for graceful shutdown
 */
export async function closeRateLimiterRedis(): Promise<void> {
  if (redis) {
    await redis.quit();
    redis = null;
  }
}
