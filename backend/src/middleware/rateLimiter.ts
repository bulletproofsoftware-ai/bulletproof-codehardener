import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';
import { sendError } from '../utils/apiResponse.js';

export const rateLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.RATE_LIMIT_MAX_REQUESTS,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    sendError(
      res,
      'RATE_LIMIT_EXCEEDED',
      'Too many requests, please try again later',
      429
    );
  },
  skip: (req) => {
    // Skip rate limiting for health checks and internal/dev requests
    if (req.path === '/health' || req.path === '/live' || req.path === '/ready') return true;
    // Skip rate limiting for local dev requests (docker internal + localhost)
    const ip = req.ip || req.socket.remoteAddress || '';
    if (ip === '127.0.0.1' || ip === '::1' || ip.includes('172.') || ip.includes('192.168.')) return true;
    return false;
  },
});

// Stricter rate limit for auth endpoints
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    sendError(
      res,
      'RATE_LIMIT_EXCEEDED',
      'Too many authentication attempts, please try again later',
      429
    );
  },
});

// Rate limit for scan endpoints
export const scanRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 scans per minute
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    sendError(
      res,
      'RATE_LIMIT_EXCEEDED',
      'Too many scan requests, please try again later',
      429
    );
  },
});

// Rate limit for prompt analysis endpoints (SEC-021: 100/hour/user)
export const promptRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 100, // 100 requests per hour
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    sendError(
      res,
      'RATE_LIMIT_EXCEEDED',
      'Too many prompt analysis requests, please try again later',
      429
    );
  },
});

// Rate limit for test generation endpoints (SEC-022: 20/hour per user)
export const testGeneratorRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 test case generations per hour
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    sendError(
      res,
      'RATE_LIMIT_EXCEEDED',
      'Too many test generation requests, please try again later (20/hour limit)',
      429
    );
  },
});
