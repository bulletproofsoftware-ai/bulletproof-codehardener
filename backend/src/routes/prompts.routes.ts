/**
 * Prompts Routes
 * API routes for prompt parsing and tool recommendation
 * Implements: API-001 to API-006, SEC-021
 */

import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { promptRateLimiter } from '../middleware/rateLimiter.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  analyzePrompt,
  analyzePrompts,
  parsePromptFile,
  classifyIntent,
  extractEntities,
  mapToTools,
  listTools,
  getTool,
  listCategories,
  listIntents,
} from '../controllers/prompts.controller.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

// Prompt analysis endpoints (rate limited per SEC-021: 100/hour/user)
router.post('/analyze', promptRateLimiter, asyncHandler(analyzePrompt));
router.post('/analyze/batch', promptRateLimiter, asyncHandler(analyzePrompts));
router.post('/parse-file', promptRateLimiter, asyncHandler(parsePromptFile));

// Lightweight endpoints (also rate limited but less intensive)
router.post('/classify', promptRateLimiter, asyncHandler(classifyIntent));
router.post('/extract-entities', promptRateLimiter, asyncHandler(extractEntities));
router.post('/map-tools', promptRateLimiter, asyncHandler(mapToTools));

// Tool discovery endpoints (no additional rate limiting beyond global)
router.get('/tools', asyncHandler(listTools));
router.get('/tools/categories', asyncHandler(listCategories));
router.get('/tools/:toolId', asyncHandler(getTool));
router.get('/intents', asyncHandler(listIntents));

export { router as promptRoutes };
