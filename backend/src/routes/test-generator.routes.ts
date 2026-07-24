/**
 * Test Generator Routes
 * API endpoints for code analysis, BRD parsing, and test case generation
 */

import { Router } from 'express';
import multer from 'multer';
import { authenticate } from '../middleware/auth.js';
import { testGeneratorRateLimiter } from '../middleware/rateLimiter.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  analyzeCode,
  analyzeBrd,
  getAnalysis,
  listAnalyses,
  generateTests,
  listTestCases,
  getTestCase,
  executeTests,
  getCoverage,
  deleteTestCase,
} from '../controllers/test-generator.controller.js';

const router = Router();

// Configure multer for BRD file uploads (10MB limit per SEC-014)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
  },
  fileFilter: (_req, file, cb) => {
    const allowedTypes = [
      'text/markdown',
      'text/x-markdown',
      'text/plain',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/pdf',
    ];
    const allowedExtensions = ['.md', '.markdown', '.docx', '.pdf'];
    const ext = file.originalname.toLowerCase().slice(file.originalname.lastIndexOf('.'));

    if (allowedTypes.includes(file.mimetype) || allowedExtensions.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Supported: .md, .markdown, .docx, .pdf'));
    }
  },
});

// All routes require authentication
router.use(authenticate);

// =============================================================================
// Analysis Endpoints
// =============================================================================

/**
 * POST /api/v1/test-generator/analyze-code
 * Analyze a code repository
 * Rate limited to 20/hour per user (SEC-022)
 */
router.post('/analyze-code', testGeneratorRateLimiter, asyncHandler(analyzeCode));

/**
 * POST /api/v1/test-generator/analyze-brd
 * Parse a BRD document (multipart/form-data with file, or JSON with content)
 * Rate limited to 20/hour per user (SEC-022)
 */
router.post(
  '/analyze-brd',
  testGeneratorRateLimiter,
  upload.single('file'),
  asyncHandler(analyzeBrd)
);

/**
 * GET /api/v1/test-generator/analysis/:analysisId
 * Get analysis results (code or BRD)
 * Query params: type=code|brd (default: code)
 */
router.get('/analysis/:analysisId', asyncHandler(getAnalysis));

/**
 * GET /api/v1/test-generator/analyses
 * List analyses for a project
 * Query params: projectId (required), type=code|brd, page, limit
 */
router.get('/analyses', asyncHandler(listAnalyses));

// =============================================================================
// Test Generation Endpoints
// =============================================================================

/**
 * POST /api/v1/test-generator/generate
 * Generate test cases from code and/or BRD analysis
 * Rate limited to 20/hour per user (SEC-022)
 */
router.post('/generate', testGeneratorRateLimiter, asyncHandler(generateTests));

/**
 * GET /api/v1/test-generator/tests
 * List generated test cases
 * Query params: projectId (required), category, priority, executed, page, limit
 */
router.get('/tests', asyncHandler(listTestCases));

/**
 * GET /api/v1/test-generator/tests/:testId
 * Get a specific test case
 */
router.get('/tests/:testId', asyncHandler(getTestCase));

/**
 * DELETE /api/v1/test-generator/tests/:testId
 * Delete a test case
 */
router.delete('/tests/:testId', asyncHandler(deleteTestCase));

/**
 * POST /api/v1/test-generator/execute
 * Execute generated test cases (queue for scanning)
 * Rate limited to 20/hour per user (SEC-022)
 */
router.post('/execute', testGeneratorRateLimiter, asyncHandler(executeTests));

/**
 * GET /api/v1/test-generator/coverage
 * Get test coverage report for a project
 * Query params: projectId (required), codeAnalysisId, brdAnalysisId
 */
router.get('/coverage', asyncHandler(getCoverage));

export { router as testGeneratorRoutes };
