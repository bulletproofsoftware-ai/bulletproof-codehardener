/**
 * Test Generator Controller
 * Handles API endpoints for code analysis, BRD parsing, and test case generation
 */

import type { Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendSuccess, sendCreated, sendValidationError, sendError } from '../utils/apiResponse.js';
import { NotFoundError, BadRequestError } from '../middleware/errorHandler.js';
import { createLogger } from '../utils/logger.js';
import * as testGenerator from '../services/test-generator/index.js';
import type { OutputFormat } from '../services/test-generator/generator/template-engine.js';
import { randomUUID } from 'crypto';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { safePath } from '../utils/safePath.js';

const logger = createLogger('test-generator-controller');

// Maximum file size for BRD uploads (SEC-014: 10MB)
const MAX_BRD_FILE_SIZE = 10 * 1024 * 1024;

// Allowed repository hosts (SEC-017)
const ALLOWED_REPO_HOSTS = ['github.com', 'gitlab.com', 'bitbucket.org'];

// =============================================================================
// Validation Schemas
// =============================================================================

const analyzeCodeSchema = z.object({
  projectId: z.string().uuid(),
  repositoryUrl: z.string().url().optional(),
  repositoryPath: z.string().optional(),
  branch: z.string().optional(),
  options: z.object({
    includeDataFlow: z.boolean().optional(),
    includeSensitiveData: z.boolean().optional(),
    maxFileSize: z.number().optional(),
    excludePatterns: z.array(z.string()).optional(),
  }).optional(),
}).refine(data => data.repositoryUrl || data.repositoryPath, {
  message: 'Either repositoryUrl or repositoryPath must be provided',
});

const generateTestsSchema = z.object({
  projectId: z.string().uuid(),
  codeAnalysisId: z.string().uuid().optional(),
  brdAnalysisId: z.string().uuid().optional(),
  options: z.object({
    includeOwasp: z.boolean().optional(),
    includeCwe: z.boolean().optional(),
    alignWithBrd: z.boolean().optional(),
    fillGaps: z.boolean().optional(),
    outputFormat: z.enum(['json', 'markdown', 'gherkin', 'junit', 'csv', 'html']).optional(),
    owaspFocus: z.array(z.string()).optional(),
    cweFocus: z.array(z.string()).optional(),
    maxTestCases: z.number().optional(),
    includePrompts: z.boolean().optional(),
  }).optional(),
});

const executeTestsSchema = z.object({
  projectId: z.string().uuid(),
  testCaseIds: z.array(z.string().uuid()).min(1),
  scanProfile: z.enum(['quick', 'standard', 'comprehensive']).optional(),
});

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Validate repository URL for allowed hosts (SEC-017)
 */
function validateRepositoryUrl(url: string): void {
  try {
    const parsed = new URL(url);
    if (!ALLOWED_REPO_HOSTS.includes(parsed.hostname)) {
      throw new BadRequestError(
        `Repository host not allowed. Allowed hosts: ${ALLOWED_REPO_HOSTS.join(', ')}`
      );
    }
  } catch (error) {
    if (error instanceof BadRequestError) throw error;
    throw new BadRequestError('Invalid repository URL');
  }
}

/**
 * Transform code analysis DB row to API response
 */
function transformCodeAnalysis(row: Record<string, unknown>) {
  return {
    id: row.id,
    projectId: row.project_id,
    repositoryUrl: row.repository_url,
    analysisDate: row.analysis_date,
    detectedLanguages: row.detected_languages,
    detectedFrameworks: row.detected_frameworks,
    extractedEndpoints: row.extracted_endpoints,
    authPatterns: row.auth_patterns,
    dataFlows: row.data_flows,
    sensitiveDataPoints: row.sensitive_data_points,
    dependencies: row.dependencies,
    infrastructureFiles: row.infrastructure_files,
    codeSummary: row.code_summary,
    status: row.status,
    errorMessage: row.error_message,
    processingTimeMs: row.processing_time_ms,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Transform BRD analysis DB row to API response
 */
function transformBrdAnalysis(row: Record<string, unknown>) {
  return {
    id: row.id,
    projectId: row.project_id,
    documentName: row.document_name,
    documentType: row.document_type,
    analysisDate: row.analysis_date,
    requirements: row.requirements,
    securityRequirements: row.security_requirements,
    functionalRequirements: row.functional_requirements,
    status: row.status,
    errorMessage: row.error_message,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Transform generated test case DB row to API response
 */
function transformTestCase(row: Record<string, unknown>) {
  return {
    id: row.id,
    projectId: row.project_id,
    codeAnalysisId: row.code_analysis_id,
    brdAnalysisId: row.brd_analysis_id,
    title: row.title,
    description: row.description,
    category: row.category,
    owaspCategory: row.owasp_category,
    cweId: row.cwe_id,
    alignedRequirementId: row.aligned_requirement_id,
    alignmentConfidence: row.alignment_confidence,
    testPrompt: row.test_prompt,
    targetFile: row.target_file,
    targetEndpoint: row.target_endpoint,
    targetFunction: row.target_function,
    recommendedScanners: row.recommended_scanners,
    priority: row.priority,
    expectedSeverity: row.expected_severity,
    executed: row.executed,
    executionDate: row.execution_date,
    scanResultId: row.scan_result_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// =============================================================================
// Code Analysis Endpoints
// =============================================================================

/**
 * POST /api/v1/test-generator/analyze-code
 * Analyze a code repository
 */
export async function analyzeCode(req: Request, res: Response) {
  const validation = analyzeCodeSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.issues);
  }

  const { projectId, repositoryUrl, repositoryPath, branch: _branch, options } = validation.data;

  // Verify project ownership
  const project = await db.execute(sql`
    SELECT id, repo_url, default_branch FROM projects
    WHERE id = ${projectId} AND user_id = ${req.user!.id}
  `);

  if (project.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  const projectData = project.rows[0] as Record<string, unknown>;

  // Determine repository source
  const repoUrl = repositoryUrl || (projectData.repo_url as string);
  const repoPath = repositoryPath;

  // Validate remote URLs but allow file:// and local paths
  if (repoUrl && !repoUrl.startsWith('file://') && !repoPath) {
    validateRepositoryUrl(repoUrl);
  }

  if (!repoUrl && !repoPath) {
    throw new BadRequestError('No repository URL or path available');
  }

  // Create analysis record
  const analysisId = randomUUID();
  await db.execute(sql`
    INSERT INTO code_analysis_results (id, project_id, repository_url, status)
    VALUES (${analysisId}, ${projectId}, ${repoUrl || null}, 'pending')
  `);

  logger.info(
    { analysisId, projectId, repoUrl, repoPath },
    'Code analysis initiated'
  );

  // For now, run analysis synchronously
  // In production, this would be queued via BullMQ
  try {
    await db.execute(sql`
      UPDATE code_analysis_results SET status = 'processing' WHERE id = ${analysisId}
    `);

    const startTime = Date.now();
    // Resolve analysis path: prefer explicit path, then file:// URL mapped to /repos mount
    let analysisPath = repoPath;
    if (!analysisPath && repoUrl?.startsWith('file://')) {
      const localPath = repoUrl.replace('file://', '');
      const homeDir = process.env.HOST_CODE_DIR || '/repos';
      analysisPath = localPath.replace(/^\/[^/]+\/[^/]+\/Code\//, `${homeDir}/`);
      if (analysisPath === localPath) {
        analysisPath = localPath;
      }
    }
    if (!analysisPath) analysisPath = `/tmp/repo-${analysisId}`;

    // If URL provided, clone would happen here (via existing GitHub integration)
    // For now, we assume the path is available

    const analysisResult = await testGenerator.analyzeCode(analysisPath, options);

    const processingTime = Date.now() - startTime;

    // Update analysis record with results
    await db.execute(sql`
      UPDATE code_analysis_results SET
        detected_languages = ${JSON.stringify(analysisResult.result.languages)},
        detected_frameworks = ${JSON.stringify(analysisResult.result.frameworks)},
        extracted_endpoints = ${JSON.stringify(analysisResult.result.endpoints)},
        auth_patterns = ${JSON.stringify(analysisResult.result.authPatterns)},
        data_flows = ${JSON.stringify(analysisResult.result.dataFlows)},
        sensitive_data_points = ${JSON.stringify(analysisResult.result.sensitiveData)},
        dependencies = ${JSON.stringify(analysisResult.result.dependencies)},
        infrastructure_files = ${JSON.stringify(analysisResult.result.infrastructure)},
        code_summary = ${JSON.stringify(analysisResult.result.summary)},
        status = 'completed',
        processing_time_ms = ${processingTime},
        updated_at = NOW()
      WHERE id = ${analysisId}
    `);

    // Fetch and return the complete record
    const result = await db.execute(sql`
      SELECT * FROM code_analysis_results WHERE id = ${analysisId}
    `);

    logger.info(
      { analysisId, processingTime },
      'Code analysis completed'
    );

    return sendCreated(res, transformCodeAnalysis(result.rows[0] as Record<string, unknown>));
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    await db.execute(sql`
      UPDATE code_analysis_results SET
        status = 'failed',
        error_message = ${errorMessage},
        updated_at = NOW()
      WHERE id = ${analysisId}
    `);

    logger.error({ analysisId, error: errorMessage }, 'Code analysis failed');
    throw error;
  }
}

/**
 * POST /api/v1/test-generator/analyze-brd
 * Parse a BRD document (accepts multipart/form-data or JSON with content)
 */
export async function analyzeBrd(req: Request, res: Response) {
  const projectId = req.body.projectId;

  if (!projectId || typeof projectId !== 'string') {
    return sendValidationError(res, [{ path: ['projectId'], message: 'projectId is required' }]);
  }

  // Verify project ownership
  const project = await db.execute(sql`
    SELECT id FROM projects
    WHERE id = ${projectId} AND user_id = ${req.user!.id}
  `);

  if (project.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  let documentName = 'inline-content';
  let documentType: 'markdown' | 'docx' | 'pdf' = 'markdown';
  let brdResult;

  // Check if file was uploaded (multipart) or content provided (JSON)
  if (req.file) {
    // Multipart file upload
    const file = req.file;

    // Check file size (SEC-014)
    if (file.size > MAX_BRD_FILE_SIZE) {
      return sendError(
        res,
        'FILE_TOO_LARGE',
        `File size exceeds maximum limit of ${MAX_BRD_FILE_SIZE / 1024 / 1024}MB`,
        413
      );
    }

    documentName = file.originalname;
    const ext = path.extname(documentName).toLowerCase();

    if (ext === '.md' || ext === '.markdown') {
      documentType = 'markdown';
    } else if (ext === '.docx') {
      documentType = 'docx';
    } else if (ext === '.pdf') {
      documentType = 'pdf';
    } else {
      return sendValidationError(res, [
        { path: ['file'], message: 'Unsupported file type. Supported: .md, .markdown, .docx, .pdf' },
      ]);
    }

    // Write to temp file and parse
    const tempPath = safePath(os.tmpdir(), `brd-${randomUUID()}${ext}`);
    try {
      await fs.writeFile(tempPath, file.buffer);
      brdResult = await testGenerator.parseBrd(tempPath);
    } finally {
      // Clean up temp file (SEC-009)
      await fs.unlink(tempPath).catch(() => {});
    }
  } else if (req.body.content) {
    // JSON with inline content
    const content = req.body.content;

    // Check content size
    if (content.length > MAX_BRD_FILE_SIZE) {
      return sendError(
        res,
        'CONTENT_TOO_LARGE',
        `Content exceeds maximum limit of ${MAX_BRD_FILE_SIZE / 1024 / 1024}MB`,
        413
      );
    }

    documentName = req.body.documentName || 'inline-content.md';
    brdResult = testGenerator.parseBrdContent(content);
  } else {
    return sendValidationError(res, [
      { path: ['file', 'content'], message: 'Either file upload or content must be provided' },
    ]);
  }

  // Create BRD analysis record
  const analysisId = randomUUID();
  await db.execute(sql`
    INSERT INTO brd_analysis_results (
      id, project_id, document_name, document_type,
      requirements, security_requirements, functional_requirements,
      status, analysis_date
    ) VALUES (
      ${analysisId},
      ${projectId},
      ${documentName},
      ${documentType},
      ${JSON.stringify(brdResult.requirements)},
      ${JSON.stringify(brdResult.requirements.filter(r => r.type === 'security'))},
      ${JSON.stringify(brdResult.requirements.filter(r => r.type === 'functional'))},
      'completed',
      NOW()
    )
  `);

  logger.info(
    { analysisId, projectId, documentName, requirementCount: brdResult.requirements.length },
    'BRD analysis completed'
  );

  // Fetch and return the complete record
  const result = await db.execute(sql`
    SELECT * FROM brd_analysis_results WHERE id = ${analysisId}
  `);

  return sendCreated(res, transformBrdAnalysis(result.rows[0] as Record<string, unknown>));
}

/**
 * GET /api/v1/test-generator/analysis/:analysisId
 * Get analysis results (code or BRD)
 */
export async function getAnalysis(req: Request, res: Response) {
  const { analysisId } = z.object({ analysisId: z.string().uuid() }).parse(req.params);
  const { type } = z.object({ type: z.string().min(1).optional() }).passthrough().parse(req.query);

  if (type === 'brd') {
    // Get BRD analysis
    const result = await db.execute(sql`
      SELECT b.* FROM brd_analysis_results b
      JOIN projects p ON p.id = b.project_id
      WHERE b.id = ${analysisId} AND p.user_id = ${req.user!.id}
    `);

    if (result.rows.length === 0) {
      throw new NotFoundError('BRD analysis not found');
    }

    return sendSuccess(res, transformBrdAnalysis(result.rows[0] as Record<string, unknown>));
  }

  // Default: Get code analysis
  const result = await db.execute(sql`
    SELECT c.* FROM code_analysis_results c
    JOIN projects p ON p.id = c.project_id
    WHERE c.id = ${analysisId} AND p.user_id = ${req.user!.id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Code analysis not found');
  }

  return sendSuccess(res, transformCodeAnalysis(result.rows[0] as Record<string, unknown>));
}

/**
 * GET /api/v1/test-generator/analyses
 * List analyses for a project
 */
export async function listAnalyses(req: Request, res: Response) {
  const querySchema = z.object({
    projectId: z.string().uuid().optional(),
    type: z.string().min(1).optional(),
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  }).passthrough();
  const { projectId, type, page, limit } = querySchema.parse(req.query);
  const offset = (page - 1) * limit;

  if (!projectId) {
    return sendValidationError(res, [{ path: ['projectId'], message: 'projectId is required' }]);
  }

  // Verify project ownership
  const project = await db.execute(sql`
    SELECT id FROM projects WHERE id = ${projectId} AND user_id = ${req.user!.id}
  `);

  if (project.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  if (type === 'brd') {
    const [analyses, countResult] = await Promise.all([
      db.execute(sql`
        SELECT * FROM brd_analysis_results
        WHERE project_id = ${projectId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `),
      db.execute(sql`
        SELECT COUNT(*) as count FROM brd_analysis_results
        WHERE project_id = ${projectId}
      `),
    ]);

    const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string);

    return sendSuccess(
      res,
      analyses.rows.map(row => transformBrdAnalysis(row as Record<string, unknown>)),
      200,
      { page, limit, total, totalPages: Math.ceil(total / limit) }
    );
  }

  // Default: List code analyses
  const [analyses, countResult] = await Promise.all([
    db.execute(sql`
      SELECT * FROM code_analysis_results
      WHERE project_id = ${projectId}
      ORDER BY created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `),
    db.execute(sql`
      SELECT COUNT(*) as count FROM code_analysis_results
      WHERE project_id = ${projectId}
    `),
  ]);

  const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string);

  return sendSuccess(
    res,
    analyses.rows.map(row => transformCodeAnalysis(row as Record<string, unknown>)),
    200,
    { page, limit, total, totalPages: Math.ceil(total / limit) }
  );
}

// =============================================================================
// Test Generation Endpoints
// =============================================================================

/**
 * POST /api/v1/test-generator/generate
 * Generate test cases from analysis
 */
export async function generateTests(req: Request, res: Response) {
  const validation = generateTestsSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.issues);
  }

  const { projectId, codeAnalysisId, brdAnalysisId, options } = validation.data;

  // Verify project ownership
  const project = await db.execute(sql`
    SELECT id FROM projects WHERE id = ${projectId} AND user_id = ${req.user!.id}
  `);

  if (project.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  // Load code analysis if provided
  let codeAnalysisResult = null;
  if (codeAnalysisId) {
    const codeAnalysis = await db.execute(sql`
      SELECT * FROM code_analysis_results
      WHERE id = ${codeAnalysisId} AND project_id = ${projectId}
    `);

    if (codeAnalysis.rows.length === 0) {
      throw new NotFoundError('Code analysis not found');
    }

    const row = codeAnalysis.rows[0] as Record<string, unknown>;
    codeAnalysisResult = {
      languages: row.detected_languages as testGenerator.LanguageDetection[],
      frameworks: row.detected_frameworks as testGenerator.FrameworkDetection[],
      endpoints: row.extracted_endpoints as testGenerator.ExtractedEndpoint[],
      authPatterns: row.auth_patterns as testGenerator.AuthPattern[],
      dataFlows: row.data_flows as testGenerator.DataFlow[],
      sensitiveData: row.sensitive_data_points as testGenerator.SensitiveDataPoint[],
      dependencies: row.dependencies as testGenerator.Dependency[],
      infrastructure: row.infrastructure_files as testGenerator.InfrastructureFile[],
      summary: row.code_summary as testGenerator.CodeSummary,
    };
  }

  // Load BRD analysis if provided
  let brdRequirements: testGenerator.ParsedRequirement[] = [];
  if (brdAnalysisId) {
    const brdAnalysis = await db.execute(sql`
      SELECT * FROM brd_analysis_results
      WHERE id = ${brdAnalysisId} AND project_id = ${projectId}
    `);

    if (brdAnalysis.rows.length === 0) {
      throw new NotFoundError('BRD analysis not found');
    }

    const row = brdAnalysis.rows[0] as Record<string, unknown>;
    brdRequirements = row.requirements as testGenerator.ParsedRequirement[];
  }

  if (!codeAnalysisResult && brdRequirements.length === 0) {
    throw new BadRequestError(
      'At least one of codeAnalysisId or brdAnalysisId must be provided'
    );
  }

  logger.info(
    { projectId, codeAnalysisId, brdAnalysisId },
    'Starting test generation'
  );

  // Generate tests
  let testCases: testGenerator.GeneratedTestCase[];
  let generationResult;

  if (codeAnalysisResult) {
    generationResult = await testGenerator.generateTests(
      codeAnalysisResult as testGenerator.CodeAnalysisResult,
      codeAnalysisResult.endpoints || [],
      brdRequirements,
      {
        includeOwasp: options?.includeOwasp ?? true,
        includeCwe: options?.includeCwe ?? true,
        alignWithBrd: options?.alignWithBrd ?? brdRequirements.length > 0,
        fillGaps: options?.fillGaps ?? true,
        outputFormat: options?.outputFormat as OutputFormat,
        owaspFocus: options?.owaspFocus,
        cweFocus: options?.cweFocus,
        maxTestCases: options?.maxTestCases,
        includePrompts: options?.includePrompts,
      }
    );
    testCases = generationResult.testCases;
  } else {
    // Generate from BRD only
    const brdResult = testGenerator.generateFromBrdContent(
      brdRequirements.map(r => `${r.id}: ${r.title}\n${r.description}`).join('\n\n')
    );
    testCases = brdResult.testCases;
  }

  // Store generated test cases
  for (const tc of testCases) {
    // Handle category as string or object
    const categoryObj = typeof tc.category === 'string'
      ? { primary: tc.category }
      : tc.category;
    const categoryPrimary = categoryObj.primary || tc.type;
    const categoryOwasp = categoryObj.owasp || null;
    const categoryCwe = categoryObj.cwe?.[0]
      ? parseInt(String(categoryObj.cwe[0]).replace('CWE-', ''))
      : null;
    const categoryBrdReq = categoryObj.brdRequirement;

    await db.execute(sql`
      INSERT INTO generated_test_cases (
        id, project_id, code_analysis_id, brd_analysis_id,
        title, description, category,
        owasp_category, cwe_id, aligned_requirement_id, alignment_confidence,
        test_prompt, target_file, target_endpoint, target_function,
        recommended_scanners, priority, expected_severity
      ) VALUES (
        ${randomUUID()},
        ${projectId},
        ${codeAnalysisId || null},
        ${brdAnalysisId || null},
        ${tc.name},
        ${tc.description},
        ${categoryPrimary},
        ${categoryOwasp},
        ${categoryCwe},
        ${tc.brdRequirementId || null},
        ${categoryBrdReq ? 0.8 : null},
        ${tc.steps.join('\n')},
        ${tc.targetEndpoint?.path || null},
        ${tc.targetEndpoint?.path || null},
        ${null},
        ${JSON.stringify(tc.metadata?.recommendedScanners || [])},
        ${tc.priority},
        ${tc.priority}
      )
    `);
  }

  logger.info(
    { projectId, testCount: testCases.length },
    'Test generation completed'
  );

  // Build response
  const response = {
    projectId,
    codeAnalysisId,
    brdAnalysisId,
    testCases: testCases.map(tc => ({
      id: tc.id,
      name: tc.name,
      description: tc.description,
      type: tc.type,
      priority: tc.priority,
      category: tc.category,
      steps: tc.steps,
      expectedResult: tc.expectedResult,
      targetEndpoint: tc.targetEndpoint,
      brdRequirementId: tc.brdRequirementId,
    })),
    coverage: generationResult?.coverage || null,
    stats: {
      total: testCases.length,
      byType: testCases.reduce((acc, tc) => {
        acc[tc.type] = (acc[tc.type] || 0) + 1;
        return acc;
      }, {} as Record<string, number>),
      byPriority: testCases.reduce((acc, tc) => {
        acc[tc.priority] = (acc[tc.priority] || 0) + 1;
        return acc;
      }, {} as Record<string, number>),
    },
    output: generationResult?.output || null,
  };

  return sendCreated(res, response);
}

/**
 * GET /api/v1/test-generator/tests
 * List generated test cases
 */
export async function listTestCases(req: Request, res: Response) {
  const querySchema = z.object({
    projectId: z.string().uuid().optional(),
    category: z.string().min(1).optional(),
    priority: z.string().min(1).optional(),
    executed: z.enum(['true', 'false']).optional(),
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(200).default(50),
  }).passthrough();
  const { projectId, category, priority, executed, page, limit } = querySchema.parse(req.query);
  const offset = (page - 1) * limit;

  if (!projectId) {
    return sendValidationError(res, [{ path: ['projectId'], message: 'projectId is required' }]);
  }

  // Verify project ownership
  const project = await db.execute(sql`
    SELECT id FROM projects WHERE id = ${projectId} AND user_id = ${req.user!.id}
  `);

  if (project.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  let whereClause = sql`project_id = ${projectId}`;

  if (category) {
    whereClause = sql`${whereClause} AND category = ${category}`;
  }
  if (priority) {
    whereClause = sql`${whereClause} AND priority = ${priority}`;
  }
  if (executed !== undefined) {
    whereClause = sql`${whereClause} AND executed = ${executed === 'true'}`;
  }

  const [testCases, countResult] = await Promise.all([
    db.execute(sql`
      SELECT * FROM generated_test_cases
      WHERE ${whereClause}
      ORDER BY
        CASE priority
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          ELSE 5
        END,
        created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `),
    db.execute(sql`
      SELECT COUNT(*) as count FROM generated_test_cases WHERE ${whereClause}
    `),
  ]);

  const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string);

  return sendSuccess(
    res,
    testCases.rows.map(row => transformTestCase(row as Record<string, unknown>)),
    200,
    { page, limit, total, totalPages: Math.ceil(total / limit) }
  );
}

/**
 * GET /api/v1/test-generator/tests/:testId
 * Get a specific test case
 */
export async function getTestCase(req: Request, res: Response) {
  const { testId } = z.object({ testId: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    SELECT t.* FROM generated_test_cases t
    JOIN projects p ON p.id = t.project_id
    WHERE t.id = ${testId} AND p.user_id = ${req.user!.id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Test case not found');
  }

  return sendSuccess(res, transformTestCase(result.rows[0] as Record<string, unknown>));
}

/**
 * POST /api/v1/test-generator/execute
 * Execute generated test cases (queue for scanning)
 */
export async function executeTests(req: Request, res: Response) {
  const validation = executeTestsSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.issues);
  }

  const { projectId, testCaseIds, scanProfile } = validation.data;

  // Verify project ownership
  const project = await db.execute(sql`
    SELECT id, repo_url, default_branch FROM projects
    WHERE id = ${projectId} AND user_id = ${req.user!.id}
  `);

  if (project.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  // Verify test cases belong to project
  const testCases = await db.execute(sql`
    SELECT id, test_prompt, recommended_scanners, target_endpoint
    FROM generated_test_cases
    WHERE id = ANY(${testCaseIds}) AND project_id = ${projectId}
  `);

  if (testCases.rows.length !== testCaseIds.length) {
    throw new BadRequestError('Some test case IDs are invalid or do not belong to this project');
  }

  // Mark test cases as executed
  await db.execute(sql`
    UPDATE generated_test_cases
    SET executed = true, execution_date = NOW(), updated_at = NOW()
    WHERE id = ANY(${testCaseIds})
  `);

  logger.info(
    { projectId, testCaseCount: testCaseIds.length, scanProfile },
    'Test cases marked for execution'
  );

  // In a full implementation, this would:
  // 1. Create a scan record
  // 2. Queue scan jobs via BullMQ with the test prompts
  // 3. Return the scan ID for tracking

  return sendSuccess(res, {
    message: 'Test cases queued for execution',
    testCaseIds,
    executedAt: new Date().toISOString(),
    // scanId: would be returned here after creating scan
  });
}

/**
 * GET /api/v1/test-generator/coverage
 * Get test coverage report for a project
 */
export async function getCoverage(req: Request, res: Response) {
  const coverageQuerySchema = z.object({
    projectId: z.string().uuid().optional(),
    codeAnalysisId: z.string().uuid().optional(),
    brdAnalysisId: z.string().uuid().optional(),
  }).passthrough();
  const { projectId, codeAnalysisId, brdAnalysisId } = coverageQuerySchema.parse(req.query);

  if (!projectId) {
    return sendValidationError(res, [{ path: ['projectId'], message: 'projectId is required' }]);
  }

  // Verify project ownership
  const project = await db.execute(sql`
    SELECT id FROM projects WHERE id = ${projectId} AND user_id = ${req.user!.id}
  `);

  if (project.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  // Get test case statistics
  const stats = await db.execute(sql`
    SELECT
      COUNT(*) as total,
      COUNT(*) FILTER (WHERE category = 'owasp' OR owasp_category IS NOT NULL) as owasp_count,
      COUNT(*) FILTER (WHERE category = 'cwe' OR cwe_id IS NOT NULL) as cwe_count,
      COUNT(*) FILTER (WHERE aligned_requirement_id IS NOT NULL) as brd_aligned_count,
      COUNT(*) FILTER (WHERE executed = true) as executed_count,
      COUNT(DISTINCT owasp_category) as owasp_categories_covered,
      COUNT(DISTINCT cwe_id) as cwe_ids_covered,
      COUNT(DISTINCT aligned_requirement_id) as requirements_covered
    FROM generated_test_cases
    WHERE project_id = ${projectId}
      ${codeAnalysisId ? sql`AND code_analysis_id = ${codeAnalysisId}` : sql``}
      ${brdAnalysisId ? sql`AND brd_analysis_id = ${brdAnalysisId}` : sql``}
  `);

  const statsRow = stats.rows[0] as Record<string, unknown>;

  // Get OWASP coverage breakdown
  const owaspCoverage = await db.execute(sql`
    SELECT owasp_category, COUNT(*) as count
    FROM generated_test_cases
    WHERE project_id = ${projectId}
      AND owasp_category IS NOT NULL
    GROUP BY owasp_category
    ORDER BY owasp_category
  `);

  // Get CWE coverage breakdown
  const cweCoverage = await db.execute(sql`
    SELECT cwe_id, COUNT(*) as count
    FROM generated_test_cases
    WHERE project_id = ${projectId}
      AND cwe_id IS NOT NULL
    GROUP BY cwe_id
    ORDER BY cwe_id
  `);

  // Get priority breakdown
  const priorityBreakdown = await db.execute(sql`
    SELECT priority, COUNT(*) as count
    FROM generated_test_cases
    WHERE project_id = ${projectId}
    GROUP BY priority
  `);

  return sendSuccess(res, {
    projectId,
    summary: {
      totalTestCases: parseInt(statsRow.total as string),
      owaspTests: parseInt(statsRow.owasp_count as string),
      cweTests: parseInt(statsRow.cwe_count as string),
      brdAlignedTests: parseInt(statsRow.brd_aligned_count as string),
      executedTests: parseInt(statsRow.executed_count as string),
      owaspCategoriesCovered: parseInt(statsRow.owasp_categories_covered as string),
      cweidsCovered: parseInt(statsRow.cwe_ids_covered as string),
      requirementsCovered: parseInt(statsRow.requirements_covered as string),
    },
    owasp: {
      totalCategories: 10,
      covered: parseInt(statsRow.owasp_categories_covered as string),
      coveragePercent: Math.round((parseInt(statsRow.owasp_categories_covered as string) / 10) * 100),
      breakdown: owaspCoverage.rows.reduce((acc, row: any) => {
        acc[row.owasp_category] = parseInt(row.count);
        return acc;
      }, {} as Record<string, number>),
    },
    cwe: {
      totalTopCategories: 25,
      covered: parseInt(statsRow.cwe_ids_covered as string),
      coveragePercent: Math.round((parseInt(statsRow.cwe_ids_covered as string) / 25) * 100),
      breakdown: cweCoverage.rows.reduce((acc, row: any) => {
        acc[`CWE-${row.cwe_id}`] = parseInt(row.count);
        return acc;
      }, {} as Record<string, number>),
    },
    priority: priorityBreakdown.rows.reduce((acc, row: any) => {
      acc[row.priority] = parseInt(row.count);
      return acc;
    }, {} as Record<string, number>),
  });
}

/**
 * DELETE /api/v1/test-generator/tests/:testId
 * Delete a test case
 */
export async function deleteTestCase(req: Request, res: Response) {
  const { testId } = z.object({ testId: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    DELETE FROM generated_test_cases t
    USING projects p
    WHERE t.project_id = p.id
      AND t.id = ${testId}
      AND p.user_id = ${req.user!.id}
    RETURNING t.id
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Test case not found');
  }

  logger.info({ testId }, 'Test case deleted');

  return sendSuccess(res, { deleted: true, id: testId });
}
