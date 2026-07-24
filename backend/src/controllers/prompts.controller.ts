/**
 * Prompts Controller
 * API endpoints for prompt parsing and tool recommendation
 * Implements: API-001 to API-006
 */

import type { Request, Response } from 'express';
import { z } from 'zod';
import { sendSuccess, sendValidationError } from '../utils/apiResponse.js';
import { createLogger } from '../utils/logger.js';
import {
  getPromptParserService,
  getToolById,
  getAllCategories,
  getToolsByCategory,
  getToolsByIntent,
  TOOL_REGISTRY,
} from '../services/prompt-parser/index.js';
import type { SecurityIntent } from '../services/prompt-parser/index.js';

const logger = createLogger('prompts-controller');

// Validation schemas
const analyzePromptSchema = z.object({
  prompt: z.string().min(1).max(10000),
  options: z.object({
    maxTools: z.number().int().min(1).max(20).optional(),
    minRelevance: z.number().min(0).max(1).optional(),
    includeAlternatives: z.boolean().optional(),
  }).optional(),
});

const analyzePromptsSchema = z.object({
  prompts: z.array(z.string().min(1).max(10000)).min(1).max(50),
  options: z.object({
    maxTools: z.number().int().min(1).max(20).optional(),
    minRelevance: z.number().min(0).max(1).optional(),
    deduplicateTools: z.boolean().optional(),
  }).optional(),
});

const parseFileSchema = z.object({
  filePath: z.string().min(1).max(500),
  options: z.object({
    processPrompts: z.boolean().optional(),
    maxPrompts: z.number().int().min(1).max(100).optional(),
  }).optional(),
});

const classifyIntentSchema = z.object({
  text: z.string().min(1).max(10000),
});

const extractEntitiesSchema = z.object({
  text: z.string().min(1).max(10000),
});

const mapToToolsSchema = z.object({
  prompt: z.string().min(1).max(10000),
  options: z.object({
    maxTools: z.number().int().min(1).max(20).optional(),
    minRelevance: z.number().min(0).max(1).optional(),
    languages: z.array(z.string()).optional(),
    explicitTools: z.array(z.string()).optional(),
  }).optional(),
});

/**
 * POST /api/v1/prompts/analyze
 * Analyze a single prompt - classify intent, extract entities, and recommend tools
 */
export async function analyzePrompt(req: Request, res: Response) {
  const validation = analyzePromptSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { prompt, options } = validation.data;
  const service = getPromptParserService();

  logger.debug({ promptLength: prompt.length }, 'Analyzing prompt');

  const result = service.processPrompt(prompt);

  // Transform to API response format
  const response = {
    prompt: result.prompt,
    intent: result.analysis.classification.intent,
    confidence: result.analysis.classification.confidence,
    alternativeIntents: options?.includeAlternatives
      ? result.analysis.classification.alternativeIntents
      : undefined,
    entities: {
      languages: result.analysis.entities.languages.map(l => l.language),
      filePaths: result.analysis.entities.filePaths.map(p => p.path),
      severityFilters: result.analysis.entities.severityFilters.map(s => ({
        severity: s.severity,
        operator: s.operator,
      })),
      tools: result.analysis.entities.toolReferences.map(t => t.tool),
      targets: result.analysis.entities.targets.map(t => ({
        type: t.type,
        value: t.value,
      })),
    },
    recommendedTools: result.mapping.recommendedTools.map(r => ({
      id: r.tool.id,
      name: r.tool.name,
      category: r.tool.category,
      relevance: r.relevance,
      reason: r.reason,
      explicitRequest: r.explicitRequest,
      estimatedTime: r.tool.estimatedTime,
      config: r.suggestedConfig,
    })),
    reasoning: result.mapping.reasoning,
    estimatedTime: result.mapping.estimatedTime,
    processingTime: result.processingTime,
  };

  logger.info(
    { intent: result.analysis.classification.intent, toolCount: result.mapping.recommendedTools.length },
    'Prompt analyzed'
  );

  return sendSuccess(res, response);
}

/**
 * POST /api/v1/prompts/analyze/batch
 * Analyze multiple prompts and combine tool recommendations
 */
export async function analyzePrompts(req: Request, res: Response) {
  const validation = analyzePromptsSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { prompts, options } = validation.data;
  const service = getPromptParserService();

  logger.debug({ promptCount: prompts.length }, 'Analyzing prompts batch');

  const batchResult = service.processPrompts(prompts);

  // Transform to API response format
  const response = {
    results: batchResult.results.map(r => ({
      prompt: r.prompt,
      intent: r.analysis.classification.intent,
      confidence: r.analysis.classification.confidence,
      toolCount: r.mapping.recommendedTools.length,
    })),
    combinedTools: options?.deduplicateTools !== false
      ? batchResult.combinedTools.map(t => ({
          id: t.id,
          name: t.name,
          category: t.category,
          estimatedTime: t.estimatedTime,
        }))
      : undefined,
    totalEstimatedScanTime: batchResult.totalEstimatedScanTime,
    totalProcessingTime: batchResult.totalProcessingTime,
  };

  logger.info(
    { promptCount: prompts.length, combinedToolCount: batchResult.combinedTools.length },
    'Prompts batch analyzed'
  );

  return sendSuccess(res, response);
}

/**
 * POST /api/v1/prompts/parse-file
 * Parse a file containing prompts
 */
export async function parsePromptFile(req: Request, res: Response) {
  const validation = parseFileSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { filePath, options } = validation.data;
  const service = getPromptParserService();

  logger.debug({ filePath }, 'Parsing prompt file');

  // Security: Validate file path doesn't escape allowed directories
  // In production, this should check against allowed paths
  if (filePath.includes('..') || filePath.startsWith('/etc') || filePath.startsWith('/var')) {
    return sendValidationError(res, [{ path: ['filePath'], message: 'Invalid file path' }]);
  }

  try {
    if (options?.processPrompts) {
      const fileResult = await service.processFile(filePath);

      const response = {
        filePath: fileResult.parseResult.filePath,
        format: fileResult.parseResult.format,
        success: fileResult.parseResult.success,
        errors: fileResult.parseResult.errors,
        prompts: fileResult.promptResults.slice(0, options?.maxPrompts || 50).map(r => ({
          id: (fileResult.parseResult.prompts.find(p => p.text === r.prompt))?.id,
          text: r.prompt.substring(0, 200) + (r.prompt.length > 200 ? '...' : ''),
          intent: r.analysis.classification.intent,
          confidence: r.analysis.classification.confidence,
          toolCount: r.mapping.recommendedTools.length,
        })),
        combinedTools: fileResult.combinedTools.map(t => ({
          id: t.id,
          name: t.name,
          category: t.category,
        })),
        totalProcessingTime: fileResult.totalProcessingTime,
      };

      logger.info({ filePath, promptCount: fileResult.promptResults.length }, 'File processed');

      return sendSuccess(res, response);
    } else {
      const parseResult = await service.parseFile(filePath);

      const response = {
        filePath: parseResult.filePath,
        format: parseResult.format,
        success: parseResult.success,
        errors: parseResult.errors,
        prompts: parseResult.prompts.map(p => ({
          id: p.id,
          text: p.text.substring(0, 200) + (p.text.length > 200 ? '...' : ''),
          lineNumber: p.lineNumber,
          metadata: p.metadata,
        })),
        fileMetadata: parseResult.fileMetadata,
      };

      logger.info({ filePath, promptCount: parseResult.prompts.length }, 'File parsed');

      return sendSuccess(res, response);
    }
  } catch (error) {
    logger.error({ error, filePath }, 'Failed to parse file');
    return sendValidationError(res, [{ path: ['filePath'], message: 'Failed to read or parse file' }]);
  }
}

/**
 * POST /api/v1/prompts/classify
 * Classify intent only (lightweight endpoint)
 */
export async function classifyIntent(req: Request, res: Response) {
  const validation = classifyIntentSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { text } = validation.data;
  const service = getPromptParserService();

  const analysis = service.analyze(text);

  return sendSuccess(res, {
    text: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
    intent: analysis.classification.intent,
    confidence: analysis.classification.confidence,
    alternativeIntents: analysis.classification.alternativeIntents,
    explanation: analysis.classification.explanation,
    matchedPatterns: analysis.classification.matchedPatterns,
    matchedKeywords: analysis.classification.matchedKeywords,
  });
}

/**
 * POST /api/v1/prompts/extract-entities
 * Extract entities only (lightweight endpoint)
 */
export async function extractEntities(req: Request, res: Response) {
  const validation = extractEntitiesSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { text } = validation.data;
  const service = getPromptParserService();

  const analysis = service.analyze(text);

  return sendSuccess(res, {
    text: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
    entities: {
      languages: analysis.entities.languages,
      filePaths: analysis.entities.filePaths,
      severityFilters: analysis.entities.severityFilters,
      toolReferences: analysis.entities.toolReferences,
      outputFormats: analysis.entities.outputFormats,
      targets: analysis.entities.targets,
    },
    normalizedText: analysis.normalizedText,
  });
}

/**
 * POST /api/v1/prompts/map-tools
 * Map prompt to tools only (lightweight endpoint)
 */
export async function mapToTools(req: Request, res: Response) {
  const validation = mapToToolsSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { prompt } = validation.data;
  const service = getPromptParserService();

  const mapping = service.mapToTools(prompt);

  return sendSuccess(res, {
    prompt: prompt.substring(0, 100) + (prompt.length > 100 ? '...' : ''),
    intent: mapping.intent,
    confidence: mapping.confidence,
    recommendedTools: mapping.recommendedTools.map(r => ({
      id: r.tool.id,
      name: r.tool.name,
      category: r.tool.category,
      relevance: r.relevance,
      reason: r.reason,
      explicitRequest: r.explicitRequest,
      estimatedTime: r.tool.estimatedTime,
      config: r.suggestedConfig,
    })),
    reasoning: mapping.reasoning,
    estimatedTime: mapping.estimatedTime,
  });
}

/**
 * GET /api/v1/prompts/tools
 * List all available tools
 */
export async function listTools(req: Request, res: Response) {
  const querySchema = z.object({
    category: z.string().min(1).optional(),
    intent: z.string().min(1).optional(),
    language: z.string().min(1).optional(),
  }).passthrough();
  const { category, intent, language } = querySchema.parse(req.query);

  let tools = TOOL_REGISTRY;

  if (category) {
    const categoryTools = getToolsByCategory(category as any);
    tools = categoryTools.length > 0 ? categoryTools : [];
  }

  if (intent) {
    const intentTools = getToolsByIntent(intent as SecurityIntent);
    tools = tools.filter(t => intentTools.some(it => it.id === t.id));
  }

  if (language) {
    tools = tools.filter(t => !t.languages || t.languages.includes(language.toLowerCase()));
  }

  const response = tools.map(t => ({
    id: t.id,
    name: t.name,
    category: t.category,
    description: t.description,
    languages: t.languages || [],
    license: t.license,
    version: t.version,
    enabled: t.enabled,
    intents: t.intents,
    priority: t.priority,
    estimatedTime: t.estimatedTime,
    inputTypes: t.inputTypes,
    outputFormats: t.outputFormats,
  }));

  return sendSuccess(res, response, 200, { total: response.length });
}

/**
 * GET /api/v1/prompts/tools/:toolId
 * Get a specific tool by ID
 */
export async function getTool(req: Request, res: Response) {
  const { toolId } = z.object({ toolId: z.string().min(1) }).parse(req.params);

  const tool = getToolById(toolId);
  if (!tool) {
    return sendValidationError(res, [{ path: ['toolId'], message: 'Tool not found' }]);
  }

  return sendSuccess(res, {
    id: tool.id,
    name: tool.name,
    category: tool.category,
    description: tool.description,
    languages: tool.languages || [],
    license: tool.license,
    version: tool.version,
    enabled: tool.enabled,
    intents: tool.intents,
    priority: tool.priority,
    estimatedTime: tool.estimatedTime,
    resources: tool.resources,
    inputTypes: tool.inputTypes,
    outputFormats: tool.outputFormats,
  });
}

/**
 * GET /api/v1/prompts/tools/categories
 * List all tool categories
 */
export async function listCategories(_req: Request, res: Response) {
  const categories = getAllCategories().map(cat => {
    const tools = getToolsByCategory(cat);
    return {
      id: cat,
      name: cat.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      toolCount: tools.length,
      tools: tools.map(t => t.id),
    };
  });

  return sendSuccess(res, categories);
}

/**
 * GET /api/v1/prompts/intents
 * List all supported intents
 */
export async function listIntents(_req: Request, res: Response) {
  const intents: SecurityIntent[] = [
    'vulnerability_scan',
    'sast',
    'dast',
    'sca',
    'secrets_detection',
    'iac_security',
    'container_security',
    'api_security',
    'dependency_audit',
    'compliance_check',
    'performance_test',
    'accessibility_test',
    'visual_regression',
    'supply_chain',
    'code_quality',
  ];

  const response = intents.map(intent => {
    const tools = getToolsByIntent(intent);
    return {
      id: intent,
      name: intent.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      toolCount: tools.length,
      tools: tools.map(t => t.id),
    };
  });

  return sendSuccess(res, response);
}
