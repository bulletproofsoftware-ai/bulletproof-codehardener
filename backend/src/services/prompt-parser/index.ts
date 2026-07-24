/**
 * Prompt Parser Service
 * Main entry point for parsing natural language security prompts
 * and mapping them to appropriate security tools
 */

// NLU Engine exports
export * from './nlu/index.js';

// File Parser exports
export {
  FileParser,
  createFileParser,
  getFileParser,
  parseFile,
  type ParsedPrompt,
  type PromptMetadata,
  type FileParseResult,
  type ParseError,
  type FileParserConfig,
} from './file-parser.js';

// Tool Registry exports
export {
  TOOL_REGISTRY,
  getToolById,
  getToolsByCategory,
  getToolsByIntent,
  getToolsByLanguage,
  getEnabledTools,
  getAllToolIds,
  getAllCategories,
  isValidToolId,
  getToolsByPriority,
  getLanguageAgnosticTools,
  type ToolDefinition,
  type ToolCategory,
} from './tool-registry.js';

// Tool Mapper exports
export {
  ToolMapper,
  createToolMapper,
  getToolMapper,
  mapPromptToTools,
  getToolsForIntent,
  type ToolMappingResult,
  type ToolRecommendation,
  type ToolMapperConfig,
} from './tool-mapper.js';

// Import for PromptParserService
import { FileParser, FileParseResult } from './file-parser.js';
import { NLUEngine, NLUAnalysisResult } from './nlu/index.js';
import { ToolMapper, ToolMappingResult } from './tool-mapper.js';
import { ToolDefinition } from './tool-registry.js';

/**
 * Complete prompt processing result
 */
export interface PromptProcessingResult {
  /** Original prompt text */
  prompt: string;
  /** NLU analysis */
  analysis: NLUAnalysisResult;
  /** Tool mapping */
  mapping: ToolMappingResult;
  /** Processing timestamp */
  timestamp: Date;
  /** Processing duration in ms */
  processingTime: number;
}

/**
 * Batch processing result
 */
export interface BatchProcessingResult {
  /** Individual results */
  results: PromptProcessingResult[];
  /** Combined recommended tools (deduplicated) */
  combinedTools: ToolDefinition[];
  /** Total processing time */
  totalProcessingTime: number;
  /** Total estimated scan time */
  totalEstimatedScanTime: number;
}

/**
 * File processing result
 */
export interface FileProcessingResult {
  /** File parse result */
  parseResult: FileParseResult;
  /** Processing results for each prompt */
  promptResults: PromptProcessingResult[];
  /** Combined recommended tools */
  combinedTools: ToolDefinition[];
  /** Total processing time */
  totalProcessingTime: number;
}

/**
 * Prompt Parser Service
 * Main service class that combines file parsing, NLU analysis, and tool mapping
 */
export class PromptParserService {
  private fileParser: FileParser;
  private nluEngine: NLUEngine;
  private toolMapper: ToolMapper;

  constructor() {
    this.fileParser = new FileParser();
    this.nluEngine = new NLUEngine();
    this.toolMapper = new ToolMapper();
  }

  /**
   * Process a single prompt text
   * @param prompt The prompt to process
   * @returns Complete processing result
   */
  processPrompt(prompt: string): PromptProcessingResult {
    const startTime = Date.now();

    // Analyze with NLU
    const analysis = this.nluEngine.analyze(prompt);

    // Map to tools
    const mapping = this.toolMapper.mapPrompt(prompt);

    return {
      prompt,
      analysis,
      mapping,
      timestamp: new Date(),
      processingTime: Date.now() - startTime,
    };
  }

  /**
   * Process multiple prompts
   * @param prompts Array of prompt texts
   * @returns Batch processing result
   */
  processPrompts(prompts: string[]): BatchProcessingResult {
    const startTime = Date.now();
    const results = prompts.map(p => this.processPrompt(p));

    // Collect and deduplicate tools
    const toolMap = new Map<string, ToolDefinition>();
    for (const result of results) {
      for (const rec of result.mapping.recommendedTools) {
        if (!toolMap.has(rec.tool.id)) {
          toolMap.set(rec.tool.id, rec.tool);
        }
      }
    }

    const combinedTools = Array.from(toolMap.values());
    const totalEstimatedScanTime = combinedTools.reduce(
      (sum, t) => sum + t.estimatedTime,
      0
    );

    return {
      results,
      combinedTools,
      totalProcessingTime: Date.now() - startTime,
      totalEstimatedScanTime,
    };
  }

  /**
   * Process a file containing prompts
   * @param filePath Path to the file
   * @returns File processing result
   */
  async processFile(filePath: string): Promise<FileProcessingResult> {
    const startTime = Date.now();

    // Parse the file
    const parseResult = await this.fileParser.parseFile(filePath);

    // Process each parsed prompt
    const promptResults = parseResult.prompts.map(p => this.processPrompt(p.text));

    // Collect and deduplicate tools
    const toolMap = new Map<string, ToolDefinition>();
    for (const result of promptResults) {
      for (const rec of result.mapping.recommendedTools) {
        if (!toolMap.has(rec.tool.id)) {
          toolMap.set(rec.tool.id, rec.tool);
        }
      }
    }

    return {
      parseResult,
      promptResults,
      combinedTools: Array.from(toolMap.values()),
      totalProcessingTime: Date.now() - startTime,
    };
  }

  /**
   * Quick analyze - just get NLU analysis
   * @param text The text to analyze
   * @returns NLU analysis result
   */
  analyze(text: string): NLUAnalysisResult {
    return this.nluEngine.analyze(text);
  }

  /**
   * Quick map - just get tool mapping
   * @param text The text to map
   * @returns Tool mapping result
   */
  mapToTools(text: string): ToolMappingResult {
    return this.toolMapper.mapPrompt(text);
  }

  /**
   * Parse a file without processing
   * @param filePath Path to the file
   * @returns File parse result
   */
  async parseFile(filePath: string): Promise<FileParseResult> {
    return this.fileParser.parseFile(filePath);
  }
}

/**
 * Factory function to create a PromptParserService instance
 */
export function createPromptParserService(): PromptParserService {
  return new PromptParserService();
}

// Default singleton instance
let defaultService: PromptParserService | null = null;

/**
 * Get the default PromptParserService instance (singleton)
 */
export function getPromptParserService(): PromptParserService {
  if (!defaultService) {
    defaultService = new PromptParserService();
  }
  return defaultService;
}
