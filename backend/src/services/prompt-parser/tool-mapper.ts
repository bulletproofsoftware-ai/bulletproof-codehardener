/**
 * Tool Mapper Service
 * Maps parsed prompts and intents to appropriate security tools
 * Implements: TM-004 to TM-010
 */

import { SecurityIntent } from './nlu/patterns.js';
import { ClassificationResult, getIntentClassifier } from './nlu/intent-classifier.js';
import { EntityExtractionResult, getEntityExtractor } from './nlu/entity-extractor.js';
import {
  ToolDefinition,
  getToolsByIntent,
  getToolsByLanguage,
  getToolById,
  getLanguageAgnosticTools,
} from './tool-registry.js';

/**
 * Tool mapping result for a single prompt
 */
export interface ToolMappingResult {
  /** The original prompt text */
  prompt: string;
  /** Classified intent */
  intent: SecurityIntent;
  /** Confidence in the classification */
  confidence: number;
  /** Recommended tools in priority order */
  recommendedTools: ToolRecommendation[];
  /** Extracted entities that influenced the mapping */
  entities: EntityExtractionResult;
  /** Explanation of why these tools were selected */
  reasoning: string;
  /** Alternative intents considered */
  alternativeIntents: Array<{ intent: SecurityIntent; confidence: number }>;
  /** Estimated total execution time in seconds */
  estimatedTime: number;
}

/**
 * Single tool recommendation
 */
export interface ToolRecommendation {
  /** Tool definition */
  tool: ToolDefinition;
  /** Relevance score (0-1) */
  relevance: number;
  /** Why this tool was recommended */
  reason: string;
  /** Whether this tool was explicitly requested */
  explicitRequest: boolean;
  /** Suggested configuration overrides */
  suggestedConfig?: Record<string, unknown>;
}

/**
 * Tool mapping configuration
 */
export interface ToolMapperConfig {
  /** Maximum number of tools to recommend */
  maxTools?: number;
  /** Minimum relevance score to include a tool */
  minRelevance?: number;
  /** Whether to include language-agnostic tools */
  includeAgnosticTools?: boolean;
  /** Whether to boost explicitly requested tools */
  boostExplicitRequests?: boolean;
  /** Default tools to always include (by ID) */
  defaultTools?: string[];
}

const DEFAULT_CONFIG: Required<ToolMapperConfig> = {
  maxTools: 5,
  minRelevance: 0.3,
  includeAgnosticTools: true,
  boostExplicitRequests: true,
  defaultTools: [],
};

/**
 * Tool Mapper class
 * Maps prompts to appropriate security tools based on intent and entities
 */
export class ToolMapper {
  private config: Required<ToolMapperConfig>;
  private classifier = getIntentClassifier();
  private extractor = getEntityExtractor();

  constructor(config?: ToolMapperConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Map a prompt to recommended tools
   * Implements: TM-004, TM-005
   * @param prompt The prompt text to analyze
   * @returns Tool mapping result
   */
  mapPrompt(prompt: string): ToolMappingResult {
    // Classify intent
    const classification = this.classifier.classify(prompt);

    // Extract entities
    const entities = this.extractor.extract(prompt);

    // Get tool recommendations
    const recommendations = this.getRecommendations(classification, entities);

    // Calculate total estimated time
    const estimatedTime = recommendations.reduce(
      (sum, r) => sum + r.tool.estimatedTime,
      0
    );

    // Build reasoning
    const reasoning = this.buildReasoning(classification, entities, recommendations);

    return {
      prompt,
      intent: classification.intent,
      confidence: classification.confidence,
      recommendedTools: recommendations,
      entities,
      reasoning,
      alternativeIntents: classification.alternativeIntents,
      estimatedTime,
    };
  }

  /**
   * Map multiple prompts and deduplicate tools
   * @param prompts Array of prompt texts
   * @returns Combined tool mapping with deduplicated tools
   */
  mapPrompts(prompts: string[]): {
    results: ToolMappingResult[];
    combinedTools: ToolRecommendation[];
    totalEstimatedTime: number;
  } {
    const results = prompts.map(p => this.mapPrompt(p));

    // Combine and deduplicate tools
    const toolMap = new Map<string, ToolRecommendation>();
    for (const result of results) {
      for (const rec of result.recommendedTools) {
        const existing = toolMap.get(rec.tool.id);
        if (!existing || existing.relevance < rec.relevance) {
          toolMap.set(rec.tool.id, rec);
        }
      }
    }

    const combinedTools = Array.from(toolMap.values())
      .sort((a, b) => b.relevance - a.relevance)
      .slice(0, this.config.maxTools * 2); // Allow more tools when combining

    const totalEstimatedTime = combinedTools.reduce(
      (sum, r) => sum + r.tool.estimatedTime,
      0
    );

    return { results, combinedTools, totalEstimatedTime };
  }

  /**
   * Get tool recommendations based on classification and entities
   * Implements: TM-006, TM-007
   */
  private getRecommendations(
    classification: ClassificationResult,
    entities: EntityExtractionResult
  ): ToolRecommendation[] {
    const recommendations: ToolRecommendation[] = [];
    const addedTools = new Set<string>();

    // 1. Add explicitly requested tools (highest priority)
    if (this.config.boostExplicitRequests) {
      for (const toolRef of entities.toolReferences) {
        const tool = getToolById(toolRef.tool);
        if (tool && tool.enabled && !addedTools.has(tool.id)) {
          addedTools.add(tool.id);
          recommendations.push({
            tool,
            relevance: 1.0, // Explicit request = max relevance
            reason: `Explicitly requested: "${toolRef.matchedText}"`,
            explicitRequest: true,
          });
        }
      }
    }

    // 2. Add tools for the primary intent
    const intentTools = getToolsByIntent(classification.intent);
    for (const tool of intentTools) {
      if (!tool.enabled || addedTools.has(tool.id)) continue;

      const relevance = this.calculateRelevance(tool, classification, entities);
      if (relevance >= this.config.minRelevance) {
        addedTools.add(tool.id);
        recommendations.push({
          tool,
          relevance,
          reason: `Matches intent: ${classification.intent}`,
          explicitRequest: false,
        });
      }
    }

    // 3. Add language-specific tools
    for (const langEntity of entities.languages) {
      const langTools = getToolsByLanguage(langEntity.language);
      for (const tool of langTools) {
        if (!tool.enabled || addedTools.has(tool.id)) continue;

        const relevance = this.calculateRelevance(tool, classification, entities) * 0.9;
        if (relevance >= this.config.minRelevance) {
          addedTools.add(tool.id);
          recommendations.push({
            tool,
            relevance,
            reason: `Supports ${langEntity.language} code`,
            explicitRequest: false,
          });
        }
      }
    }

    // 4. Add tools for alternative intents (lower relevance)
    for (const alt of classification.alternativeIntents) {
      if (alt.confidence < 0.4) continue;

      const altTools = getToolsByIntent(alt.intent);
      for (const tool of altTools) {
        if (!tool.enabled || addedTools.has(tool.id)) continue;

        const baseRelevance = this.calculateRelevance(tool, classification, entities);
        const relevance = baseRelevance * alt.confidence * 0.8;
        if (relevance >= this.config.minRelevance) {
          addedTools.add(tool.id);
          recommendations.push({
            tool,
            relevance,
            reason: `Also relevant for: ${alt.intent}`,
            explicitRequest: false,
          });
        }
      }
    }

    // 5. Add language-agnostic tools if enabled
    if (this.config.includeAgnosticTools && recommendations.length < this.config.maxTools) {
      const agnosticTools = getLanguageAgnosticTools()
        .filter(t => t.enabled && !addedTools.has(t.id) && t.intents.includes(classification.intent));

      for (const tool of agnosticTools) {
        if (recommendations.length >= this.config.maxTools) break;

        const relevance = this.calculateRelevance(tool, classification, entities) * 0.85;
        if (relevance >= this.config.minRelevance) {
          addedTools.add(tool.id);
          recommendations.push({
            tool,
            relevance,
            reason: 'Language-agnostic tool for this intent',
            explicitRequest: false,
          });
        }
      }
    }

    // 6. Add default tools if configured
    for (const toolId of this.config.defaultTools) {
      if (addedTools.has(toolId)) continue;

      const tool = getToolById(toolId);
      if (tool && tool.enabled) {
        addedTools.add(tool.id);
        recommendations.push({
          tool,
          relevance: 0.5,
          reason: 'Default tool for all scans',
          explicitRequest: false,
        });
      }
    }

    // Sort by relevance and limit
    return recommendations
      .sort((a, b) => b.relevance - a.relevance)
      .slice(0, this.config.maxTools)
      .map(rec => ({
        ...rec,
        suggestedConfig: this.getSuggestedConfig(rec.tool, entities),
      }));
  }

  /**
   * Calculate relevance score for a tool
   * Implements: TM-008
   */
  private calculateRelevance(
    tool: ToolDefinition,
    classification: ClassificationResult,
    entities: EntityExtractionResult
  ): number {
    let score = 0;

    // Base score from intent match
    if (tool.intents.includes(classification.intent)) {
      score += 0.4;
    }

    // Boost from tool priority
    score += (tool.priority / 10) * 0.2;

    // Boost from confidence
    score += classification.confidence * 0.2;

    // Boost from language match
    if (tool.languages && entities.languages.length > 0) {
      const matchedLangs = entities.languages.filter(
        l => tool.languages!.includes(l.language)
      );
      if (matchedLangs.length > 0) {
        score += 0.15;
      }
    } else if (!tool.languages) {
      // Language-agnostic tool gets a small boost
      score += 0.05;
    }

    // Boost from target type match
    if (entities.targets.length > 0) {
      const targetTypes = entities.targets.map(t => t.type);
      const matchingInputs = tool.inputTypes.filter(
        i => targetTypes.includes(i as any)
      );
      if (matchingInputs.length > 0) {
        score += 0.1;
      }
    }

    // Boost from output format match
    if (entities.outputFormats.length > 0) {
      const requestedFormats = entities.outputFormats.map(o => o.format);
      const matchingFormats = tool.outputFormats.filter(
        f => requestedFormats.includes(f as any)
      );
      if (matchingFormats.length > 0) {
        score += 0.05;
      }
    }

    return Math.min(score, 1.0);
  }

  /**
   * Get suggested configuration for a tool based on entities
   * Implements: TM-009
   */
  private getSuggestedConfig(
    tool: ToolDefinition,
    entities: EntityExtractionResult
  ): Record<string, unknown> | undefined {
    const config: Record<string, unknown> = {};

    // Set severity threshold if specified
    if (entities.severityFilters.length > 0) {
      const filter = entities.severityFilters[0];
      config.severityThreshold = filter.severity;
      config.severityOperator = filter.operator;
    }

    // Set output format if specified
    if (entities.outputFormats.length > 0) {
      const requestedFormat = entities.outputFormats[0].format;
      if (tool.outputFormats.includes(requestedFormat)) {
        config.outputFormat = requestedFormat;
      }
    }

    // Set target paths if specified
    if (entities.filePaths.length > 0) {
      config.targetPaths = entities.filePaths.map(p => p.path);
    }

    // Set target URLs if specified
    const urls = entities.targets.filter(t => t.type === 'url');
    if (urls.length > 0) {
      config.targetUrls = urls.map(t => t.value);
    }

    return Object.keys(config).length > 0 ? config : undefined;
  }

  /**
   * Build human-readable reasoning for the mapping
   * Implements: TM-010
   */
  private buildReasoning(
    classification: ClassificationResult,
    entities: EntityExtractionResult,
    recommendations: ToolRecommendation[]
  ): string {
    const parts: string[] = [];

    // Explain intent classification
    parts.push(
      `Classified as "${classification.intent}" with ${(classification.confidence * 100).toFixed(0)}% confidence.`
    );

    // Explain language detection
    if (entities.languages.length > 0) {
      const langs = entities.languages.map(l => l.language).join(', ');
      parts.push(`Detected languages: ${langs}.`);
    }

    // Explain tool selection
    if (recommendations.length > 0) {
      const toolNames = recommendations.slice(0, 3).map(r => r.tool.name).join(', ');
      parts.push(`Recommended tools: ${toolNames}.`);

      // Explain explicit requests
      const explicit = recommendations.filter(r => r.explicitRequest);
      if (explicit.length > 0) {
        parts.push(`Tools "${explicit.map(r => r.tool.name).join('", "')}" were explicitly requested.`);
      }
    }

    // Explain severity filter
    if (entities.severityFilters.length > 0) {
      const filter = entities.severityFilters[0];
      parts.push(`Filtering for ${filter.operator === 'gte' ? 'at least ' : ''}${filter.severity} severity.`);
    }

    return parts.join(' ');
  }
}

/**
 * Factory function to create a ToolMapper instance
 */
export function createToolMapper(config?: ToolMapperConfig): ToolMapper {
  return new ToolMapper(config);
}

// Default singleton instance
let defaultMapper: ToolMapper | null = null;

/**
 * Get the default ToolMapper instance (singleton)
 */
export function getToolMapper(): ToolMapper {
  if (!defaultMapper) {
    defaultMapper = new ToolMapper();
  }
  return defaultMapper;
}

/**
 * Quick map function for simple use cases
 * @param prompt The prompt text to map
 * @returns Tool mapping result
 */
export function mapPromptToTools(prompt: string): ToolMappingResult {
  return getToolMapper().mapPrompt(prompt);
}

/**
 * Get recommended tools for an intent
 * @param intent The security intent
 * @returns Array of tool definitions
 */
export function getToolsForIntent(intent: SecurityIntent): ToolDefinition[] {
  return getToolsByIntent(intent)
    .filter(t => t.enabled)
    .sort((a, b) => b.priority - a.priority);
}
