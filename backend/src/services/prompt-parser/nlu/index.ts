/**
 * NLU Engine - Natural Language Understanding for Security Prompts
 * Barrel export for NLU components
 */

// Types
export type { SecurityIntent, IntentPattern } from './patterns.js';
export type {
  ClassificationResult,
  NegationResult,
  CompoundResult,
} from './intent-classifier.js';
export type {
  LanguageEntity,
  FilePathEntity,
  SeverityFilter,
  ToolReference,
  OutputFormat,
  TargetEntity,
  EntityExtractionResult,
} from './entity-extractor.js';

// Patterns and constants
export {
  INTENT_PATTERNS,
  NEGATION_PATTERNS,
  COMPOUND_CONNECTORS,
  TOOL_REFERENCE_PATTERNS,
  SEVERITY_PATTERNS,
  LANGUAGE_PATTERNS,
  FILE_PATH_PATTERNS,
  KNOWN_TOOLS,
  INTENT_PRIORITY,
  getIntentDescription,
  getIntentKeywords,
} from './patterns.js';

// Synonyms
export {
  SECURITY_SYNONYMS,
  normalizeTerm,
  normalizeText,
  findTerms,
  isKnownTerm,
  getSynonyms,
  getCanonical,
} from './synonyms.js';

// Intent Classifier
export {
  IntentClassifier,
  createIntentClassifier,
  getIntentClassifier,
  classifyIntent,
  classifyIntentWithConfidence,
} from './intent-classifier.js';

// Entity Extractor
export {
  EntityExtractor,
  createEntityExtractor,
  getEntityExtractor,
  extractEntities,
  extractLanguagesFromText,
  extractFilePathsFromText,
} from './entity-extractor.js';

/**
 * NLU Engine class - combines intent classification and entity extraction
 */
import { IntentClassifier, ClassificationResult } from './intent-classifier.js';
import { EntityExtractor, EntityExtractionResult } from './entity-extractor.js';
import { SecurityIntent } from './patterns.js';

/**
 * Complete NLU analysis result
 */
export interface NLUAnalysisResult {
  /** The original input text */
  text: string;
  /** Intent classification result */
  classification: ClassificationResult;
  /** Extracted entities */
  entities: EntityExtractionResult;
  /** Normalized text after synonym replacement */
  normalizedText: string;
  /** Whether the prompt is compound (multiple intents) */
  isCompound: boolean;
  /** Individual segments if compound */
  segments?: NLUAnalysisResult[];
}

/**
 * NLU Engine - Main entry point for natural language understanding
 */
export class NLUEngine {
  private classifier: IntentClassifier;
  private extractor: EntityExtractor;

  constructor() {
    this.classifier = new IntentClassifier();
    this.extractor = new EntityExtractor();
  }

  /**
   * Analyze a prompt text
   * @param text The prompt to analyze
   * @returns Complete NLU analysis result
   */
  analyze(text: string): NLUAnalysisResult {
    // Check for compound prompt
    const compound = this.classifier.parseCompound(text);

    if (compound.isCompound && compound.segments.length > 1) {
      // Analyze each segment
      const segments = compound.segments.map(segment => this.analyzeSingle(segment));

      // Return compound result
      return {
        text,
        classification: segments[0].classification, // Primary classification
        entities: this.mergeEntities(segments.map(s => s.entities)),
        normalizedText: this.classifier.normalizeSynonyms(text),
        isCompound: true,
        segments,
      };
    }

    return this.analyzeSingle(text);
  }

  /**
   * Analyze a single (non-compound) prompt
   */
  private analyzeSingle(text: string): NLUAnalysisResult {
    const classification = this.classifier.classify(text);
    const entities = this.extractor.extract(text);
    const normalizedText = this.classifier.normalizeSynonyms(text);

    return {
      text,
      classification,
      entities,
      normalizedText,
      isCompound: false,
    };
  }

  /**
   * Merge entities from multiple segments
   */
  private mergeEntities(entityArrays: EntityExtractionResult[]): EntityExtractionResult {
    const merged: EntityExtractionResult = {
      languages: [],
      filePaths: [],
      severityFilters: [],
      toolReferences: [],
      outputFormats: [],
      targets: [],
      raw: {
        languages: [],
        filePaths: [],
        severities: [],
        tools: [],
        formats: [],
        targets: [],
      },
    };

    const seenLanguages = new Set<string>();
    const seenPaths = new Set<string>();
    const seenTools = new Set<string>();
    const seenFormats = new Set<string>();
    const seenTargets = new Set<string>();

    for (const entities of entityArrays) {
      // Merge languages
      for (const lang of entities.languages) {
        if (!seenLanguages.has(lang.language)) {
          seenLanguages.add(lang.language);
          merged.languages.push(lang);
        }
      }

      // Merge file paths
      for (const path of entities.filePaths) {
        if (!seenPaths.has(path.path)) {
          seenPaths.add(path.path);
          merged.filePaths.push(path);
        }
      }

      // Merge severity filters (take first)
      if (merged.severityFilters.length === 0 && entities.severityFilters.length > 0) {
        merged.severityFilters = entities.severityFilters;
      }

      // Merge tool references
      for (const tool of entities.toolReferences) {
        if (!seenTools.has(tool.tool)) {
          seenTools.add(tool.tool);
          merged.toolReferences.push(tool);
        }
      }

      // Merge output formats
      for (const format of entities.outputFormats) {
        if (!seenFormats.has(format.format)) {
          seenFormats.add(format.format);
          merged.outputFormats.push(format);
        }
      }

      // Merge targets
      for (const target of entities.targets) {
        if (!seenTargets.has(target.value)) {
          seenTargets.add(target.value);
          merged.targets.push(target);
        }
      }
    }

    // Update raw
    merged.raw = {
      languages: merged.languages.map(l => l.language),
      filePaths: merged.filePaths.map(f => f.path),
      severities: merged.severityFilters.map(s => `${s.operator}:${s.severity}`),
      tools: merged.toolReferences.map(t => t.tool),
      formats: merged.outputFormats.map(o => o.format),
      targets: merged.targets.map(t => t.value),
    };

    return merged;
  }

  /**
   * Quick classify - just get the intent
   */
  classifyIntent(text: string): SecurityIntent {
    return this.classifier.classify(text).intent;
  }

  /**
   * Check for negation in text
   */
  detectNegation(text: string): { hasNegation: boolean; negatedTerms: string[] } {
    return this.classifier.detectNegation(text);
  }
}

/**
 * Factory function to create an NLUEngine instance
 */
export function createNLUEngine(): NLUEngine {
  return new NLUEngine();
}

// Default singleton instance
let defaultEngine: NLUEngine | null = null;

/**
 * Get the default NLUEngine instance (singleton)
 */
export function getNLUEngine(): NLUEngine {
  if (!defaultEngine) {
    defaultEngine = new NLUEngine();
  }
  return defaultEngine;
}

/**
 * Quick analyze function
 * @param text The text to analyze
 * @returns NLU analysis result
 */
export function analyzePrompt(text: string): NLUAnalysisResult {
  return getNLUEngine().analyze(text);
}
