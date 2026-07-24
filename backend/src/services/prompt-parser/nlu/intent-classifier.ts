/**
 * Intent Classifier Service
 * Classifies security-related prompts into specific intent categories
 * Implements: NLU-001 (Classify security intent)
 */

import {
  SecurityIntent,
  IntentPattern,
  INTENT_PATTERNS,
  NEGATION_PATTERNS,
  COMPOUND_CONNECTORS,
  INTENT_PRIORITY,
  getIntentDescription,
} from './patterns.js';
import { normalizeText, findTerms } from './synonyms.js';

/**
 * Classification result for a single intent
 */
export interface ClassificationResult {
  /** The classified intent */
  intent: SecurityIntent;
  /** Confidence score (0.0-1.0) */
  confidence: number;
  /** Alternative intents with lower confidence */
  alternativeIntents: Array<{
    intent: SecurityIntent;
    confidence: number;
  }>;
  /** Human-readable explanation of the classification */
  explanation: string;
  /** Matched patterns that led to this classification */
  matchedPatterns: string[];
  /** Matched keywords */
  matchedKeywords: string[];
  /** Original text that was classified */
  originalText: string;
  /** Normalized text after synonym replacement */
  normalizedText: string;
}

/**
 * Negation detection result
 */
export interface NegationResult {
  /** Whether negation was detected */
  hasNegation: boolean;
  /** Terms that are negated */
  negatedTerms: string[];
  /** The negation pattern that matched */
  negationPattern?: string;
}

/**
 * Compound prompt parsing result
 */
export interface CompoundResult {
  /** Individual prompt segments */
  segments: string[];
  /** The connectors found between segments */
  connectors: string[];
  /** Whether the prompt is compound */
  isCompound: boolean;
}

/**
 * Internal scoring result for intent matching
 */
interface IntentScore {
  intent: SecurityIntent;
  score: number;
  patternMatches: string[];
  keywordMatches: string[];
}

/**
 * Intent Classifier - Classifies natural language prompts into security intents
 */
export class IntentClassifier {
  private readonly minConfidence: number = 0.3;
  private readonly maxAlternatives: number = 3;

  /**
   * Create a new IntentClassifier
   * @param options Configuration options
   */
  constructor(options?: { minConfidence?: number; maxAlternatives?: number }) {
    if (options?.minConfidence !== undefined) {
      this.minConfidence = options.minConfidence;
    }
    if (options?.maxAlternatives !== undefined) {
      this.maxAlternatives = options.maxAlternatives;
    }
  }

  /**
   * Classify a prompt into a security intent
   * Returns the highest confidence intent
   * @param text The prompt text to classify
   * @returns Classification result with intent and confidence
   */
  classify(text: string): ClassificationResult {
    return this.classifyWithAlternatives(text);
  }

  /**
   * Classify a prompt and return alternatives
   * @param text The prompt text to classify
   * @returns Classification result with alternatives
   */
  classifyWithAlternatives(text: string): ClassificationResult {
    const normalizedText = this.normalizeSynonyms(text);
    const scores = this.scoreAllIntents(normalizedText, text);

    // Sort by score (highest first)
    scores.sort((a, b) => b.score - a.score);

    // Get the top intent
    const topScore = scores[0];
    const confidence = this.calculateConfidence(topScore, scores);

    // Get alternatives (other intents above minimum confidence)
    const alternatives = scores
      .slice(1)
      .filter(s => {
        const altConfidence = this.calculateConfidence(s, scores);
        return altConfidence >= this.minConfidence;
      })
      .slice(0, this.maxAlternatives)
      .map(s => ({
        intent: s.intent,
        confidence: this.calculateConfidence(s, scores),
      }));

    // Build explanation
    const explanation = this.buildExplanation(topScore, confidence);

    return {
      intent: confidence >= this.minConfidence ? topScore.intent : 'unknown',
      confidence,
      alternativeIntents: alternatives,
      explanation,
      matchedPatterns: topScore.patternMatches,
      matchedKeywords: topScore.keywordMatches,
      originalText: text,
      normalizedText,
    };
  }

  /**
   * Normalize synonyms in text
   * @param text The text to normalize
   * @returns Text with synonyms replaced by canonical terms
   */
  normalizeSynonyms(text: string): string {
    return normalizeText(text);
  }

  /**
   * Detect negation in a prompt
   * @param text The text to check for negation
   * @returns Negation detection result
   */
  detectNegation(text: string): NegationResult {
    const result: NegationResult = {
      hasNegation: false,
      negatedTerms: [],
    };

    for (const pattern of NEGATION_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        result.hasNegation = true;
        result.negationPattern = pattern.source;

        // Extract what comes after the negation
        const afterNegation = text.slice(match.index! + match[0].length);
        const words = afterNegation.split(/\s+/).slice(0, 3); // Get next 3 words
        result.negatedTerms.push(...words.filter(w => w.length > 2));
        break;
      }
    }

    return result;
  }

  /**
   * Parse a compound prompt into segments
   * @param text The compound prompt
   * @returns Parsed compound result with segments
   */
  parseCompound(text: string): CompoundResult {
    const result: CompoundResult = {
      segments: [],
      connectors: [],
      isCompound: false,
    };

    let remaining = text;
    const segments: string[] = [];
    const connectors: string[] = [];

    // Try to split by each connector pattern
    for (const connector of COMPOUND_CONNECTORS) {
      const parts = remaining.split(connector);
      if (parts.length > 1) {
        // Found a compound prompt
        for (let i = 0; i < parts.length; i++) {
          const part = parts[i].trim();
          if (part.length > 0) {
            segments.push(part);
            if (i < parts.length - 1) {
              // Find the actual connector text
              const match = remaining.match(connector);
              if (match) {
                connectors.push(match[0].trim());
              }
            }
          }
        }
        result.isCompound = true;
        result.segments = segments;
        result.connectors = connectors;
        return result;
      }
    }

    // Not compound - return original text as single segment
    result.segments = [text];
    return result;
  }

  /**
   * Score all intents against the text
   * @param normalizedText Text after synonym normalization
   * @param originalText Original text for reference
   * @returns Array of intent scores
   */
  private scoreAllIntents(normalizedText: string, originalText: string): IntentScore[] {
    const scores: IntentScore[] = [];

    for (const intentPattern of INTENT_PATTERNS) {
      const score = this.scoreIntent(intentPattern, normalizedText, originalText);
      scores.push(score);
    }

    // Add 'unknown' intent with base score
    scores.push({
      intent: 'unknown',
      score: 0.1,
      patternMatches: [],
      keywordMatches: [],
    });

    return scores;
  }

  /**
   * Score a single intent pattern against text
   */
  private scoreIntent(
    intentPattern: IntentPattern,
    normalizedText: string,
    originalText: string
  ): IntentScore {
    const patternMatches: string[] = [];
    const keywordMatches: string[] = [];
    let score = 0;

    // Check regex patterns
    for (const pattern of intentPattern.patterns) {
      const match = normalizedText.match(pattern) || originalText.match(pattern);
      if (match) {
        patternMatches.push(match[0]);
        score += intentPattern.weight * 0.4; // Pattern match contributes 40%
      }
    }

    // Check keywords (in normalized text)
    const lowerNormalized = normalizedText.toLowerCase();
    for (const keyword of intentPattern.keywords) {
      if (lowerNormalized.includes(keyword.toLowerCase())) {
        keywordMatches.push(keyword);
        score += intentPattern.weight * 0.2; // Keyword match contributes 20%
      }
    }

    // Check for found security terms (from synonyms)
    const foundTerms = findTerms(originalText);
    for (const term of foundTerms) {
      if (intentPattern.keywords.includes(term.canonical.toLowerCase())) {
        if (!keywordMatches.includes(term.canonical)) {
          keywordMatches.push(term.canonical);
          score += intentPattern.weight * 0.15; // Synonym match contributes 15%
        }
      }
    }

    // Apply priority boost for more specific intents
    const priorityIndex = INTENT_PRIORITY.indexOf(intentPattern.intent);
    if (priorityIndex >= 0 && priorityIndex < 5) {
      score *= 1.1; // 10% boost for high-priority intents
    }

    return {
      intent: intentPattern.intent,
      score,
      patternMatches,
      keywordMatches,
    };
  }

  /**
   * Calculate confidence score for an intent
   * Normalizes score to 0.0-1.0 range
   */
  private calculateConfidence(intentScore: IntentScore, allScores: IntentScore[]): number {
    const maxPossibleScore = 2.0; // Maximum theoretical score
    const rawConfidence = Math.min(intentScore.score / maxPossibleScore, 1.0);

    // Adjust based on separation from second-best
    if (allScores.length > 1) {
      const secondBest = allScores.find(s => s.intent !== intentScore.intent);
      if (secondBest && secondBest.score > 0) {
        const separation = intentScore.score / secondBest.score;
        // If clear separation (2x or more), boost confidence slightly
        if (separation >= 2) {
          return Math.min(rawConfidence * 1.1, 1.0);
        }
      }
    }

    return rawConfidence;
  }

  /**
   * Build human-readable explanation for classification
   */
  private buildExplanation(topScore: IntentScore, confidence: number): string {
    const intentDescription = getIntentDescription(topScore.intent);
    const parts: string[] = [];

    parts.push(`Classified as "${topScore.intent}" (${intentDescription}).`);

    if (topScore.patternMatches.length > 0) {
      parts.push(`Matched patterns: "${topScore.patternMatches.slice(0, 3).join('", "')}".`);
    }

    if (topScore.keywordMatches.length > 0) {
      parts.push(`Found keywords: ${topScore.keywordMatches.slice(0, 5).join(', ')}.`);
    }

    parts.push(`Confidence: ${(confidence * 100).toFixed(0)}%.`);

    return parts.join(' ');
  }
}

/**
 * Factory function to create an IntentClassifier instance
 */
export function createIntentClassifier(options?: {
  minConfidence?: number;
  maxAlternatives?: number;
}): IntentClassifier {
  return new IntentClassifier(options);
}

// Default singleton instance
let defaultClassifier: IntentClassifier | null = null;

/**
 * Get the default IntentClassifier instance (singleton)
 */
export function getIntentClassifier(): IntentClassifier {
  if (!defaultClassifier) {
    defaultClassifier = new IntentClassifier();
  }
  return defaultClassifier;
}

/**
 * Quick classify function for simple use cases
 * @param text The text to classify
 * @returns The classified intent
 */
export function classifyIntent(text: string): SecurityIntent {
  return getIntentClassifier().classify(text).intent;
}

/**
 * Quick classify with confidence
 * @param text The text to classify
 * @returns Tuple of [intent, confidence]
 */
export function classifyIntentWithConfidence(text: string): [SecurityIntent, number] {
  const result = getIntentClassifier().classify(text);
  return [result.intent, result.confidence];
}
