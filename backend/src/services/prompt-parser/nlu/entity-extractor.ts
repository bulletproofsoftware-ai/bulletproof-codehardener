/**
 * Entity Extractor Service
 * Extracts security-relevant entities from natural language prompts
 * Implements: NLU-002 (Language detection), NLU-003 (File path extraction),
 *             NLU-004 (Severity filters), NLU-005 (Output format preferences)
 */

import {
  LANGUAGE_PATTERNS,
  FILE_PATH_PATTERNS,
  SEVERITY_PATTERNS,
  TOOL_REFERENCE_PATTERNS,
  KNOWN_TOOLS,
} from './patterns.js';
import { findTerms, getCanonical } from './synonyms.js';

/**
 * Extracted language entity
 */
export interface LanguageEntity {
  /** Detected programming language */
  language: string;
  /** Original text that triggered detection */
  matchedText: string;
  /** Position in original text */
  position: number;
}

/**
 * Extracted file path entity
 */
export interface FilePathEntity {
  /** The extracted path */
  path: string;
  /** Type of path (absolute, relative, glob) */
  pathType: 'absolute' | 'relative' | 'glob' | 'file';
  /** Position in original text */
  position: number;
}

/**
 * Extracted severity filter
 */
export interface SeverityFilter {
  /** Severity level */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Comparison operator */
  operator: 'eq' | 'gte' | 'lte';
  /** Original text that specified the severity */
  matchedText: string;
}

/**
 * Extracted tool reference
 */
export interface ToolReference {
  /** Tool name (canonical) */
  tool: string;
  /** Original text that referenced the tool */
  matchedText: string;
  /** Whether this was an explicit tool name or inferred */
  explicit: boolean;
}

/**
 * Output format preference
 */
export interface OutputFormat {
  /** Preferred format */
  format: 'json' | 'sarif' | 'markdown' | 'html' | 'text' | 'table';
  /** Original text that specified the format */
  matchedText: string;
}

/**
 * Target specification (URL, repo, path)
 */
export interface TargetEntity {
  /** Target type */
  type: 'url' | 'repository' | 'path' | 'image' | 'api';
  /** Target value */
  value: string;
  /** Original text */
  matchedText: string;
}

/**
 * Complete entity extraction result
 */
export interface EntityExtractionResult {
  /** Detected programming languages */
  languages: LanguageEntity[];
  /** Extracted file paths */
  filePaths: FilePathEntity[];
  /** Severity filters */
  severityFilters: SeverityFilter[];
  /** Tool references */
  toolReferences: ToolReference[];
  /** Output format preferences */
  outputFormats: OutputFormat[];
  /** Target specifications */
  targets: TargetEntity[];
  /** All extracted entities as raw key-value pairs */
  raw: Record<string, string[]>;
}

/**
 * Output format detection patterns
 */
const OUTPUT_FORMAT_PATTERNS: Array<{
  pattern: RegExp;
  format: OutputFormat['format'];
}> = [
  { pattern: /\b(output|format|report)\s*(as|in|to)\s*json\b/i, format: 'json' },
  { pattern: /\bjson\s*(output|format|report)\b/i, format: 'json' },
  { pattern: /\b(output|format|report)\s*(as|in|to)\s*sarif\b/i, format: 'sarif' },
  { pattern: /\bsarif\s*(output|format)\b/i, format: 'sarif' },
  { pattern: /\b(output|format|report)\s*(as|in|to)\s*markdown\b/i, format: 'markdown' },
  { pattern: /\bmarkdown\s*(output|format|report)\b/i, format: 'markdown' },
  { pattern: /\b(output|format|report)\s*(as|in|to)\s*html\b/i, format: 'html' },
  { pattern: /\bhtml\s*(output|format|report)\b/i, format: 'html' },
  { pattern: /\b(output|format|report)\s*(as|in|to)\s*text\b/i, format: 'text' },
  { pattern: /\bplain\s*text\s*(output|format)\b/i, format: 'text' },
  { pattern: /\b(output|format|report)\s*(as|in|to)\s*table\b/i, format: 'table' },
  { pattern: /\btable\s*(output|format)\b/i, format: 'table' },
];

/**
 * Target detection patterns
 */
const TARGET_PATTERNS: Array<{
  pattern: RegExp;
  type: TargetEntity['type'];
}> = [
  // URLs
  { pattern: /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi, type: 'url' },
  // Git repositories
  { pattern: /\bgit@[\w.-]+:[\w/-]+\.git\b/gi, type: 'repository' },
  { pattern: /\bgithub\.com\/[\w-]+\/[\w-]+/gi, type: 'repository' },
  { pattern: /\bgitlab\.com\/[\w-]+\/[\w-]+/gi, type: 'repository' },
  // Docker images
  { pattern: /\b[\w.-]+\/[\w.-]+:[\w.-]+\b/g, type: 'image' },
  { pattern: /\b(docker|container)\s+image\s+[\w.-/]+/gi, type: 'image' },
  // API endpoints
  { pattern: /\bapi\s+endpoint\s+[^\s]+/gi, type: 'api' },
  { pattern: /\bendpoint\s+(at\s+)?\/[\w/-]+/gi, type: 'api' },
];

/**
 * Entity Extractor class
 */
export class EntityExtractor {
  /**
   * Extract all entities from text
   * @param text The text to extract entities from
   * @returns Complete entity extraction result
   */
  extract(text: string): EntityExtractionResult {
    const result: EntityExtractionResult = {
      languages: this.extractLanguages(text),
      filePaths: this.extractFilePaths(text),
      severityFilters: this.extractSeverityFilters(text),
      toolReferences: this.extractToolReferences(text),
      outputFormats: this.extractOutputFormats(text),
      targets: this.extractTargets(text),
      raw: {},
    };

    // Build raw entity map
    result.raw = {
      languages: result.languages.map(l => l.language),
      filePaths: result.filePaths.map(f => f.path),
      severities: result.severityFilters.map(s => `${s.operator}:${s.severity}`),
      tools: result.toolReferences.map(t => t.tool),
      formats: result.outputFormats.map(o => o.format),
      targets: result.targets.map(t => t.value),
    };

    return result;
  }

  /**
   * Extract programming languages from text
   * Implements: NLU-002
   */
  extractLanguages(text: string): LanguageEntity[] {
    const languages: LanguageEntity[] = [];
    const seen = new Set<string>();

    for (const { pattern, language } of LANGUAGE_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags || 'gi');
      let match;
      while ((match = regex.exec(text)) !== null) {
        if (!seen.has(language)) {
          seen.add(language);
          languages.push({
            language,
            matchedText: match[0],
            position: match.index,
          });
        }
      }
    }

    // Also check for language mentions via synonyms
    const foundTerms = findTerms(text);
    for (const term of foundTerms) {
      // Check if canonical form is a language
      const langMatch = [
        'python', 'javascript', 'typescript', 'golang', 'java', 'ruby', 'php', 'rust', 'csharp'
      ].find(l => term.canonical.toLowerCase() === l);

      if (langMatch && !seen.has(langMatch)) {
        seen.add(langMatch);
        languages.push({
          language: langMatch,
          matchedText: term.original,
          position: term.index,
        });
      }
    }

    return languages.sort((a, b) => a.position - b.position);
  }

  /**
   * Extract file paths from text
   * Implements: NLU-003
   */
  extractFilePaths(text: string): FilePathEntity[] {
    const paths: FilePathEntity[] = [];
    const seen = new Set<string>();

    for (const pattern of FILE_PATH_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags || 'g');
      let match;
      while ((match = regex.exec(text)) !== null) {
        const pathStr = match[1] || match[0];
        const trimmedPath = pathStr.trim();

        if (trimmedPath && !seen.has(trimmedPath) && this.isValidPath(trimmedPath)) {
          seen.add(trimmedPath);
          paths.push({
            path: trimmedPath,
            pathType: this.classifyPathType(trimmedPath),
            position: match.index,
          });
        }
      }
    }

    return paths.sort((a, b) => a.position - b.position);
  }

  /**
   * Extract severity filters from text
   * Implements: NLU-004
   */
  extractSeverityFilters(text: string): SeverityFilter[] {
    const filters: SeverityFilter[] = [];

    for (const { pattern, value, operator } of SEVERITY_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        // Handle $1 replacement in value
        let severity = value;
        if (value === '$1' && match[1]) {
          severity = match[1].toLowerCase();
        }

        // Validate severity value
        if (['critical', 'high', 'medium', 'low'].includes(severity)) {
          filters.push({
            severity: severity as SeverityFilter['severity'],
            operator,
            matchedText: match[0],
          });
        }
      }
    }

    return filters;
  }

  /**
   * Extract tool references from text
   * Implements: NLU-008
   */
  extractToolReferences(text: string): ToolReference[] {
    const tools: ToolReference[] = [];
    const seen = new Set<string>();
    const lowerText = text.toLowerCase();

    // Check for explicit tool names
    for (const tool of KNOWN_TOOLS) {
      if (lowerText.includes(tool.toLowerCase())) {
        if (!seen.has(tool)) {
          seen.add(tool);
          const idx = lowerText.indexOf(tool.toLowerCase());
          tools.push({
            tool,
            matchedText: text.slice(idx, idx + tool.length),
            explicit: true,
          });
        }
      }
    }

    // Check for tool reference patterns like "use X" or "run with Y"
    for (const pattern of TOOL_REFERENCE_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags || 'gi');
      let match;
      while ((match = regex.exec(text)) !== null) {
        // The captured group contains the potential tool name
        const potentialTool = match[2] || match[1];
        if (potentialTool) {
          const normalizedTool = potentialTool.toLowerCase();
          // Check if it's a known tool
          const knownTool = KNOWN_TOOLS.find(t => t.toLowerCase() === normalizedTool);
          if (knownTool && !seen.has(knownTool)) {
            seen.add(knownTool);
            tools.push({
              tool: knownTool,
              matchedText: match[0],
              explicit: true,
            });
          }
        }
      }
    }

    // Also check via synonyms (e.g., "semgrep" -> "opengrep")
    const foundTerms = findTerms(text);
    for (const term of foundTerms) {
      const canonical = getCanonical(term.original);
      if (canonical && KNOWN_TOOLS.includes(canonical) && !seen.has(canonical)) {
        seen.add(canonical);
        tools.push({
          tool: canonical,
          matchedText: term.original,
          explicit: false,
        });
      }
    }

    return tools;
  }

  /**
   * Extract output format preferences from text
   * Implements: NLU-005
   */
  extractOutputFormats(text: string): OutputFormat[] {
    const formats: OutputFormat[] = [];
    const seen = new Set<string>();

    for (const { pattern, format } of OUTPUT_FORMAT_PATTERNS) {
      const match = text.match(pattern);
      if (match && !seen.has(format)) {
        seen.add(format);
        formats.push({
          format,
          matchedText: match[0],
        });
      }
    }

    return formats;
  }

  /**
   * Extract targets (URLs, repos, images) from text
   */
  extractTargets(text: string): TargetEntity[] {
    const targets: TargetEntity[] = [];
    const seen = new Set<string>();

    for (const { pattern, type } of TARGET_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags || 'g');
      let match;
      while ((match = regex.exec(text)) !== null) {
        const value = match[0].trim();
        if (!seen.has(value)) {
          seen.add(value);
          targets.push({
            type,
            value,
            matchedText: match[0],
          });
        }
      }
    }

    return targets;
  }

  /**
   * Check if a string looks like a valid path
   */
  private isValidPath(path: string): boolean {
    // Exclude common false positives
    if (path.length < 2) return false;
    if (/^(the|a|an|is|are|was|be|to|of|and|or|in|on|at|for|with|as|by|from)$/i.test(path)) {
      return false;
    }
    // Must contain path separator or file extension
    return /[/\\.]/.test(path);
  }

  /**
   * Classify the type of path
   */
  private classifyPathType(path: string): FilePathEntity['pathType'] {
    if (path.startsWith('/') || /^[A-Za-z]:/.test(path)) {
      return 'absolute';
    }
    if (path.startsWith('./') || path.startsWith('../')) {
      return 'relative';
    }
    if (path.includes('*') || path.includes('**')) {
      return 'glob';
    }
    return 'file';
  }
}

/**
 * Factory function to create an EntityExtractor instance
 */
export function createEntityExtractor(): EntityExtractor {
  return new EntityExtractor();
}

// Default singleton instance
let defaultExtractor: EntityExtractor | null = null;

/**
 * Get the default EntityExtractor instance (singleton)
 */
export function getEntityExtractor(): EntityExtractor {
  if (!defaultExtractor) {
    defaultExtractor = new EntityExtractor();
  }
  return defaultExtractor;
}

/**
 * Quick extract function for simple use cases
 * @param text The text to extract entities from
 * @returns Entity extraction result
 */
export function extractEntities(text: string): EntityExtractionResult {
  return getEntityExtractor().extract(text);
}

/**
 * Extract just the languages from text
 * @param text The text to analyze
 * @returns Array of detected language names
 */
export function extractLanguagesFromText(text: string): string[] {
  return getEntityExtractor().extractLanguages(text).map(l => l.language);
}

/**
 * Extract just the file paths from text
 * @param text The text to analyze
 * @returns Array of extracted paths
 */
export function extractFilePathsFromText(text: string): string[] {
  return getEntityExtractor().extractFilePaths(text).map(f => f.path);
}
