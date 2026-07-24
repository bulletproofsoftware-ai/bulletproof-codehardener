/**
 * File Parser Service
 * Parses .md and .yaml files containing security test prompts
 * Implements: PPS-001 to PPS-012
 */

import { readFile, access, stat } from 'fs/promises';
import { constants } from 'fs';
import { extname, basename, resolve } from 'path';
import { safePath } from '../../utils/safePath.js';
import matter from 'gray-matter';
import yaml from 'js-yaml';

/**
 * Parsed prompt from a file
 */
export interface ParsedPrompt {
  /** Unique identifier for this prompt */
  id: string;
  /** The raw prompt text */
  text: string;
  /** Original source file path */
  sourcePath: string;
  /** Line number in source file */
  lineNumber: number;
  /** Associated metadata from frontmatter or yaml */
  metadata: PromptMetadata;
  /** File format (md or yaml) */
  format: 'markdown' | 'yaml';
  /** Hash of the prompt content */
  contentHash: string;
}

/**
 * Metadata associated with a prompt
 */
export interface PromptMetadata {
  /** Optional title/name for the prompt */
  title?: string;
  /** Description */
  description?: string;
  /** Tags for categorization */
  tags?: string[];
  /** Target languages */
  languages?: string[];
  /** Priority (1-10) */
  priority?: number;
  /** Expected tools to use */
  tools?: string[];
  /** Severity threshold */
  severity?: string;
  /** Custom key-value pairs */
  custom?: Record<string, unknown>;
}

/**
 * Result of parsing a file
 */
export interface FileParseResult {
  /** Whether parsing succeeded */
  success: boolean;
  /** Parsed prompts from the file */
  prompts: ParsedPrompt[];
  /** Original file path */
  filePath: string;
  /** File format detected */
  format: 'markdown' | 'yaml' | 'unknown';
  /** Parse errors if any */
  errors: ParseError[];
  /** File metadata */
  fileMetadata: {
    size: number;
    modifiedAt: Date;
    checksum: string;
  };
}

/**
 * Parse error details
 */
export interface ParseError {
  /** Error message */
  message: string;
  /** Line number where error occurred */
  line?: number;
  /** Column number */
  column?: number;
  /** Error code */
  code: string;
}

/**
 * File parser configuration
 */
export interface FileParserConfig {
  /** Maximum file size in bytes (default: 1MB) */
  maxFileSize?: number;
  /** Allowed file extensions */
  allowedExtensions?: string[];
  /** Whether to extract prompts from code blocks */
  extractCodeBlocks?: boolean;
  /** Custom prompt delimiter for markdown */
  promptDelimiter?: string;
}

const DEFAULT_CONFIG: Required<FileParserConfig> = {
  maxFileSize: 1024 * 1024, // 1MB
  allowedExtensions: ['.md', '.yaml', '.yml'],
  extractCodeBlocks: true,
  promptDelimiter: '---prompt---',
};

/**
 * File Parser class
 * Parses markdown and YAML files containing security prompts
 */
export class FileParser {
  private config: Required<FileParserConfig>;

  constructor(config?: FileParserConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Parse a file and extract prompts
   * Implements: PPS-001, PPS-002
   * @param filePath Path to the file to parse
   * @returns File parse result
   */
  async parseFile(filePath: string): Promise<FileParseResult> {
    const errors: ParseError[] = [];
    const result: FileParseResult = {
      success: false,
      prompts: [],
      filePath,
      format: 'unknown',
      errors,
      fileMetadata: {
        size: 0,
        modifiedAt: new Date(),
        checksum: '',
      },
    };

    try {
      // Validate file exists and is accessible
      const validation = await this.validateFile(filePath);
      if (!validation.valid) {
        errors.push(...validation.errors);
        return result;
      }

      // Get file metadata
      const stats = await stat(filePath);
      result.fileMetadata = {
        size: stats.size,
        modifiedAt: stats.mtime,
        checksum: await this.calculateChecksum(filePath),
      };

      // Detect format and parse
      const ext = extname(filePath).toLowerCase();
      if (ext === '.md') {
        result.format = 'markdown';
        result.prompts = await this.parseMarkdown(filePath, errors);
      } else if (ext === '.yaml' || ext === '.yml') {
        result.format = 'yaml';
        result.prompts = await this.parseYaml(filePath, errors);
      } else {
        errors.push({
          message: `Unsupported file extension: ${ext}`,
          code: 'UNSUPPORTED_EXTENSION',
        });
        return result;
      }

      result.success = result.prompts.length > 0 || errors.length === 0;
    } catch (error) {
      errors.push({
        message: error instanceof Error ? error.message : 'Unknown error',
        code: 'PARSE_ERROR',
      });
    }

    return result;
  }

  /**
   * Parse markdown file
   * Implements: PPS-003, PPS-004, PPS-005
   */
  private async parseMarkdown(filePath: string, _errors: ParseError[]): Promise<ParsedPrompt[]> {
    const content = await readFile(filePath, 'utf-8');
    const prompts: ParsedPrompt[] = [];

    // Parse frontmatter
    const { data: frontmatter, content: markdownContent } = matter(content);
    const baseMetadata = this.extractMetadata(frontmatter);

    // Split content by prompt delimiter if present
    if (content.includes(this.config.promptDelimiter)) {
      const sections = markdownContent.split(this.config.promptDelimiter);
      let lineOffset = this.countLines(content.split(markdownContent)[0] || '');

      for (let i = 0; i < sections.length; i++) {
        const section = sections[i].trim();
        if (section) {
          const prompt = this.createPrompt(
            section,
            filePath,
            lineOffset,
            baseMetadata,
            'markdown'
          );
          prompts.push(prompt);
        }
        lineOffset += this.countLines(sections[i]);
      }
    } else {
      // Extract prompts from code blocks and headings
      const extracted = this.extractPromptsFromMarkdown(markdownContent, baseMetadata);
      for (const { text, metadata, lineNumber } of extracted) {
        const prompt = this.createPrompt(
          text,
          filePath,
          lineNumber,
          { ...baseMetadata, ...metadata },
          'markdown'
        );
        prompts.push(prompt);
      }

      // If no code blocks found, treat entire content as a single prompt
      if (prompts.length === 0 && markdownContent.trim()) {
        prompts.push(
          this.createPrompt(
            markdownContent.trim(),
            filePath,
            1,
            baseMetadata,
            'markdown'
          )
        );
      }
    }

    return prompts;
  }

  /**
   * Parse YAML file
   * Implements: PPS-006, PPS-007
   */
  private async parseYaml(filePath: string, errors: ParseError[]): Promise<ParsedPrompt[]> {
    const content = await readFile(filePath, 'utf-8');
    const prompts: ParsedPrompt[] = [];

    try {
      const parsed = yaml.load(content) as unknown;

      if (Array.isArray(parsed)) {
        // Array of prompts
        for (let i = 0; i < parsed.length; i++) {
          const item = parsed[i];
          if (this.isPromptObject(item)) {
            const metadata = this.extractMetadata(item);
            const text = String(item.prompt || item.text || item);
            prompts.push(
              this.createPrompt(text, filePath, i + 1, metadata, 'yaml')
            );
          }
        }
      } else if (this.isPromptObject(parsed)) {
        // Single prompt object
        const metadata = this.extractMetadata(parsed);
        const text = String(parsed.prompt || parsed.text || '');
        if (text) {
          prompts.push(
            this.createPrompt(text, filePath, 1, metadata, 'yaml')
          );
        }

        // Check for nested prompts array
        if (Array.isArray(parsed.prompts)) {
          for (let i = 0; i < parsed.prompts.length; i++) {
            const item = parsed.prompts[i];
            if (typeof item === 'string') {
              prompts.push(
                this.createPrompt(item, filePath, i + 2, metadata, 'yaml')
              );
            } else if (this.isPromptObject(item)) {
              const itemMetadata = { ...metadata, ...this.extractMetadata(item) };
              const itemText = String(item.prompt || item.text || '');
              if (itemText) {
                prompts.push(
                  this.createPrompt(itemText, filePath, i + 2, itemMetadata, 'yaml')
                );
              }
            }
          }
        }
      }
    } catch (error) {
      errors.push({
        message: error instanceof Error ? error.message : 'YAML parse error',
        code: 'YAML_PARSE_ERROR',
      });
    }

    return prompts;
  }

  /**
   * Extract prompts from markdown content
   * Looks for code blocks with 'prompt' or 'security' language tag
   */
  private extractPromptsFromMarkdown(
    content: string,
    _baseMetadata: PromptMetadata
  ): Array<{ text: string; metadata: PromptMetadata; lineNumber: number }> {
    const prompts: Array<{ text: string; metadata: PromptMetadata; lineNumber: number }> = [];

    // Match code blocks with specific language tags
    const codeBlockRegex = /```(?:prompt|security|scan|test)(.*?)\n([\s\S]*?)```/gi;
    let match;
    let lineNumber = 1;

    while ((match = codeBlockRegex.exec(content)) !== null) {
      const blockContent = match[2].trim();
      if (blockContent) {
        // Count lines up to this match
        lineNumber = this.countLines(content.substring(0, match.index)) + 1;
        prompts.push({
          text: blockContent,
          metadata: {},
          lineNumber,
        });
      }
    }

    // Also extract from sections with specific headings
    const headingRegex = /^#+\s*(security\s*test|prompt|scan|check):?\s*(.*)$/gim;
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const headingMatch = headingRegex.exec(line);
      if (headingMatch) {
        // Get content until next heading or end
        let promptText = '';
        let j = i + 1;
        while (j < lines.length && !lines[j].startsWith('#')) {
          promptText += lines[j] + '\n';
          j++;
        }
        promptText = promptText.trim();
        if (promptText) {
          prompts.push({
            text: promptText,
            metadata: { title: headingMatch[2] || undefined },
            lineNumber: i + 1,
          });
        }
      }
    }

    return prompts;
  }

  /**
   * Validate file before parsing
   * Implements: PPS-008, PPS-009
   */
  private async validateFile(
    filePath: string
  ): Promise<{ valid: boolean; errors: ParseError[] }> {
    const errors: ParseError[] = [];

    // Check file exists
    try {
      await access(filePath, constants.R_OK);
    } catch {
      errors.push({
        message: `File not found or not readable: ${filePath}`,
        code: 'FILE_NOT_FOUND',
      });
      return { valid: false, errors };
    }

    // Check file size
    const stats = await stat(filePath);
    if (stats.size > this.config.maxFileSize) {
      errors.push({
        message: `File too large: ${stats.size} bytes (max: ${this.config.maxFileSize})`,
        code: 'FILE_TOO_LARGE',
      });
      return { valid: false, errors };
    }

    // Check extension
    const ext = extname(filePath).toLowerCase();
    if (!this.config.allowedExtensions.includes(ext)) {
      errors.push({
        message: `Unsupported extension: ${ext}`,
        code: 'UNSUPPORTED_EXTENSION',
      });
      return { valid: false, errors };
    }

    // Security: Check for path traversal
    const resolvedPath = safePath(process.cwd(), filePath);
    if (filePath.includes('..') && resolvedPath !== resolve(process.cwd(), filePath)) {
      errors.push({
        message: 'Path traversal detected',
        code: 'PATH_TRAVERSAL',
      });
      return { valid: false, errors };
    }

    return { valid: true, errors };
  }

  /**
   * Create a ParsedPrompt object
   */
  private createPrompt(
    text: string,
    sourcePath: string,
    lineNumber: number,
    metadata: PromptMetadata,
    format: 'markdown' | 'yaml'
  ): ParsedPrompt {
    return {
      id: this.generatePromptId(sourcePath, lineNumber, text),
      text: text.trim(),
      sourcePath,
      lineNumber,
      metadata,
      format,
      contentHash: this.hashContent(text),
    };
  }

  /**
   * Extract metadata from an object
   */
  private extractMetadata(obj: unknown): PromptMetadata {
    if (!obj || typeof obj !== 'object') {
      return {};
    }

    const data = obj as Record<string, unknown>;
    const metadata: PromptMetadata = {};

    if (typeof data.title === 'string') metadata.title = data.title;
    if (typeof data.description === 'string') metadata.description = data.description;
    if (Array.isArray(data.tags)) metadata.tags = data.tags.filter(t => typeof t === 'string');
    if (Array.isArray(data.languages)) metadata.languages = data.languages.filter(l => typeof l === 'string');
    if (typeof data.priority === 'number') metadata.priority = data.priority;
    if (Array.isArray(data.tools)) metadata.tools = data.tools.filter(t => typeof t === 'string');
    if (typeof data.severity === 'string') metadata.severity = data.severity;

    // Collect remaining custom fields
    const knownFields = ['title', 'description', 'tags', 'languages', 'priority', 'tools', 'severity', 'prompt', 'text', 'prompts'];
    const custom: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      if (!knownFields.includes(key)) {
        custom[key] = value;
      }
    }
    if (Object.keys(custom).length > 0) {
      metadata.custom = custom;
    }

    return metadata;
  }

  /**
   * Check if an object is a prompt object
   */
  private isPromptObject(obj: unknown): obj is Record<string, unknown> {
    return obj !== null && typeof obj === 'object';
  }

  /**
   * Count lines in text
   */
  private countLines(text: string): number {
    return (text.match(/\n/g) || []).length + 1;
  }

  /**
   * Generate a unique prompt ID
   */
  private generatePromptId(filePath: string, lineNumber: number, text: string): string {
    const fileName = basename(filePath, extname(filePath));
    const hash = this.hashContent(text).substring(0, 8);
    return `${fileName}-L${lineNumber}-${hash}`;
  }

  /**
   * Calculate file checksum
   */
  private async calculateChecksum(filePath: string): Promise<string> {
    const content = await readFile(filePath, 'utf-8');
    return this.hashContent(content);
  }

  /**
   * Simple hash function for content
   * Uses djb2 algorithm for fast hashing
   */
  private hashContent(content: string): string {
    let hash = 5381;
    for (let i = 0; i < content.length; i++) {
      hash = ((hash << 5) + hash) + content.charCodeAt(i);
    }
    return Math.abs(hash).toString(16);
  }
}

/**
 * Factory function to create a FileParser instance
 */
export function createFileParser(config?: FileParserConfig): FileParser {
  return new FileParser(config);
}

// Default singleton instance
let defaultParser: FileParser | null = null;

/**
 * Get the default FileParser instance (singleton)
 */
export function getFileParser(): FileParser {
  if (!defaultParser) {
    defaultParser = new FileParser();
  }
  return defaultParser;
}

/**
 * Quick parse function for simple use cases
 * @param filePath Path to the file to parse
 * @returns File parse result
 */
export async function parseFile(filePath: string): Promise<FileParseResult> {
  return getFileParser().parseFile(filePath);
}
