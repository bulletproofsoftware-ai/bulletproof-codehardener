/**
 * BRD Parser Orchestrator
 * Coordinates parsing of BRD documents in various formats (Markdown, DOCX, PDF)
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { createLogger } from '../../../utils/logger.js';
import type { BRDSection, ParsedRequirement, BRDAnalysisResult } from '../types.js';

// Import parsers
import {
  parseMarkdownFile,
  parseMarkdownContent,
  getSectionsByType,
  getRequirementsByType,
  getSecurityRequirements,
  getHighPriorityRequirements,
} from './markdown-parser.js';

import {
  parseDocxFile,
  isValidDocx,
  getDocxMetadata,
} from './docx-parser.js';

import {
  parsePdfFile,
  isValidPdf,
  getPdfMetadata,
  getPdfPageCount,
} from './pdf-parser.js';

import {
  extractRequirements,
  categorizeRequirements,
  getRequirementsSummary,
  validateRequirements,
  findRelatedRequirements,
} from './requirement-extractor.js';

const logger = createLogger('brd-parser');

export type SupportedFormat = 'markdown' | 'docx' | 'pdf' | 'text';

export interface ParseOptions {
  /** Force specific format (auto-detect if not provided) */
  format?: SupportedFormat;
  /** Extract requirements from tables (DOCX only) */
  extractTablesAsRequirements?: boolean;
  /** Validate requirements after extraction */
  validateAfterParse?: boolean;
  /** Source identifier for tracking */
  sourceId?: string;
}

export interface ParseResult {
  format: SupportedFormat;
  sections: BRDSection[];
  requirements: ParsedRequirement[];
  rawText?: string;
  metadata?: {
    title?: string;
    author?: string;
    created?: string;
    modified?: string;
    pageCount?: number;
  };
  validation?: Array<{
    requirementId: string;
    issues: string[];
  }>;
}

/**
 * Detect file format from extension and content
 */
async function detectFormat(filePath: string): Promise<SupportedFormat> {
  const ext = path.extname(filePath).toLowerCase();

  switch (ext) {
    case '.md':
    case '.markdown':
      return 'markdown';

    case '.docx':
      if (await isValidDocx(filePath)) {
        return 'docx';
      }
      throw new Error('Invalid DOCX file');

    case '.pdf':
      if (await isValidPdf(filePath)) {
        return 'pdf';
      }
      throw new Error('Invalid PDF file');

    case '.txt':
      return 'text';

    default:
      // Try to detect from content
      try {
        const buffer = await fs.readFile(filePath);

        // Check for PDF signature
        if (buffer.toString('utf-8', 0, 5) === '%PDF-') {
          return 'pdf';
        }

        // Check for ZIP signature (DOCX)
        if (buffer.readUInt32LE(0) === 0x04034b50) {
          return 'docx';
        }

        // Default to markdown/text
        return 'markdown';
      } catch {
        return 'text';
      }
  }
}

/**
 * Parse a BRD file
 */
export async function parseBRDFile(
  filePath: string,
  options: ParseOptions = {}
): Promise<ParseResult> {
  logger.info({ filePath, options }, 'Parsing BRD file');

  const startTime = Date.now();

  // Detect or use provided format
  const format = options.format || await detectFormat(filePath);

  let sections: BRDSection[] = [];
  let requirements: ParsedRequirement[] = [];
  let rawText: string | undefined;
  let metadata: ParseResult['metadata'];

  switch (format) {
    case 'markdown':
    case 'text': {
      const result = await parseMarkdownFile(filePath);
      sections = result.sections;
      requirements = result.requirements;
      break;
    }

    case 'docx': {
      const result = await parseDocxFile(filePath);
      sections = result.sections;
      requirements = result.requirements;
      rawText = result.rawText;

      // Get metadata
      const docxMeta = await getDocxMetadata(filePath);
      metadata = {
        title: docxMeta.title,
        author: docxMeta.creator,
        created: docxMeta.created,
        modified: docxMeta.modified,
      };

      // Extract requirements from tables if requested
      if (options.extractTablesAsRequirements) {
        // We need the XML content for table extraction
        // For now, skip table extraction as it requires re-reading the file
        logger.debug('Table extraction requested but not implemented in this version');
      }
      break;
    }

    case 'pdf': {
      const result = await parsePdfFile(filePath);
      sections = result.sections;
      requirements = result.requirements;
      rawText = result.rawText;

      // Get metadata
      const pdfMeta = await getPdfMetadata(filePath);
      metadata = {
        title: pdfMeta.title,
        author: pdfMeta.author,
        created: pdfMeta.creationDate,
        modified: pdfMeta.modDate,
        pageCount: await getPdfPageCount(filePath),
      };
      break;
    }
  }

  // Extract and enrich requirements
  requirements = extractRequirements(
    sections,
    requirements,
    options.sourceId || filePath
  );

  // Validate if requested
  let validation: ParseResult['validation'];
  if (options.validateAfterParse) {
    validation = validateRequirements(requirements);
  }

  logger.info(
    {
      filePath,
      format,
      sectionCount: sections.length,
      requirementCount: requirements.length,
      validationIssues: validation?.length || 0,
      durationMs: Date.now() - startTime,
    },
    'BRD parsing completed'
  );

  return {
    format,
    sections,
    requirements,
    rawText,
    metadata,
    validation,
  };
}

/**
 * Parse BRD content from string
 */
export function parseBRDContent(
  content: string,
  options: ParseOptions = {}
): ParseResult {
  logger.info({ contentLength: content.length }, 'Parsing BRD content');

  const startTime = Date.now();
  const format: SupportedFormat = 'markdown'; // String content is always treated as markdown

  const { sections, requirements: initialRequirements } = parseMarkdownContent(
    content,
    options.sourceId || 'inline'
  );

  const requirements = extractRequirements(
    sections,
    initialRequirements,
    options.sourceId || 'inline'
  );

  let validation: ParseResult['validation'];
  if (options.validateAfterParse) {
    validation = validateRequirements(requirements);
  }

  logger.info(
    {
      format,
      sectionCount: sections.length,
      requirementCount: requirements.length,
      durationMs: Date.now() - startTime,
    },
    'BRD content parsing completed'
  );

  return {
    format,
    sections,
    requirements,
    validation,
  };
}

/**
 * Parse multiple BRD files
 */
export async function parseBRDFiles(
  filePaths: string[],
  options: ParseOptions = {}
): Promise<{
  results: Map<string, ParseResult>;
  combinedRequirements: ParsedRequirement[];
  combinedSections: BRDSection[];
}> {
  logger.info({ fileCount: filePaths.length }, 'Parsing multiple BRD files');

  const results = new Map<string, ParseResult>();
  const combinedRequirements: ParsedRequirement[] = [];
  const combinedSections: BRDSection[] = [];

  for (const filePath of filePaths) {
    try {
      const result = await parseBRDFile(filePath, {
        ...options,
        sourceId: filePath,
      });

      results.set(filePath, result);
      combinedRequirements.push(...result.requirements);
      combinedSections.push(...result.sections);
    } catch (error) {
      logger.error(
        { filePath, error: error instanceof Error ? error.message : 'Unknown error' },
        'Failed to parse BRD file'
      );
    }
  }

  // Deduplicate requirements across files
  const uniqueRequirements = deduplicateRequirements(combinedRequirements);

  logger.info(
    {
      filesProcessed: results.size,
      totalRequirements: uniqueRequirements.length,
      totalSections: combinedSections.length,
    },
    'Multiple BRD files parsed'
  );

  return {
    results,
    combinedRequirements: uniqueRequirements,
    combinedSections,
  };
}

/**
 * Deduplicate requirements based on similarity
 */
function deduplicateRequirements(requirements: ParsedRequirement[]): ParsedRequirement[] {
  const unique: ParsedRequirement[] = [];
  const seenIds = new Set<string>();

  for (const req of requirements) {
    // Skip exact ID duplicates
    if (seenIds.has(req.id)) {
      continue;
    }

    // Check for similar requirements (by description)
    const isSimilar = unique.some(existing => {
      const words1 = new Set(existing.description.toLowerCase().split(/\s+/));
      const words2 = new Set(req.description.toLowerCase().split(/\s+/));
      const intersection = new Set([...words1].filter(x => words2.has(x)));
      const union = new Set([...words1, ...words2]);
      return intersection.size / union.size > 0.9;
    });

    if (!isSimilar) {
      unique.push(req);
      seenIds.add(req.id);
    }
  }

  return unique;
}

/**
 * Create BRD analysis result
 */
export function createBRDAnalysisResult(
  parseResult: ParseResult,
  sourceFile: string
): BRDAnalysisResult {
  const categorized = categorizeRequirements(parseResult.requirements);

  return {
    id: `brd-${Date.now()}`,
    projectId: '',
    documentName: sourceFile,
    documentType: parseResult.format === 'docx' ? 'docx' : parseResult.format === 'pdf' ? 'pdf' : 'markdown',
    analysisDate: new Date(),
    sections: parseResult.sections,
    requirements: parseResult.requirements,
    securityRequirements: categorized.security,
    functionalRequirements: categorized.functional,
    apiRequirements: categorized.api,
    status: 'completed',
  };
}

// Re-export utilities
export {
  // Markdown parser
  parseMarkdownFile,
  parseMarkdownContent,
  getSectionsByType,
  getRequirementsByType,
  getSecurityRequirements,
  getHighPriorityRequirements,

  // DOCX parser
  parseDocxFile,
  isValidDocx,
  getDocxMetadata,

  // PDF parser
  parsePdfFile,
  isValidPdf,
  getPdfMetadata,
  getPdfPageCount,

  // Requirement extractor
  extractRequirements,
  categorizeRequirements,
  getRequirementsSummary,
  validateRequirements,
  findRelatedRequirements,
};
