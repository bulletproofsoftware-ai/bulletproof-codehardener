/**
 * BP-003: PDF Parser
 * Parses BRD documents in PDF format
 */

import * as fs from 'fs/promises';
import { createLogger } from '../../../utils/logger.js';
import type { BRDSection, ParsedRequirement } from '../types.js';
import {
  parseMarkdownSections,
  extractMarkdownRequirements,
} from './markdown-parser.js';

const logger = createLogger('pdf-parser');

/**
 * PDF object types
 */
type PDFObject = string | number | boolean | null | PDFArray | PDFDictionary;
type PDFArray = PDFObject[];
interface PDFDictionary {
  [key: string]: PDFObject;
}

/**
 * Extract text content from a PDF file
 * This is a basic PDF text extractor that handles common PDF structures
 */
async function extractPdfText(filePath: string): Promise<string> {
  const buffer = await fs.readFile(filePath);
  const content = buffer.toString('binary');

  // Check PDF signature
  if (!content.startsWith('%PDF-')) {
    throw new Error('Invalid PDF file');
  }

  const textBlocks: string[] = [];

  // Find and extract text streams
  // PDF text is typically in stream objects between "stream" and "endstream"

  // Pattern to find stream content
  const streamPattern = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
  let streamMatch;

  while ((streamMatch = streamPattern.exec(content)) !== null) {
    const streamData = streamMatch[1];

    // Try to extract text from the stream
    const extractedText = extractTextFromStream(streamData);
    if (extractedText) {
      textBlocks.push(extractedText);
    }
  }

  // Also try to find text in BT...ET blocks (text objects)
  const textObjectPattern = /BT\s*([\s\S]*?)\s*ET/g;
  let textMatch;

  while ((textMatch = textObjectPattern.exec(content)) !== null) {
    const textContent = textMatch[1];
    const extractedText = extractTextFromTextObject(textContent);
    if (extractedText) {
      textBlocks.push(extractedText);
    }
  }

  // Join all text blocks
  const fullText = textBlocks.join('\n');

  // Clean up the text
  return cleanPdfText(fullText);
}

/**
 * Extract text from a PDF stream
 */
function extractTextFromStream(streamData: string): string {
  const textParts: string[] = [];

  // Look for text showing operators: Tj, TJ, ', "
  // Tj: Show string
  // TJ: Show array of strings
  // ': Move to next line and show string
  // ": Set word and character spacing, move to next line, show string

  // Simple string pattern (hex or literal)
  const stringPattern = /\(([^)]*)\)|<([0-9A-Fa-f]+)>/g;
  let match;

  while ((match = stringPattern.exec(streamData)) !== null) {
    if (match[1]) {
      // Literal string
      textParts.push(decodePdfString(match[1]));
    } else if (match[2]) {
      // Hex string
      textParts.push(decodeHexString(match[2]));
    }
  }

  return textParts.join('');
}

/**
 * Extract text from a BT...ET text object
 */
function extractTextFromTextObject(textContent: string): string {
  const textParts: string[] = [];

  // Look for Tj operator with string
  const tjPattern = /\(([^)]*)\)\s*Tj/g;
  let tjMatch;

  while ((tjMatch = tjPattern.exec(textContent)) !== null) {
    textParts.push(decodePdfString(tjMatch[1]));
  }

  // Look for TJ operator with array
  const tjArrayPattern = /\[(.*?)\]\s*TJ/g;
  let tjArrayMatch;

  while ((tjArrayMatch = tjArrayPattern.exec(textContent)) !== null) {
    const arrayContent = tjArrayMatch[1];
    const strings = arrayContent.match(/\(([^)]*)\)/g);
    if (strings) {
      for (const str of strings) {
        const decoded = decodePdfString(str.slice(1, -1));
        textParts.push(decoded);
      }
    }
  }

  // Look for ' operator
  const quotePattern = /\(([^)]*)\)\s*'/g;
  let quoteMatch;

  while ((quoteMatch = quotePattern.exec(textContent)) !== null) {
    textParts.push('\n' + decodePdfString(quoteMatch[1]));
  }

  return textParts.join('');
}

/**
 * Decode PDF literal string (handle escape sequences)
 */
function decodePdfString(str: string): string {
  return str
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\b/g, '\b')
    .replace(/\\f/g, '\f')
    .replace(/\\\(/g, '(')
    .replace(/\\\)/g, ')')
    .replace(/\\\\/g, '\\')
    .replace(/\\(\d{1,3})/g, (_, octal) => String.fromCharCode(parseInt(octal, 8)));
}

/**
 * Decode hex string
 */
function decodeHexString(hex: string): string {
  let result = '';
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.substr(i, 2), 16);
    result += String.fromCharCode(byte);
  }
  return result;
}

/**
 * Clean up extracted PDF text
 */
function cleanPdfText(text: string): string {
  return text
    // Remove excessive whitespace
    .replace(/\s+/g, ' ')
    // Restore line breaks at sentence ends
    .replace(/\.\s+([A-Z])/g, '.\n$1')
    // Restore line breaks at bullet points
    .replace(/([•·-])\s*/g, '\n$1 ')
    // Restore line breaks at numbered items
    .replace(/(\d+\.)\s+/g, '\n$1 ')
    // Clean up multiple newlines
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * Try to detect section headings from PDF text
 * PDFs often don't have explicit heading markers, so we use heuristics
 */
function detectHeadings(text: string): string {
  const lines = text.split('\n');
  const result: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Skip empty lines
    if (!line) {
      result.push('');
      continue;
    }

    // Detect potential headings:
    // 1. All caps lines
    // 2. Numbered sections (1. Section Name)
    // 3. Short lines followed by longer content

    const isAllCaps = line === line.toUpperCase() && /[A-Z]/.test(line) && line.length > 3;
    const isNumberedSection = /^\d+(\.\d+)*\.?\s+[A-Z]/.test(line);
    const isShortLine = line.length < 60 && !line.endsWith('.') && !line.endsWith(',');

    // Check if next line is longer (content after heading)
    const nextLine = lines[i + 1]?.trim() || '';
    const nextIsContent = nextLine.length > line.length * 1.5;

    if (isAllCaps || isNumberedSection) {
      // Determine heading level
      let level = 1;
      if (isNumberedSection) {
        const dots = (line.match(/\./g) || []).length;
        level = Math.min(dots + 1, 3);
      }
      result.push('#'.repeat(level) + ' ' + line);
    } else if (isShortLine && nextIsContent && !line.startsWith('-') && !line.startsWith('*')) {
      // Potentially a heading
      result.push('## ' + line);
    } else {
      result.push(line);
    }
  }

  return result.join('\n');
}

/**
 * Parse a PDF file into BRD sections and requirements
 */
export async function parsePdfFile(filePath: string): Promise<{
  sections: BRDSection[];
  requirements: ParsedRequirement[];
  rawText: string;
}> {
  logger.info({ filePath }, 'Parsing PDF file');

  const startTime = Date.now();

  // Extract text from PDF
  let rawText = await extractPdfText(filePath);

  // Try to detect headings
  rawText = detectHeadings(rawText);

  // Use markdown parser to extract sections and requirements
  const sections = parseMarkdownSections(rawText);
  const requirements = extractMarkdownRequirements(rawText);

  // Update source file path
  for (const req of requirements) {
    if (req.source && typeof req.source === 'object') {
      req.source.file = filePath;
    } else {
      req.source = { file: filePath, section: '' };
    }
  }

  logger.info(
    {
      filePath,
      sectionCount: sections.length,
      requirementCount: requirements.length,
      rawTextLength: rawText.length,
      durationMs: Date.now() - startTime,
    },
    'PDF parsing completed'
  );

  return { sections, requirements, rawText };
}

/**
 * Check if file is a valid PDF
 */
export async function isValidPdf(filePath: string): Promise<boolean> {
  try {
    const buffer = await fs.readFile(filePath);
    const header = buffer.toString('utf-8', 0, 8);
    return header.startsWith('%PDF-');
  } catch {
    return false;
  }
}

/**
 * Get PDF metadata
 */
export async function getPdfMetadata(filePath: string): Promise<{
  title?: string;
  author?: string;
  subject?: string;
  creator?: string;
  producer?: string;
  creationDate?: string;
  modDate?: string;
}> {
  try {
    const buffer = await fs.readFile(filePath);
    const content = buffer.toString('binary');

    const metadata: {
      title?: string;
      author?: string;
      subject?: string;
      creator?: string;
      producer?: string;
      creationDate?: string;
      modDate?: string;
    } = {};

    // Look for Info dictionary
    const titleMatch = content.match(/\/Title\s*\(([^)]*)\)/);
    if (titleMatch) metadata.title = decodePdfString(titleMatch[1]);

    const authorMatch = content.match(/\/Author\s*\(([^)]*)\)/);
    if (authorMatch) metadata.author = decodePdfString(authorMatch[1]);

    const subjectMatch = content.match(/\/Subject\s*\(([^)]*)\)/);
    if (subjectMatch) metadata.subject = decodePdfString(subjectMatch[1]);

    const creatorMatch = content.match(/\/Creator\s*\(([^)]*)\)/);
    if (creatorMatch) metadata.creator = decodePdfString(creatorMatch[1]);

    const producerMatch = content.match(/\/Producer\s*\(([^)]*)\)/);
    if (producerMatch) metadata.producer = decodePdfString(producerMatch[1]);

    const creationDateMatch = content.match(/\/CreationDate\s*\(([^)]*)\)/);
    if (creationDateMatch) metadata.creationDate = decodePdfString(creationDateMatch[1]);

    const modDateMatch = content.match(/\/ModDate\s*\(([^)]*)\)/);
    if (modDateMatch) metadata.modDate = decodePdfString(modDateMatch[1]);

    return metadata;
  } catch {
    return {};
  }
}

/**
 * Get PDF page count
 */
export async function getPdfPageCount(filePath: string): Promise<number> {
  try {
    const buffer = await fs.readFile(filePath);
    const content = buffer.toString('binary');

    // Look for /Count in the Pages dictionary
    const countMatch = content.match(/\/Count\s+(\d+)/);
    if (countMatch) {
      return parseInt(countMatch[1], 10);
    }

    // Alternative: count page objects
    const pageMatches = content.match(/\/Type\s*\/Page\b/g);
    if (pageMatches) {
      return pageMatches.length;
    }

    return 0;
  } catch {
    return 0;
  }
}

/**
 * Extract text from specific pages (if possible)
 * Note: This is a simplified implementation - full page-by-page extraction
 * would require more complex PDF parsing
 */
export async function extractPdfPageText(
  filePath: string,
  _startPage: number = 1,
  _endPage: number = -1
): Promise<string> {
  // For now, extract all text
  // A full implementation would parse the PDF structure to identify page boundaries
  return extractPdfText(filePath);
}
