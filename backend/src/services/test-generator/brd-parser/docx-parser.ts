/**
 * BP-002: DOCX Parser
 * Parses BRD documents in Microsoft Word format
 */

import * as fs from 'fs/promises';
import { createLogger } from '../../../utils/logger.js';
import type { BRDSection, ParsedRequirement } from '../types.js';
import {
  parseMarkdownSections,
  extractMarkdownRequirements,
} from './markdown-parser.js';

const logger = createLogger('docx-parser');

// DOCX is a ZIP file containing XML. We'll use a simple approach
// that extracts text content from the document.xml file.

/**
 * Extract text from DOCX XML content
 * This is a lightweight parser that doesn't require external dependencies
 */
function extractTextFromDocxXml(xmlContent: string): string {
  const lines: string[] = [];

  // Split by paragraph tags
  const paragraphs = xmlContent.split(/<\/w:p>/);

  for (const para of paragraphs) {
    const textMatches = para.matchAll(/<w:t[^>]*>([^<]*)<\/w:t>/g);
    const paraText: string[] = [];

    for (const textMatch of textMatches) {
      paraText.push(textMatch[1]);
    }

    if (paraText.length > 0) {
      const fullText = paraText.join('');

      // Check if this is a heading (based on style)
      const isHeading = /<w:pStyle[^>]*w:val="Heading(\d)"/i.test(para);
      const headingLevel = para.match(/<w:pStyle[^>]*w:val="Heading(\d)"/i)?.[1];

      if (isHeading && headingLevel) {
        lines.push('#'.repeat(parseInt(headingLevel, 10)) + ' ' + fullText);
      } else if (/<w:numPr>/.test(para)) {
        // This is a list item
        lines.push('- ' + fullText);
      } else {
        lines.push(fullText);
      }
    }
  }

  return lines.join('\n');
}

/**
 * Extract document.xml from DOCX file
 * DOCX files are ZIP archives containing XML files
 */
async function extractDocxContent(filePath: string): Promise<string> {
  // Read the DOCX file as a buffer
  const buffer = await fs.readFile(filePath);

  // DOCX is a ZIP file. We need to find and extract word/document.xml
  // ZIP file structure: Local file headers followed by central directory

  // Simple ZIP parsing to find document.xml
  const content = await parseZipForDocumentXml(buffer);

  if (!content) {
    throw new Error('Could not find document.xml in DOCX file');
  }

  return content;
}

/**
 * Simple ZIP parser to extract document.xml from DOCX
 */
async function parseZipForDocumentXml(buffer: Buffer): Promise<string | null> {
  // ZIP local file header signature
  const LOCAL_FILE_HEADER = 0x04034b50;

  let offset = 0;

  while (offset < buffer.length - 4) {
    const signature = buffer.readUInt32LE(offset);

    if (signature !== LOCAL_FILE_HEADER) {
      // Try to find next header
      offset++;
      continue;
    }

    // Parse local file header
    const compressionMethod = buffer.readUInt16LE(offset + 8);
    const compressedSize = buffer.readUInt32LE(offset + 18);
    // const uncompressedSize = buffer.readUInt32LE(offset + 22); // Available but not needed
    const filenameLength = buffer.readUInt16LE(offset + 26);
    const extraFieldLength = buffer.readUInt16LE(offset + 28);

    const filenameStart = offset + 30;
    const filename = buffer.toString('utf-8', filenameStart, filenameStart + filenameLength);

    const dataStart = filenameStart + filenameLength + extraFieldLength;

    if (filename === 'word/document.xml') {
      const data = buffer.subarray(dataStart, dataStart + compressedSize);

      if (compressionMethod === 0) {
        // No compression (STORED)
        return data.toString('utf-8');
      } else if (compressionMethod === 8) {
        // DEFLATE compression
        const { inflateRawSync } = await import('zlib');
        try {
          const decompressed = inflateRawSync(data);
          return decompressed.toString('utf-8');
        } catch {
          logger.error('Failed to decompress document.xml');
          return null;
        }
      }
    }

    offset = dataStart + compressedSize;
  }

  return null;
}

/**
 * Parse a DOCX file into BRD sections and requirements
 */
export async function parseDocxFile(filePath: string): Promise<{
  sections: BRDSection[];
  requirements: ParsedRequirement[];
  rawText: string;
}> {
  logger.info({ filePath }, 'Parsing DOCX file');

  const startTime = Date.now();

  // Extract XML content from DOCX
  const xmlContent = await extractDocxContent(filePath);

  // Convert XML to plain text with markdown-like formatting
  const rawText = extractTextFromDocxXml(xmlContent);

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
    'DOCX parsing completed'
  );

  return { sections, requirements, rawText };
}

/**
 * Extract tables from DOCX
 * Tables often contain requirement matrices
 */
export function extractTablesFromDocxXml(xmlContent: string): Array<{
  headers: string[];
  rows: string[][];
}> {
  const tables: Array<{ headers: string[]; rows: string[][] }> = [];

  // Find all table elements
  const tablePattern = /<w:tbl[^>]*>([\s\S]*?)<\/w:tbl>/g;
  let tableMatch;

  while ((tableMatch = tablePattern.exec(xmlContent)) !== null) {
    const tableContent = tableMatch[1];
    const rows: string[][] = [];

    // Find all rows
    const rowPattern = /<w:tr[^>]*>([\s\S]*?)<\/w:tr>/g;
    let rowMatch;

    while ((rowMatch = rowPattern.exec(tableContent)) !== null) {
      const rowContent = rowMatch[1];
      const cells: string[] = [];

      // Find all cells
      const cellPattern = /<w:tc[^>]*>([\s\S]*?)<\/w:tc>/g;
      let cellMatch;

      while ((cellMatch = cellPattern.exec(rowContent)) !== null) {
        const cellContent = cellMatch[1];

        // Extract text from cell
        const textMatches = cellContent.matchAll(/<w:t[^>]*>([^<]*)<\/w:t>/g);
        const cellText: string[] = [];

        for (const textMatch of textMatches) {
          cellText.push(textMatch[1]);
        }

        cells.push(cellText.join(' ').trim());
      }

      if (cells.length > 0) {
        rows.push(cells);
      }
    }

    if (rows.length > 0) {
      tables.push({
        headers: rows[0],
        rows: rows.slice(1),
      });
    }
  }

  return tables;
}

/**
 * Extract requirements from DOCX tables
 * Common table formats: ID | Description | Priority | Status
 */
export function extractRequirementsFromTables(tables: Array<{
  headers: string[];
  rows: string[][];
}>): ParsedRequirement[] {
  const requirements: ParsedRequirement[] = [];

  for (const table of tables) {
    // Look for common requirement table headers
    const idIndex = table.headers.findIndex(h =>
      /^(id|req|requirement|#|number)$/i.test(h.trim())
    );
    const descIndex = table.headers.findIndex(h =>
      /^(desc|description|requirement|text|detail)$/i.test(h.trim())
    );
    const priorityIndex = table.headers.findIndex(h =>
      /^(priority|importance|level)$/i.test(h.trim())
    );
    const typeIndex = table.headers.findIndex(h =>
      /^(type|category|class)$/i.test(h.trim())
    );

    // If we found at least ID and description columns
    if (idIndex >= 0 && descIndex >= 0) {
      for (const row of table.rows) {
        const id = row[idIndex]?.trim();
        const description = row[descIndex]?.trim();

        if (id && description) {
          let priority: ParsedRequirement['priority'] = 'medium';
          if (priorityIndex >= 0) {
            const prioText = row[priorityIndex]?.toLowerCase() || '';
            if (/critical|p0|must/i.test(prioText)) priority = 'critical';
            else if (/high|p1|important/i.test(prioText)) priority = 'high';
            else if (/low|p3|nice/i.test(prioText)) priority = 'low';
          }

          let type: ParsedRequirement['type'] = 'functional';
          if (typeIndex >= 0) {
            const typeText = row[typeIndex]?.toLowerCase() || '';
            if (/security/i.test(typeText)) type = 'security';
            else if (/non-?func|nfr|performance/i.test(typeText)) type = 'non-functional';
            else if (/api|interface|integration/i.test(typeText)) type = 'api';
          }

          requirements.push({
            id,
            title: description.substring(0, 50) + (description.length > 50 ? '...' : ''),
            description,
            type,
            priority,
            acceptanceCriteria: [],
            source: {
              file: '',
              section: 'Requirements Table',
              lineNumber: 0,
            },
          });
        }
      }
    }
  }

  return requirements;
}

/**
 * Check if file is a valid DOCX file
 */
export async function isValidDocx(filePath: string): Promise<boolean> {
  try {
    const buffer = await fs.readFile(filePath);

    // Check for ZIP signature (DOCX is a ZIP file)
    if (buffer.length < 4) return false;

    const signature = buffer.readUInt32LE(0);
    return signature === 0x04034b50; // PK ZIP signature
  } catch {
    return false;
  }
}

/**
 * Get document metadata from DOCX
 */
export async function getDocxMetadata(filePath: string): Promise<{
  title?: string;
  subject?: string;
  creator?: string;
  created?: string;
  modified?: string;
}> {
  try {
    const buffer = await fs.readFile(filePath);

    // Try to find core.xml which contains metadata
    // This is a simplified approach - full implementation would parse the ZIP properly
    const content = buffer.toString('utf-8');

    const metadata: {
      title?: string;
      subject?: string;
      creator?: string;
      created?: string;
      modified?: string;
    } = {};

    // Extract metadata fields if present
    const titleMatch = content.match(/<dc:title>([^<]*)<\/dc:title>/);
    if (titleMatch) metadata.title = titleMatch[1];

    const subjectMatch = content.match(/<dc:subject>([^<]*)<\/dc:subject>/);
    if (subjectMatch) metadata.subject = subjectMatch[1];

    const creatorMatch = content.match(/<dc:creator>([^<]*)<\/dc:creator>/);
    if (creatorMatch) metadata.creator = creatorMatch[1];

    const createdMatch = content.match(/<dcterms:created[^>]*>([^<]*)<\/dcterms:created>/);
    if (createdMatch) metadata.created = createdMatch[1];

    const modifiedMatch = content.match(/<dcterms:modified[^>]*>([^<]*)<\/dcterms:modified>/);
    if (modifiedMatch) metadata.modified = modifiedMatch[1];

    return metadata;
  } catch {
    return {};
  }
}
