/**
 * BP-001: Markdown Parser
 * Parses BRD documents in Markdown format
 */

import * as fs from 'fs/promises';
import { createLogger } from '../../../utils/logger.js';
import type { BRDSection, ParsedRequirement } from '../types.js';

const logger = createLogger('markdown-parser');

/** Escape special regex characters in a string */
function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Heading pattern matching
const HEADING_PATTERNS = {
  h1: /^#\s+(.+)$/,
  h2: /^##\s+(.+)$/,
  h3: /^###\s+(.+)$/,
  h4: /^####\s+(.+)$/,
  h5: /^#####\s+(.+)$/,
  h6: /^######\s+(.+)$/,
};

// Requirement ID patterns (common formats)
const REQUIREMENT_ID_PATTERNS = [
  /\[?(REQ|FR|NFR|BR|US|UC|SR|TR)-?\d+[\w.-]*\]?/gi,
  /\[?(REQUIREMENT|STORY|EPIC)-?\d+[\w.-]*\]?/gi,
  /\b(SHALL|MUST|SHOULD|MAY)\b/gi,
];

// Priority indicators
const PRIORITY_PATTERNS = {
  critical: /\b(critical|p0|priority\s*0|must\s*have|blocker)\b/gi,
  high: /\b(high|p1|priority\s*1|important|essential)\b/gi,
  medium: /\b(medium|p2|priority\s*2|normal|standard)\b/gi,
  low: /\b(low|p3|priority\s*3|nice\s*to\s*have|optional)\b/gi,
};

// Section type indicators - using string keys for flexibility
// These map to RequirementType, with some additional internal types
type SectionType = 'functional' | 'non-functional' | 'security' | 'api' | 'data' | 'ui' | 'testing' | 'deployment' | 'other';

// Map internal section types to RequirementType for BRD compatibility
function mapSectionTypeToRequirementType(sectionType: SectionType): 'functional' | 'non-functional' | 'security' | 'api' | 'other' {
  switch (sectionType) {
    case 'functional':
    case 'non-functional':
    case 'security':
    case 'api':
      return sectionType;
    case 'data':
    case 'ui':
    case 'testing':
    case 'deployment':
    case 'other':
    default:
      return 'other';
  }
}

const SECTION_INDICATORS: Record<SectionType, RegExp[]> = {
  functional: [
    /functional\s*requirement/i,
    /feature/i,
    /capability/i,
    /user\s*stor(y|ies)/i,
    /use\s*case/i,
  ],
  'non-functional': [
    /non-?functional/i,
    /performance/i,
    /scalability/i,
    /security/i,
    /reliability/i,
    /availability/i,
    /maintainability/i,
  ],
  security: [
    /security/i,
    /authentication/i,
    /authorization/i,
    /encryption/i,
    /access\s*control/i,
    /compliance/i,
  ],
  api: [
    /api/i,
    /endpoint/i,
    /interface/i,
    /integration/i,
    /rest/i,
    /graphql/i,
  ],
  data: [
    /data\s*model/i,
    /database/i,
    /schema/i,
    /entity/i,
    /storage/i,
  ],
  ui: [
    /ui|ux/i,
    /user\s*interface/i,
    /front-?end/i,
    /screen/i,
    /page/i,
    /component/i,
  ],
  testing: [
    /test/i,
    /qa/i,
    /quality/i,
    /acceptance/i,
    /validation/i,
  ],
  deployment: [
    /deploy/i,
    /infrastructure/i,
    /devops/i,
    /ci\/cd/i,
    /environment/i,
  ],
  other: [],
};

interface MarkdownLine {
  lineNumber: number;
  content: string;
  type: 'heading' | 'paragraph' | 'list-item' | 'code-block' | 'table' | 'empty' | 'other';
  headingLevel?: number;
}

/**
 * Parse markdown content into lines with type information
 */
function parseLines(content: string): MarkdownLine[] {
  const lines = content.split('\n');
  const result: MarkdownLine[] = [];
  let inCodeBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNumber = i + 1;

    // Handle code blocks
    if (line.trim().startsWith('```')) {
      inCodeBlock = !inCodeBlock;
      result.push({ lineNumber, content: line, type: 'code-block' });
      continue;
    }

    if (inCodeBlock) {
      result.push({ lineNumber, content: line, type: 'code-block' });
      continue;
    }

    // Check for headings
    for (const [level, pattern] of Object.entries(HEADING_PATTERNS)) {
      if (pattern.test(line)) {
        result.push({
          lineNumber,
          content: line,
          type: 'heading',
          headingLevel: parseInt(level.replace('h', ''), 10),
        });
        break;
      }
    }

    // If already added as heading, skip other checks
    if (result.length > 0 && result[result.length - 1].lineNumber === lineNumber) {
      continue;
    }

    // Check for list items
    if (/^\s*[-*+]\s/.test(line) || /^\s*\d+\.\s/.test(line)) {
      result.push({ lineNumber, content: line, type: 'list-item' });
      continue;
    }

    // Check for table rows
    if (line.includes('|')) {
      result.push({ lineNumber, content: line, type: 'table' });
      continue;
    }

    // Check for empty lines
    if (line.trim() === '') {
      result.push({ lineNumber, content: line, type: 'empty' });
      continue;
    }

    // Default to paragraph
    result.push({ lineNumber, content: line, type: 'paragraph' });
  }

  return result;
}

/**
 * Extract heading text from a line
 */
function extractHeadingText(line: string): string {
  return line.replace(/^#+\s+/, '').trim();
}

/**
 * Determine section type from heading text
 */
function determineSectionType(headingText: string): SectionType {
  for (const [type, patterns] of Object.entries(SECTION_INDICATORS)) {
    if (type === 'other') continue;
    for (const pattern of patterns) {
      if (pattern.test(headingText)) {
        return type as SectionType;
      }
    }
  }
  return 'other';
}

/**
 * Extract requirement IDs from text
 */
function extractRequirementIds(text: string): string[] {
  const ids: Set<string> = new Set();

  for (const pattern of REQUIREMENT_ID_PATTERNS.slice(0, 2)) {
    const matches = text.match(pattern);
    if (matches) {
      for (const match of matches) {
        ids.add(match.replace(/[[\]]/g, '').toUpperCase());
      }
    }
  }

  return Array.from(ids);
}

/**
 * Determine priority from text
 */
function determinePriority(text: string): ParsedRequirement['priority'] {
  for (const [priority, pattern] of Object.entries(PRIORITY_PATTERNS)) {
    if (pattern.test(text)) {
      return priority as ParsedRequirement['priority'];
    }
  }
  return 'medium';
}

/**
 * Check if text contains requirement keywords
 */
function containsRequirementKeywords(text: string): boolean {
  const keywords = /\b(shall|must|should|may|will|need|require|support|allow|enable|provide)\b/i;
  return keywords.test(text);
}

/**
 * Extract acceptance criteria from text
 */
function extractAcceptanceCriteria(content: string): string[] {
  const criteria: string[] = [];

  // Look for "Given/When/Then" patterns
  const gwtPattern = /(?:given|when|then)\s+.+/gi;
  const gwtMatches = content.match(gwtPattern);
  if (gwtMatches) {
    criteria.push(...gwtMatches.map(m => m.trim()));
  }

  // Look for numbered acceptance criteria
  const numberedPattern = /(?:AC|acceptance\s*criteria?)\s*#?\d+[:.]\s*(.+)/gi;
  let match;
  while ((match = numberedPattern.exec(content)) !== null) {
    criteria.push(match[1].trim());
  }

  // Look for bullet points under "Acceptance Criteria" heading
  const acSectionPattern = /acceptance\s*criteria:?\s*\n((?:\s*[-*]\s*.+\n?)+)/gi;
  while ((match = acSectionPattern.exec(content)) !== null) {
    const bullets = match[1].match(/[-*]\s*(.+)/g);
    if (bullets) {
      criteria.push(...bullets.map(b => b.replace(/^[-*]\s*/, '').trim()));
    }
  }

  return criteria.filter(c => c.length > 0);
}

/**
 * Parse markdown content into BRD sections
 */
export function parseMarkdownSections(content: string): BRDSection[] {
  const lines = parseLines(content);
  const sections: BRDSection[] = [];
  let currentSection: BRDSection | null = null;
  let sectionContent: string[] = [];

  for (const line of lines) {
    if (line.type === 'heading' && line.headingLevel && line.headingLevel <= 3) {
      // Save previous section
      if (currentSection) {
        currentSection.content = sectionContent.join('\n').trim();
        sections.push(currentSection);
      }

      // Start new section
      const headingText = extractHeadingText(line.content);
      currentSection = {
        id: `SEC-${line.lineNumber}`,
        title: headingText,
        content: '',
        type: mapSectionTypeToRequirementType(determineSectionType(headingText)),
        level: line.headingLevel,
        lineStart: line.lineNumber,
        lineEnd: line.lineNumber,
      };
      sectionContent = [];
    } else if (currentSection) {
      sectionContent.push(line.content);
      currentSection.lineEnd = line.lineNumber;
    }
  }

  // Don't forget the last section
  if (currentSection) {
    currentSection.content = sectionContent.join('\n').trim();
    sections.push(currentSection);
  }

  return sections;
}

/**
 * Extract requirements from markdown content
 */
export function extractMarkdownRequirements(content: string): ParsedRequirement[] {
  const requirements: ParsedRequirement[] = [];
  const sections = parseMarkdownSections(content);

  for (const section of sections) {
    // Extract requirement IDs from section
    const ids = extractRequirementIds(section.content);

    // If section has explicit requirement IDs
    if (ids.length > 0) {
      for (const id of ids) {
        // Find the specific line with this ID
        const escId = escapeRegExp(id);
        const idPattern = new RegExp(`.*${escId.replace(/[-]/g, '[-]?')}.*`, 'gi');
        const matches = section.content.match(idPattern);
        const description = matches ? matches[0] : section.title;

        requirements.push({
          id,
          title: section.title,
          description: description.replace(new RegExp(`\\[?${escId}\\]?:?\\s*`, 'gi'), '').trim(),
          type: section.type === 'security' ? 'security' :
                section.type === 'non-functional' ? 'non-functional' :
                section.type === 'api' ? 'api' : 'functional',
          priority: determinePriority(section.content),
          acceptanceCriteria: extractAcceptanceCriteria(section.content),
          source: {
            file: '',
            section: section.title,
            lineNumber: section.lineStart,
          },
        });
      }
    }
    // If section contains requirement keywords but no explicit IDs
    else if (containsRequirementKeywords(section.content)) {
      // Split content into potential requirements (by bullet points or paragraphs)
      const bullets = section.content.match(/[-*]\s+.+/g) || [];
      const reqBullets = bullets.filter(b => containsRequirementKeywords(b));

      if (reqBullets.length > 0) {
        for (let i = 0; i < reqBullets.length; i++) {
          const bullet = reqBullets[i].replace(/^[-*]\s+/, '').trim();
          requirements.push({
            id: `IMPL-${section.title.substring(0, 10).replace(/\s+/g, '-').toUpperCase()}-${i + 1}`,
            title: section.title,
            description: bullet,
            type: section.type === 'security' ? 'security' :
                  section.type === 'non-functional' ? 'non-functional' :
                  section.type === 'api' ? 'api' : 'functional',
            priority: determinePriority(bullet),
            acceptanceCriteria: [],
            source: {
              file: '',
              section: section.title,
              lineNumber: section.lineStart,
            },
          });
        }
      }
    }
  }

  return requirements;
}

/**
 * Parse a markdown file
 */
export async function parseMarkdownFile(filePath: string): Promise<{
  sections: BRDSection[];
  requirements: ParsedRequirement[];
}> {
  logger.info({ filePath }, 'Parsing markdown file');

  const startTime = Date.now();
  const content = await fs.readFile(filePath, 'utf-8');

  const sections = parseMarkdownSections(content);
  const requirements = extractMarkdownRequirements(content);

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
      durationMs: Date.now() - startTime,
    },
    'Markdown parsing completed'
  );

  return { sections, requirements };
}

/**
 * Parse markdown from string content
 */
export function parseMarkdownContent(content: string, sourceName: string = 'inline'): {
  sections: BRDSection[];
  requirements: ParsedRequirement[];
} {
  const sections = parseMarkdownSections(content);
  const requirements = extractMarkdownRequirements(content);

  // Update source file path
  for (const req of requirements) {
    if (req.source && typeof req.source === 'object') {
      req.source.file = sourceName;
    } else {
      req.source = { file: sourceName, section: '' };
    }
  }

  return { sections, requirements };
}

/**
 * Get sections by type
 */
export function getSectionsByType(sections: BRDSection[], type: SectionType): BRDSection[] {
  return sections.filter(s => s.type === type);
}

/**
 * Get requirements by type
 */
export function getRequirementsByType(
  requirements: ParsedRequirement[],
  type: ParsedRequirement['type']
): ParsedRequirement[] {
  return requirements.filter(r => r.type === type);
}

/**
 * Get security requirements
 */
export function getSecurityRequirements(requirements: ParsedRequirement[]): ParsedRequirement[] {
  return requirements.filter(r => r.type === 'security');
}

/**
 * Get high priority requirements
 */
export function getHighPriorityRequirements(requirements: ParsedRequirement[]): ParsedRequirement[] {
  return requirements.filter(r => r.priority === 'critical' || r.priority === 'high');
}
