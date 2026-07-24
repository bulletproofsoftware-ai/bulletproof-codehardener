/**
 * Requirement Extractor
 * Extracts and normalizes requirements from parsed BRD content
 */

import { createLogger } from '../../../utils/logger.js';
import type { BRDSection, ParsedRequirement } from '../types.js';

const logger = createLogger('requirement-extractor');

// Type for requirement types used in this module
type ReqType = 'functional' | 'non-functional' | 'security' | 'api' | 'performance' | 'compliance' | 'usability' | 'other';

// Keywords that indicate requirement type
const TYPE_KEYWORDS: Record<ReqType, string[]> = {
  functional: [
    'feature', 'capability', 'function', 'user story', 'use case',
    'shall', 'must', 'will', 'action', 'behavior', 'workflow',
  ],
  'non-functional': [
    'performance', 'scalability', 'reliability', 'availability',
    'response time', 'latency', 'throughput', 'capacity', 'load',
    'maintainability', 'usability', 'accessibility',
  ],
  security: [
    'security', 'authentication', 'authorization', 'encryption',
    'access control', 'audit', 'compliance', 'gdpr', 'hipaa', 'pci',
    'vulnerability', 'threat', 'risk', 'credential', 'permission',
  ],
  api: [
    'api', 'endpoint', 'rest', 'graphql', 'http', 'request', 'response',
    'integration', 'interface', 'webhook', 'payload', 'schema',
  ],
  performance: [],
  compliance: [],
  usability: [],
  other: [],
};

// Keywords that indicate priority
const PRIORITY_KEYWORDS: Record<ParsedRequirement['priority'], string[]> = {
  critical: ['critical', 'blocker', 'p0', 'must have', 'mandatory', 'essential', 'urgent'],
  high: ['high', 'p1', 'important', 'required', 'necessary'],
  medium: ['medium', 'p2', 'normal', 'standard', 'should have'],
  low: ['low', 'p3', 'nice to have', 'optional', 'future', 'could have'],
};

// Patterns for extracting structured information
const PATTERNS = {
  // Given-When-Then format
  givenWhenThen: /given\s+(.+?)\s+when\s+(.+?)\s+then\s+(.+?)(?:\.|$)/gi,

  // User story format: As a [role], I want [feature], so that [benefit]
  userStory: /as\s+(?:a|an)\s+(.+?),?\s+i\s+want\s+(.+?),?\s+so\s+that\s+(.+?)(?:\.|$)/gi,

  // Shall/Must/Should statements
  shallStatement: /(?:the\s+)?(?:system|application|user|admin)\s+(shall|must|should|may)\s+(.+?)(?:\.|$)/gi,

  // Numbered requirements (1.2.3 The system shall...)
  numberedReq: /^(\d+(?:\.\d+)*)\s*[.:\s]\s*(.+)/gm,

  // Acceptance criteria (AC1: ...)
  acceptanceCriteria: /(?:ac|acceptance\s*criteria?)\s*#?(\d+)[:.]\s*(.+)/gi,

  // Test scenario
  testScenario: /(?:test|scenario|verify|validate)[:\s]+(.+)/gi,
};

/**
 * Infer requirement type from text
 */
function inferType(text: string): ReqType {
  const lowerText = text.toLowerCase();

  for (const [type, keywords] of Object.entries(TYPE_KEYWORDS)) {
    for (const keyword of keywords) {
      if (lowerText.includes(keyword)) {
        return type as ReqType;
      }
    }
  }

  return 'functional'; // Default
}

/**
 * Infer priority from text
 */
function inferPriority(text: string): ParsedRequirement['priority'] {
  const lowerText = text.toLowerCase();

  for (const [priority, keywords] of Object.entries(PRIORITY_KEYWORDS)) {
    for (const keyword of keywords) {
      if (lowerText.includes(keyword)) {
        return priority as ParsedRequirement['priority'];
      }
    }
  }

  return 'medium'; // Default
}

/**
 * Extract acceptance criteria from requirement text
 */
function extractAcceptanceCriteria(text: string): string[] {
  const criteria: string[] = [];

  // Given-When-Then
  const gwtMatches = text.matchAll(PATTERNS.givenWhenThen);
  for (const match of gwtMatches) {
    criteria.push(`Given ${match[1].trim()}, When ${match[2].trim()}, Then ${match[3].trim()}`);
  }

  // Explicit AC
  const acMatches = text.matchAll(PATTERNS.acceptanceCriteria);
  for (const match of acMatches) {
    criteria.push(match[2].trim());
  }

  // Bullet points that look like criteria
  const bulletMatches = text.match(/[-*]\s+(?:verify|ensure|check|confirm|validate)\s+.+/gi);
  if (bulletMatches) {
    criteria.push(...bulletMatches.map(m => m.replace(/^[-*]\s+/, '').trim()));
  }

  return [...new Set(criteria)]; // Deduplicate
}

/**
 * Parse user story format
 */
function parseUserStory(text: string): {
  role?: string;
  feature?: string;
  benefit?: string;
} | null {
  const match = PATTERNS.userStory.exec(text);
  PATTERNS.userStory.lastIndex = 0; // Reset regex

  if (match) {
    return {
      role: match[1].trim(),
      feature: match[2].trim(),
      benefit: match[3].trim(),
    };
  }

  return null;
}

/**
 * Extract dependencies from requirement text
 */
function extractDependencies(text: string, allRequirements: ParsedRequirement[]): string[] {
  const dependencies: string[] = [];

  // Look for explicit dependency mentions
  const depPattern = /(?:depends\s+on|requires|after|following|prerequisite)[:\s]+([A-Z]+-\d+[\w-]*)/gi;
  const matches = text.matchAll(depPattern);

  for (const match of matches) {
    const depId = match[1].toUpperCase();
    if (allRequirements.some(r => r.id === depId)) {
      dependencies.push(depId);
    }
  }

  // Look for references to other requirements
  const refPattern = /(?:see|refer\s+to|as\s+(?:defined|described)\s+in)[:\s]+([A-Z]+-\d+[\w-]*)/gi;
  const refMatches = text.matchAll(refPattern);

  for (const match of refMatches) {
    const refId = match[1].toUpperCase();
    if (allRequirements.some(r => r.id === refId) && !dependencies.includes(refId)) {
      dependencies.push(refId);
    }
  }

  return dependencies;
}

/**
 * Normalize requirement ID
 */
function normalizeId(id: string): string {
  return id.toUpperCase().replace(/[[\]()]/g, '').trim();
}

/**
 * Generate requirement ID if not present
 */
function generateId(sectionTitle: string, index: number): string {
  const prefix = sectionTitle
    .substring(0, 10)
    .replace(/[^a-zA-Z0-9]/g, '')
    .toUpperCase();
  return `${prefix || 'REQ'}-${String(index + 1).padStart(3, '0')}`;
}

/**
 * Process and enrich a single requirement
 */
function processRequirement(
  req: ParsedRequirement,
  allRequirements: ParsedRequirement[]
): ParsedRequirement {
  // Normalize ID
  req.id = normalizeId(req.id);

  // Infer type if not set or default
  if (req.type === 'functional') {
    req.type = inferType(req.description);
  }

  // Infer priority if not set or default
  if (req.priority === 'medium') {
    req.priority = inferPriority(req.description);
  }

  // Extract acceptance criteria if empty
  if (!req.acceptanceCriteria || req.acceptanceCriteria.length === 0) {
    req.acceptanceCriteria = extractAcceptanceCriteria(req.description);
  }

  // Parse user story format
  const userStory = parseUserStory(req.description);
  if (userStory) {
    req.userStory = userStory;
  }

  // Extract dependencies
  req.dependencies = extractDependencies(req.description, allRequirements);

  return req;
}

/**
 * Extract additional requirements from sections that might have been missed
 */
function extractAdditionalRequirements(sections: BRDSection[]): ParsedRequirement[] {
  const requirements: ParsedRequirement[] = [];
  let globalIndex = 0;

  for (const section of sections) {
    // Skip sections that are likely not requirements
    if (!section.type || ['other', 'ui'].includes(section.type)) {
      continue;
    }

    // Look for shall/must/should statements
    const shallMatches = section.content.matchAll(PATTERNS.shallStatement);
    for (const match of shallMatches) {
      globalIndex++;
      requirements.push({
        id: generateId(section.title, globalIndex),
        title: section.title,
        description: `${match[0].trim()}`,
        type: inferType(match[2]),
        priority: match[1].toLowerCase() === 'must' || match[1].toLowerCase() === 'shall'
          ? 'high'
          : match[1].toLowerCase() === 'may'
            ? 'low'
            : 'medium',
        acceptanceCriteria: [],
        source: {
          file: '',
          section: section.title,
          lineNumber: section.lineStart,
        },
      });
    }

    // Look for user stories
    const userStoryMatches = section.content.matchAll(PATTERNS.userStory);
    for (const match of userStoryMatches) {
      globalIndex++;
      requirements.push({
        id: generateId(section.title, globalIndex),
        title: `User Story: ${match[2].substring(0, 50)}`,
        description: match[0].trim(),
        type: 'functional',
        priority: 'medium',
        acceptanceCriteria: [],
        userStory: {
          role: match[1].trim(),
          feature: match[2].trim(),
          benefit: match[3].trim(),
        },
        source: {
          file: '',
          section: section.title,
          lineNumber: section.lineStart,
        },
      });
    }
  }

  return requirements;
}

/**
 * Categorize requirements by type
 */
export function categorizeRequirements(requirements: ParsedRequirement[]): {
  functional: ParsedRequirement[];
  nonFunctional: ParsedRequirement[];
  security: ParsedRequirement[];
  api: ParsedRequirement[];
} {
  return {
    functional: requirements.filter(r => r.type === 'functional'),
    nonFunctional: requirements.filter(r => r.type === 'non-functional'),
    security: requirements.filter(r => r.type === 'security'),
    api: requirements.filter(r => r.type === 'api'),
  };
}

/**
 * Get requirements summary
 */
export function getRequirementsSummary(requirements: ParsedRequirement[]): {
  total: number;
  byType: Record<string, number>;
  byPriority: Record<string, number>;
  withAcceptanceCriteria: number;
  withDependencies: number;
} {
  const byType: Record<string, number> = {};
  const byPriority: Record<string, number> = {};
  let withAcceptanceCriteria = 0;
  let withDependencies = 0;

  for (const req of requirements) {
    byType[req.type] = (byType[req.type] || 0) + 1;
    byPriority[req.priority] = (byPriority[req.priority] || 0) + 1;

    if (req.acceptanceCriteria && req.acceptanceCriteria.length > 0) {
      withAcceptanceCriteria++;
    }
    if (req.dependencies && req.dependencies.length > 0) {
      withDependencies++;
    }
  }

  return {
    total: requirements.length,
    byType,
    byPriority,
    withAcceptanceCriteria,
    withDependencies,
  };
}

/**
 * Validate requirements for completeness
 */
export function validateRequirements(requirements: ParsedRequirement[]): Array<{
  requirementId: string;
  issues: string[];
}> {
  const validationResults: Array<{ requirementId: string; issues: string[] }> = [];

  for (const req of requirements) {
    const issues: string[] = [];

    // Check for missing acceptance criteria
    if (!req.acceptanceCriteria || req.acceptanceCriteria.length === 0) {
      issues.push('Missing acceptance criteria');
    }

    // Check for vague descriptions
    if (req.description.length < 20) {
      issues.push('Description may be too brief');
    }

    // Check for ambiguous language
    const ambiguousWords = ['some', 'few', 'many', 'etc', 'appropriate', 'reasonable', 'adequate'];
    for (const word of ambiguousWords) {
      if (req.description.toLowerCase().includes(word)) {
        issues.push(`Contains ambiguous term: "${word}"`);
        break;
      }
    }

    // Check for measurability in non-functional requirements
    if (req.type === 'non-functional') {
      const hasMetric = /\d+\s*(ms|seconds?|%|mb|gb|tps|rps)/i.test(req.description);
      if (!hasMetric) {
        issues.push('Non-functional requirement lacks measurable metric');
      }
    }

    if (issues.length > 0) {
      validationResults.push({ requirementId: req.id, issues });
    }
  }

  return validationResults;
}

/**
 * Main extraction function
 * Processes sections and existing requirements to produce final requirement list
 */
export function extractRequirements(
  sections: BRDSection[],
  initialRequirements: ParsedRequirement[],
  sourceFile: string
): ParsedRequirement[] {
  logger.info(
    { sectionCount: sections.length, initialRequirementCount: initialRequirements.length },
    'Extracting requirements'
  );

  const startTime = Date.now();

  // Start with initial requirements
  let requirements = [...initialRequirements];

  // Extract additional requirements from sections
  const additionalRequirements = extractAdditionalRequirements(sections);

  // Merge, avoiding duplicates (by similar description)
  for (const newReq of additionalRequirements) {
    const isDuplicate = requirements.some(existing => {
      const similarity = calculateSimilarity(existing.description, newReq.description);
      return similarity > 0.8;
    });

    if (!isDuplicate) {
      requirements.push(newReq);
    }
  }

  // Process and enrich all requirements
  requirements = requirements.map(req => processRequirement(req, requirements));

  // Update source file
  for (const req of requirements) {
    if (!req.source) {
      req.source = { file: sourceFile, section: '' };
    } else if (typeof req.source === 'object' && !req.source.file) {
      req.source.file = sourceFile;
    }
  }

  // Sort by priority and ID
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  requirements.sort((a, b) => {
    const prioCompare = priorityOrder[a.priority] - priorityOrder[b.priority];
    if (prioCompare !== 0) return prioCompare;
    return a.id.localeCompare(b.id);
  });

  logger.info(
    {
      totalRequirements: requirements.length,
      byType: getRequirementsSummary(requirements).byType,
      durationMs: Date.now() - startTime,
    },
    'Requirement extraction completed'
  );

  return requirements;
}

/**
 * Calculate similarity between two strings (simple Jaccard similarity)
 */
function calculateSimilarity(str1: string, str2: string): number {
  const words1 = new Set(str1.toLowerCase().split(/\s+/));
  const words2 = new Set(str2.toLowerCase().split(/\s+/));

  const intersection = new Set([...words1].filter(x => words2.has(x)));
  const union = new Set([...words1, ...words2]);

  return intersection.size / union.size;
}

/**
 * Find related requirements
 */
export function findRelatedRequirements(
  requirement: ParsedRequirement,
  allRequirements: ParsedRequirement[],
  threshold: number = 0.3
): ParsedRequirement[] {
  return allRequirements
    .filter(r => r.id !== requirement.id)
    .map(r => ({
      requirement: r,
      similarity: calculateSimilarity(requirement.description, r.description),
    }))
    .filter(({ similarity }) => similarity >= threshold)
    .sort((a, b) => b.similarity - a.similarity)
    .map(({ requirement }) => requirement)
    .slice(0, 5);
}
