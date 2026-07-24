/**
 * Test Generator Utilities
 * Helper functions for type handling and common operations
 */

import type { ParsedRequirement, RequirementSource, TestCaseCategory } from './types.js';

/**
 * Get the file from a requirement source
 * Handles both string and RequirementSource types
 */
export function getSourceFile(source: string | RequirementSource | undefined): string {
  if (!source) return '';
  if (typeof source === 'string') return source;
  return source.file || '';
}

/**
 * Get the section from a requirement source
 */
export function getSourceSection(source: string | RequirementSource | undefined): string {
  if (!source) return '';
  if (typeof source === 'string') return '';
  return source.section || '';
}

/**
 * Get the line number from a requirement source
 */
export function getSourceLineNumber(source: string | RequirementSource | undefined): number | undefined {
  if (!source) return undefined;
  if (typeof source === 'string') return undefined;
  return source.lineNumber;
}

/**
 * Safe access to acceptance criteria
 */
export function getAcceptanceCriteria(req: ParsedRequirement): string[] {
  return req.acceptanceCriteria || [];
}

/**
 * Safe access to keywords
 */
export function getKeywords(req: ParsedRequirement): string[] {
  return req.keywords || [];
}

/**
 * Get category as object, handling string case
 */
export function getCategoryObject(category: TestCaseCategory | string): TestCaseCategory {
  if (typeof category === 'string') {
    return { primary: category };
  }
  return category;
}

/**
 * Safe access to category OWASP
 */
export function getCategoryOwasp(category: TestCaseCategory | string): string | undefined {
  const cat = getCategoryObject(category);
  return cat.owasp;
}

/**
 * Safe access to category CWE
 */
export function getCategoryCwe(category: TestCaseCategory | string): string[] | undefined {
  const cat = getCategoryObject(category);
  return cat.cwe;
}

/**
 * Generate a unique ID with optional prefix
 */
export function generateId(prefix = ''): string {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomUUID().replace(/-/g, '').substring(0, 9);
  return prefix ? `${prefix}-${timestamp}-${random}` : `${timestamp}-${random}`;
}

/**
 * Normalize requirement type to allowed values
 */
export function normalizeRequirementType(
  type: string
): 'functional' | 'security' | 'performance' | 'compliance' | 'usability' | 'api' | 'other' | 'non-functional' {
  const normalized = type.toLowerCase();
  const validTypes = ['functional', 'security', 'performance', 'compliance', 'usability', 'api', 'other', 'non-functional'];
  if (validTypes.includes(normalized)) {
    return normalized as any;
  }
  return 'other';
}
