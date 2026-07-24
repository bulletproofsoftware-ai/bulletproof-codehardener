/**
 * Tool Registry
 * Centralized registry of all 37 security tools available in the platform
 * Implements: TM-001 to TM-003
 */

import { SecurityIntent } from './nlu/patterns.js';

/**
 * Security tool category
 */
export type ToolCategory =
  | 'sast'
  | 'dast'
  | 'sca'
  | 'secrets'
  | 'iac'
  | 'load'
  | 'api'
  | 'browser'
  | 'supply_chain'
  | 'policy'
  | 'reporting'
  | 'runtime'
  | 'chaos'
  | 'quality'
  | 'accessibility'
  | 'testing'
  | 'ai_security';

/**
 * Tool definition
 */
export interface ToolDefinition {
  /** Unique tool identifier */
  id: string;
  /** Display name */
  name: string;
  /** Tool category */
  category: ToolCategory;
  /** Description of what the tool does */
  description: string;
  /** Languages this tool supports (if language-specific) */
  languages?: string[];
  /** License type */
  license: string;
  /** Tool version */
  version: string;
  /** Whether the tool is enabled */
  enabled: boolean;
  /** Intents this tool can handle */
  intents: SecurityIntent[];
  /** Priority when multiple tools match (1-10, higher = preferred) */
  priority: number;
  /** Estimated execution time in seconds */
  estimatedTime: number;
  /** Resource requirements */
  resources: {
    cpu: 'low' | 'medium' | 'high';
    memory: 'low' | 'medium' | 'high';
    network: boolean;
  };
  /** Supported input types */
  inputTypes: ('file' | 'directory' | 'url' | 'image' | 'api')[];
  /** Output formats supported */
  outputFormats: string[];
}

/**
 * All registered security tools
 */
export const TOOL_REGISTRY: ToolDefinition[] = [
  // SAST Tools
  {
    id: 'bandit',
    name: 'Bandit',
    category: 'sast',
    description: 'Python security linter that finds common security issues',
    languages: ['python'],
    license: 'Apache-2.0',
    version: '1.7.7',
    enabled: true,
    intents: ['sast', 'code_quality', 'vulnerability_scan'],
    priority: 8,
    estimatedTime: 30,
    resources: { cpu: 'low', memory: 'low', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'sarif', 'text'],
  },
  {
    id: 'gosec',
    name: 'Gosec',
    category: 'sast',
    description: 'Go security checker that inspects source code for security problems',
    languages: ['go'],
    license: 'Apache-2.0',
    version: '2.18.2',
    enabled: true,
    intents: ['sast', 'code_quality', 'vulnerability_scan'],
    priority: 8,
    estimatedTime: 45,
    resources: { cpu: 'medium', memory: 'low', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'sarif', 'text'],
  },
  {
    id: 'eslint_security',
    name: 'ESLint Security',
    category: 'sast',
    description: 'JavaScript/TypeScript security rules for ESLint',
    languages: ['javascript', 'typescript'],
    license: 'MIT',
    version: '1.7.1',
    enabled: true,
    intents: ['sast', 'code_quality', 'vulnerability_scan'],
    priority: 8,
    estimatedTime: 20,
    resources: { cpu: 'low', memory: 'low', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'sarif', 'text'],
  },
  {
    id: 'pmd',
    name: 'PMD',
    category: 'sast',
    description: 'Multi-language static analyzer for code quality and security',
    languages: ['java', 'apex', 'javascript', 'xml'],
    license: 'BSD-4-Clause',
    version: '7.0.0',
    enabled: true,
    intents: ['sast', 'code_quality', 'vulnerability_scan'],
    priority: 7,
    estimatedTime: 60,
    resources: { cpu: 'medium', memory: 'medium', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'xml', 'text'],
  },
  {
    id: 'opengrep',
    name: 'Opengrep',
    category: 'sast',
    description: 'Lightweight multi-language SAST tool',
    languages: ['python', 'javascript', 'go', 'java', 'ruby', 'php'],
    license: 'LGPL-2.1',
    version: '1.0.0',
    enabled: true,
    intents: ['sast', 'code_quality', 'vulnerability_scan'],
    priority: 9,
    estimatedTime: 40,
    resources: { cpu: 'medium', memory: 'medium', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'sarif', 'text'],
  },

  // DAST Tools
  {
    id: 'zap',
    name: 'OWASP ZAP',
    category: 'dast',
    description: 'Dynamic application security testing proxy',
    license: 'Apache-2.0',
    version: '2.14.0',
    enabled: true,
    intents: ['dast', 'api_security', 'vulnerability_scan'],
    priority: 9,
    estimatedTime: 300,
    resources: { cpu: 'high', memory: 'high', network: true },
    inputTypes: ['url', 'api'],
    outputFormats: ['json', 'sarif', 'xml', 'html'],
  },
  {
    id: 'nuclei',
    name: 'Nuclei',
    category: 'dast',
    description: 'Fast vulnerability scanner based on templates',
    license: 'MIT',
    version: '3.1.10',
    enabled: true,
    intents: ['dast', 'vulnerability_scan'],
    priority: 8,
    estimatedTime: 120,
    resources: { cpu: 'medium', memory: 'medium', network: true },
    inputTypes: ['url'],
    outputFormats: ['json', 'sarif', 'text'],
  },

  // SCA/Container Tools
  {
    id: 'trivy',
    name: 'Trivy',
    category: 'sca',
    description: 'Comprehensive vulnerability scanner for containers, filesystems, and repos',
    license: 'Apache-2.0',
    version: '0.49.1',
    enabled: true,
    intents: ['sca', 'container_security', 'dependency_audit', 'vulnerability_scan'],
    priority: 10,
    estimatedTime: 60,
    resources: { cpu: 'medium', memory: 'medium', network: true },
    inputTypes: ['file', 'directory', 'image'],
    outputFormats: ['json', 'sarif', 'table', 'cyclonedx', 'spdx'],
  },
  {
    id: 'grype',
    name: 'Grype',
    category: 'sca',
    description: 'Vulnerability scanner for container images and filesystems',
    license: 'Apache-2.0',
    version: '0.74.7',
    enabled: true,
    intents: ['sca', 'container_security', 'dependency_audit'],
    priority: 8,
    estimatedTime: 45,
    resources: { cpu: 'medium', memory: 'medium', network: true },
    inputTypes: ['file', 'directory', 'image'],
    outputFormats: ['json', 'sarif', 'table', 'cyclonedx'],
  },

  // Secret Detection
  {
    id: 'gitleaks',
    name: 'Gitleaks',
    category: 'secrets',
    description: 'Secret detection in git repositories and files',
    license: 'MIT',
    version: '8.18.2',
    enabled: true,
    intents: ['secrets_detection', 'vulnerability_scan'],
    priority: 10,
    estimatedTime: 30,
    resources: { cpu: 'low', memory: 'low', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'sarif', 'csv'],
  },
  // detect-secrets removed: redundant with Gitleaks

  // IaC Security
  {
    id: 'checkov',
    name: 'Checkov',
    category: 'iac',
    description: 'Infrastructure as code scanner for misconfigurations',
    license: 'Apache-2.0',
    version: '3.2.8',
    enabled: true,
    intents: ['iac_security', 'compliance_check', 'vulnerability_scan'],
    priority: 9,
    estimatedTime: 90,
    resources: { cpu: 'medium', memory: 'medium', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'sarif', 'junitxml', 'cyclonedx'],
  },
  {
    id: 'opa',
    name: 'OPA',
    category: 'policy',
    description: 'Open Policy Agent for policy as code',
    license: 'Apache-2.0',
    version: '0.62.1',
    enabled: true,
    intents: ['compliance_check', 'iac_security'],
    priority: 8,
    estimatedTime: 15,
    resources: { cpu: 'low', memory: 'low', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'text'],
  },

  // Load Testing
  {
    id: 'locust',
    name: 'Locust',
    category: 'load',
    description: 'Python-based load testing framework',
    license: 'MIT',
    version: '2.24.0',
    enabled: true,
    intents: ['performance_test'],
    priority: 8,
    estimatedTime: 180,
    resources: { cpu: 'high', memory: 'medium', network: true },
    inputTypes: ['url', 'api'],
    outputFormats: ['json', 'html', 'csv'],
  },
  {
    id: 'artillery',
    name: 'Artillery',
    category: 'load',
    description: 'Modern load testing toolkit',
    license: 'MPL-2.0',
    version: '2.0.5',
    enabled: true,
    intents: ['performance_test'],
    priority: 8,
    estimatedTime: 180,
    resources: { cpu: 'high', memory: 'medium', network: true },
    inputTypes: ['url', 'api'],
    outputFormats: ['json', 'html'],
  },

  // API Testing
  {
    id: 'newman',
    name: 'Newman',
    category: 'api',
    description: 'Postman collection runner for API testing',
    license: 'Apache-2.0',
    version: '6.1.1',
    enabled: true,
    intents: ['api_security'],
    priority: 7,
    estimatedTime: 60,
    resources: { cpu: 'low', memory: 'low', network: true },
    inputTypes: ['api'],
    outputFormats: ['json', 'html', 'cli'],
  },
  {
    id: 'wiremock',
    name: 'WireMock',
    category: 'api',
    description: 'API mocking framework for testing',
    license: 'Apache-2.0',
    version: '3.4.2',
    enabled: false,
    intents: ['api_security'],
    priority: 6,
    estimatedTime: 30,
    resources: { cpu: 'low', memory: 'medium', network: true },
    inputTypes: ['api'],
    outputFormats: ['json'],
  },
  {
    id: 'pact',
    name: 'Pact',
    category: 'api',
    description: 'Contract testing framework',
    license: 'MIT',
    version: '2.0.4',
    enabled: true,
    intents: ['api_security'],
    priority: 7,
    estimatedTime: 45,
    resources: { cpu: 'low', memory: 'low', network: true },
    inputTypes: ['api'],
    outputFormats: ['json', 'html'],
  },
  {
    id: 'restler',
    name: 'RESTler',
    category: 'api',
    description: 'REST API fuzzing tool from Microsoft',
    license: 'MIT',
    version: '9.2.4',
    enabled: true,
    intents: ['api_security', 'dast'],
    priority: 8,
    estimatedTime: 120,
    resources: { cpu: 'medium', memory: 'medium', network: true },
    inputTypes: ['api'],
    outputFormats: ['json', 'text'],
  },

  // Browser/Visual Testing
  {
    id: 'playwright',
    name: 'Playwright',
    category: 'browser',
    description: 'Browser automation framework',
    license: 'Apache-2.0',
    version: '1.41.2',
    enabled: true,
    intents: ['visual_regression', 'accessibility_test'],
    priority: 8,
    estimatedTime: 120,
    resources: { cpu: 'high', memory: 'high', network: true },
    inputTypes: ['url'],
    outputFormats: ['json', 'html', 'png'],
  },
  {
    id: 'backstopjs',
    name: 'BackstopJS',
    category: 'browser',
    description: 'Visual regression testing',
    license: 'MIT',
    version: '6.3.23',
    enabled: true,
    intents: ['visual_regression'],
    priority: 9,
    estimatedTime: 90,
    resources: { cpu: 'medium', memory: 'high', network: true },
    inputTypes: ['url'],
    outputFormats: ['json', 'html', 'png'],
  },
  {
    id: 'pa11y',
    name: 'Pa11y',
    category: 'browser',
    description: 'Accessibility testing tool',
    license: 'MIT',
    version: '8.0.0',
    enabled: true,
    intents: ['accessibility_test'],
    priority: 9,
    estimatedTime: 60,
    resources: { cpu: 'medium', memory: 'medium', network: true },
    inputTypes: ['url'],
    outputFormats: ['json', 'html', 'csv'],
  },

  // Supply Chain
  {
    id: 'syft',
    name: 'Syft',
    category: 'supply_chain',
    description: 'SBOM generation tool',
    license: 'Apache-2.0',
    version: '1.0.1',
    enabled: true,
    intents: ['supply_chain', 'sca'],
    priority: 9,
    estimatedTime: 45,
    resources: { cpu: 'medium', memory: 'medium', network: false },
    inputTypes: ['file', 'directory', 'image'],
    outputFormats: ['json', 'cyclonedx', 'spdx', 'table'],
  },
  {
    id: 'in_toto',
    name: 'in-toto',
    category: 'supply_chain',
    description: 'Supply chain integrity framework',
    license: 'Apache-2.0',
    version: '2.1.0',
    enabled: false,
    intents: ['supply_chain'],
    priority: 7,
    estimatedTime: 30,
    resources: { cpu: 'low', memory: 'low', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json'],
  },
  {
    id: 'cosign',
    name: 'Cosign',
    category: 'supply_chain',
    description: 'Container signing and verification',
    license: 'Apache-2.0',
    version: '2.2.3',
    enabled: true,
    intents: ['supply_chain'],
    priority: 9,
    estimatedTime: 20,
    resources: { cpu: 'low', memory: 'low', network: true },
    inputTypes: ['image'],
    outputFormats: ['json', 'text'],
  },

  // Reporting
  {
    id: 'defectdojo',
    name: 'DefectDojo',
    category: 'reporting',
    description: 'Vulnerability management platform',
    license: 'BSD-3-Clause',
    version: '2.32.2',
    enabled: true,
    intents: ['vulnerability_scan'],
    priority: 5,
    estimatedTime: 10,
    resources: { cpu: 'low', memory: 'low', network: true },
    inputTypes: ['file'],
    outputFormats: ['json', 'html', 'pdf'],
  },
  {
    id: 'allure',
    name: 'Allure',
    category: 'reporting',
    description: 'Test report framework',
    license: 'Apache-2.0',
    version: '2.25.0',
    enabled: false,
    intents: ['vulnerability_scan', 'performance_test'],
    priority: 5,
    estimatedTime: 15,
    resources: { cpu: 'low', memory: 'low', network: false },
    inputTypes: ['file'],
    outputFormats: ['html', 'json'],
  },

  // Runtime Security
  {
    id: 'falco',
    name: 'Falco',
    category: 'runtime',
    description: 'Runtime security monitoring',
    license: 'Apache-2.0',
    version: '0.37.0',
    enabled: false,
    intents: ['container_security'],
    priority: 8,
    estimatedTime: 0, // Continuous
    resources: { cpu: 'medium', memory: 'medium', network: false },
    inputTypes: ['file'],
    outputFormats: ['json', 'text'],
  },

  // Chaos Engineering
  {
    id: 'toxiproxy',
    name: 'Toxiproxy',
    category: 'chaos',
    description: 'Chaos engineering proxy for testing',
    license: 'MIT',
    version: '2.7.0',
    enabled: true,
    intents: ['performance_test'],
    priority: 6,
    estimatedTime: 60,
    resources: { cpu: 'low', memory: 'low', network: true },
    inputTypes: ['url', 'api'],
    outputFormats: ['json'],
  },

  // Link Checking
  {
    id: 'lychee',
    name: 'Lychee',
    category: 'quality',
    description: 'Broken link detection for documentation and HTML',
    license: 'MIT/Apache-2.0',
    version: '0.15.0',
    enabled: true,
    intents: ['code_quality'],
    priority: 7,
    estimatedTime: 30,
    resources: { cpu: 'low', memory: 'low', network: true },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'text'],
  },

  // Accessibility
  {
    id: 'axe_core',
    name: 'axe-core',
    category: 'accessibility',
    description: 'WCAG 2.1 accessibility testing engine',
    license: 'MPL-2.0',
    version: '4.9.0',
    enabled: true,
    intents: ['accessibility_test'],
    priority: 9,
    estimatedTime: 60,
    resources: { cpu: 'medium', memory: 'medium', network: true },
    inputTypes: ['url'],
    outputFormats: ['json', 'html'],
  },

  // Testing - Coverage & Property-based
  {
    id: 'c8',
    name: 'c8',
    category: 'testing',
    description: 'Native V8 code coverage tool',
    license: 'ISC',
    version: '9.1.0',
    enabled: true,
    intents: ['code_quality'],
    priority: 7,
    estimatedTime: 45,
    resources: { cpu: 'medium', memory: 'medium', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'text', 'html'],
  },
  {
    id: 'fast_check',
    name: 'fast-check',
    category: 'testing',
    description: 'Property-based testing for JavaScript/TypeScript',
    languages: ['javascript', 'typescript'],
    license: 'MIT',
    version: '3.17.0',
    enabled: true,
    intents: ['code_quality'],
    priority: 7,
    estimatedTime: 60,
    resources: { cpu: 'medium', memory: 'medium', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'text'],
  },
  {
    id: 'hypothesis',
    name: 'Hypothesis',
    category: 'testing',
    description: 'Property-based testing for Python using stateful and data-driven strategies',
    languages: ['python'],
    license: 'MPL-2.0',
    version: '6.100.0',
    enabled: true,
    intents: ['code_quality'],
    priority: 6,
    estimatedTime: 90,
    resources: { cpu: 'medium', memory: 'high', network: false },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'text', 'junit'],
  },

  // DAST (new)
  {
    id: 'sqlmap',
    name: 'sqlmap',
    category: 'dast',
    description: 'Automated SQL injection detection and exploitation',
    license: 'GPL-2.0',
    version: '1.8.4',
    enabled: true,
    intents: ['dast', 'vulnerability_scan'],
    priority: 8,
    estimatedTime: 180,
    resources: { cpu: 'medium', memory: 'medium', network: true },
    inputTypes: ['url', 'api'],
    outputFormats: ['json', 'text'],
  },
  {
    id: 'dalfox',
    name: 'Dalfox',
    category: 'dast',
    description: 'XSS vulnerability scanning and parameter analysis',
    license: 'MIT',
    version: '2.9.3',
    enabled: true,
    intents: ['dast', 'vulnerability_scan'],
    priority: 8,
    estimatedTime: 120,
    resources: { cpu: 'medium', memory: 'medium', network: true },
    inputTypes: ['url'],
    outputFormats: ['json', 'text'],
  },
  {
    id: 'ffuf',
    name: 'ffuf',
    category: 'dast',
    description: 'Web endpoint fuzzing and content discovery',
    license: 'MIT',
    version: '2.1.0',
    enabled: true,
    intents: ['dast', 'vulnerability_scan'],
    priority: 7,
    estimatedTime: 120,
    resources: { cpu: 'medium', memory: 'low', network: true },
    inputTypes: ['url'],
    outputFormats: ['json', 'text', 'csv'],
  },

  // Supply Chain (new)
  {
    id: 'socket',
    name: 'Socket',
    category: 'supply_chain',
    description: 'Supply chain attack detection for npm, PyPI, and Go',
    license: 'MIT',
    version: '1.0.0',
    enabled: true,
    intents: ['supply_chain', 'sca'],
    priority: 8,
    estimatedTime: 30,
    resources: { cpu: 'low', memory: 'low', network: true },
    inputTypes: ['file', 'directory'],
    outputFormats: ['json', 'text'],
  },

  // AI Security
  {
    id: 'giskard',
    name: 'Giskard',
    category: 'ai_security',
    description: 'LLM vulnerability testing and red teaming',
    license: 'Apache-2.0',
    version: '2.14.0',
    enabled: true,
    intents: ['vulnerability_scan'],
    priority: 8,
    estimatedTime: 180,
    resources: { cpu: 'high', memory: 'high', network: true },
    inputTypes: ['api'],
    outputFormats: ['json', 'html'],
  },
];

// Build lookup maps for efficient access
const TOOL_BY_ID: Map<string, ToolDefinition> = new Map();
const TOOLS_BY_CATEGORY: Map<ToolCategory, ToolDefinition[]> = new Map();
const TOOLS_BY_INTENT: Map<SecurityIntent, ToolDefinition[]> = new Map();
const TOOLS_BY_LANGUAGE: Map<string, ToolDefinition[]> = new Map();

// Initialize lookup maps
function initializeLookups(): void {
  for (const tool of TOOL_REGISTRY) {
    // By ID
    TOOL_BY_ID.set(tool.id, tool);

    // By category
    const categoryTools = TOOLS_BY_CATEGORY.get(tool.category) || [];
    categoryTools.push(tool);
    TOOLS_BY_CATEGORY.set(tool.category, categoryTools);

    // By intent
    for (const intent of tool.intents) {
      const intentTools = TOOLS_BY_INTENT.get(intent) || [];
      intentTools.push(tool);
      TOOLS_BY_INTENT.set(intent, intentTools);
    }

    // By language
    if (tool.languages) {
      for (const lang of tool.languages) {
        const langTools = TOOLS_BY_LANGUAGE.get(lang) || [];
        langTools.push(tool);
        TOOLS_BY_LANGUAGE.set(lang, langTools);
      }
    }
  }
}

initializeLookups();

/**
 * Get a tool by its ID
 */
export function getToolById(id: string): ToolDefinition | undefined {
  return TOOL_BY_ID.get(id);
}

/**
 * Get all tools in a category
 */
export function getToolsByCategory(category: ToolCategory): ToolDefinition[] {
  return TOOLS_BY_CATEGORY.get(category) || [];
}

/**
 * Get tools that can handle a specific intent
 */
export function getToolsByIntent(intent: SecurityIntent): ToolDefinition[] {
  return TOOLS_BY_INTENT.get(intent) || [];
}

/**
 * Get tools that support a specific language
 */
export function getToolsByLanguage(language: string): ToolDefinition[] {
  return TOOLS_BY_LANGUAGE.get(language.toLowerCase()) || [];
}

/**
 * Get all enabled tools
 */
export function getEnabledTools(): ToolDefinition[] {
  return TOOL_REGISTRY.filter(t => t.enabled);
}

/**
 * Get all tool IDs
 */
export function getAllToolIds(): string[] {
  return TOOL_REGISTRY.map(t => t.id);
}

/**
 * Get all categories
 */
export function getAllCategories(): ToolCategory[] {
  return Array.from(TOOLS_BY_CATEGORY.keys());
}

/**
 * Check if a tool ID is valid
 */
export function isValidToolId(id: string): boolean {
  return TOOL_BY_ID.has(id);
}

/**
 * Get tools sorted by priority for a given intent
 */
export function getToolsByPriority(intent: SecurityIntent): ToolDefinition[] {
  const tools = getToolsByIntent(intent);
  return tools.sort((a, b) => b.priority - a.priority);
}

/**
 * Get language-agnostic tools (tools that work on any language)
 */
export function getLanguageAgnosticTools(): ToolDefinition[] {
  return TOOL_REGISTRY.filter(t => !t.languages || t.languages.length === 0);
}
