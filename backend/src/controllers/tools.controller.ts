import { Request, Response } from 'express';
import { z } from 'zod';
import { apiSuccess, apiError } from '../utils/apiResponse.js';

// Tool definitions - all 37 integrated security tools
const TOOLS: Record<string, {
  name: string;
  category: string;
  description: string;
  languages?: string[];
  license: string;
  version: string;
  enabled: boolean;
}> = {
  // SAST Tools
  bandit: {
    name: 'Bandit',
    category: 'sast',
    description: 'Python security linter',
    languages: ['python'],
    license: 'Apache-2.0',
    version: '1.7.7',
    enabled: true,
  },
  gosec: {
    name: 'Gosec',
    category: 'sast',
    description: 'Go security checker',
    languages: ['go'],
    license: 'Apache-2.0',
    version: '2.18.2',
    enabled: true,
  },
  eslint_security: {
    name: 'ESLint Security',
    category: 'sast',
    description: 'JavaScript/TypeScript security rules',
    languages: ['javascript', 'typescript'],
    license: 'MIT',
    version: '1.7.1',
    enabled: true,
  },
  pmd: {
    name: 'PMD',
    category: 'sast',
    description: 'Multi-language static analyzer',
    languages: ['java', 'apex', 'javascript', 'xml'],
    license: 'BSD-4-Clause',
    version: '7.0.0',
    enabled: true,
  },
  opengrep: {
    name: 'Opengrep',
    category: 'sast',
    description: 'Lightweight multi-language SAST',
    languages: ['python', 'javascript', 'go', 'java', 'ruby', 'php'],
    license: 'LGPL-2.1',
    version: '1.0.0',
    enabled: true,
  },

  // DAST Tools
  zap: {
    name: 'OWASP ZAP',
    category: 'dast',
    description: 'Dynamic application security testing',
    license: 'Apache-2.0',
    version: '2.14.0',
    enabled: true,
  },
  nuclei: {
    name: 'Nuclei',
    category: 'dast',
    description: 'Fast vulnerability scanner',
    license: 'MIT',
    version: '3.1.10',
    enabled: true,
  },

  // SCA/Container Tools
  trivy: {
    name: 'Trivy',
    category: 'sca',
    description: 'Comprehensive vulnerability scanner',
    license: 'Apache-2.0',
    version: '0.49.1',
    enabled: true,
  },
  grype: {
    name: 'Grype',
    category: 'sca',
    description: 'Vulnerability scanner for containers',
    license: 'Apache-2.0',
    version: '0.74.7',
    enabled: true,
  },

  // Secret Detection
  gitleaks: {
    name: 'Gitleaks',
    category: 'secrets',
    description: 'Secret detection in git repos',
    license: 'MIT',
    version: '8.18.2',
    enabled: true,
  },
  // detect-secrets removed: redundant with Gitleaks

  // IaC Security
  checkov: {
    name: 'Checkov',
    category: 'iac',
    description: 'Infrastructure as code scanner',
    license: 'Apache-2.0',
    version: '3.2.8',
    enabled: true,
  },

  // Load Testing
  locust: {
    name: 'Locust',
    category: 'load',
    description: 'Python load testing framework',
    license: 'MIT',
    version: '2.24.0',
    enabled: true,
  },
  gatling: {
    name: 'Gatling',
    category: 'load',
    description: 'High-performance load testing',
    license: 'Apache-2.0',
    version: '3.10.3',
    enabled: false,
  },
  artillery: {
    name: 'Artillery',
    category: 'load',
    description: 'Modern load testing toolkit',
    license: 'MPL-2.0',
    version: '2.0.5',
    enabled: true,
  },

  // API Testing
  newman: {
    name: 'Newman',
    category: 'api',
    description: 'Postman collection runner',
    license: 'Apache-2.0',
    version: '6.1.1',
    enabled: true,
  },
  wiremock: {
    name: 'WireMock',
    category: 'api',
    description: 'API mocking framework',
    license: 'Apache-2.0',
    version: '3.4.2',
    enabled: false,
  },
  pact: {
    name: 'Pact',
    category: 'api',
    description: 'Contract testing framework',
    license: 'MIT',
    version: '2.0.4',
    enabled: true,
  },
  restler: {
    name: 'RESTler',
    category: 'api',
    description: 'REST API fuzzing tool',
    license: 'MIT',
    version: '9.2.4',
    enabled: true,
  },

  // Browser/Visual Testing
  playwright: {
    name: 'Playwright',
    category: 'browser',
    description: 'Browser automation framework',
    license: 'Apache-2.0',
    version: '1.41.2',
    enabled: true,
  },
  backstopjs: {
    name: 'BackstopJS',
    category: 'browser',
    description: 'Visual regression testing',
    license: 'MIT',
    version: '6.3.23',
    enabled: true,
  },
  pa11y: {
    name: 'Pa11y',
    category: 'browser',
    description: 'Accessibility testing',
    license: 'MIT',
    version: '8.0.0',
    enabled: true,
  },

  // Supply Chain
  syft: {
    name: 'Syft',
    category: 'supply_chain',
    description: 'SBOM generation tool',
    license: 'Apache-2.0',
    version: '1.0.1',
    enabled: true,
  },
  in_toto: {
    name: 'in-toto',
    category: 'supply_chain',
    description: 'Supply chain integrity framework',
    license: 'Apache-2.0',
    version: '2.1.0',
    enabled: false,
  },
  cosign: {
    name: 'Cosign',
    category: 'supply_chain',
    description: 'Container signing and verification',
    license: 'Apache-2.0',
    version: '2.2.3',
    enabled: true,
  },

  // Policy/Reporting
  opa: {
    name: 'OPA',
    category: 'policy',
    description: 'Open Policy Agent',
    license: 'Apache-2.0',
    version: '0.62.1',
    enabled: true,
  },
  defectdojo: {
    name: 'DefectDojo',
    category: 'reporting',
    description: 'Vulnerability management platform',
    license: 'BSD-3-Clause',
    version: '2.32.2',
    enabled: true,
  },
  allure: {
    name: 'Allure',
    category: 'reporting',
    description: 'Test report framework',
    license: 'Apache-2.0',
    version: '2.25.0',
    enabled: false,
  },

  // Link Checking
  lychee: {
    name: 'Lychee',
    category: 'quality',
    description: 'Broken link detection',
    license: 'MIT/Apache-2.0',
    version: '0.15.0',
    enabled: true,
  },

  // Accessibility
  axe_core: {
    name: 'axe-core',
    category: 'accessibility',
    description: 'WCAG 2.1 accessibility testing',
    license: 'MPL-2.0',
    version: '4.9.0',
    enabled: true,
  },

  // Testing
  c8: {
    name: 'c8',
    category: 'testing',
    description: 'Native V8 code coverage',
    license: 'ISC',
    version: '9.1.0',
    enabled: true,
  },
  fast_check: {
    name: 'fast-check',
    category: 'testing',
    description: 'Property-based testing for JS/TS',
    license: 'MIT',
    version: '3.17.0',
    enabled: true,
  },
  hypothesis: {
    name: 'Hypothesis',
    category: 'testing',
    description: 'Property-based testing for Python',
    license: 'MPL-2.0',
    version: '6.100.0',
    enabled: true,
  },

  // DAST (new)
  sqlmap: {
    name: 'sqlmap',
    category: 'dast',
    description: 'SQL injection testing',
    license: 'GPL-2.0',
    version: '1.8.4',
    enabled: true,
  },
  dalfox: {
    name: 'Dalfox',
    category: 'dast',
    description: 'XSS vulnerability scanning',
    license: 'MIT',
    version: '2.9.3',
    enabled: true,
  },
  ffuf: {
    name: 'ffuf',
    category: 'dast',
    description: 'Web endpoint fuzzing',
    license: 'MIT',
    version: '2.1.0',
    enabled: true,
  },

  // Supply Chain (new)
  socket: {
    name: 'Socket',
    category: 'supply_chain',
    description: 'Supply chain attack detection',
    license: 'MIT',
    version: '1.0.0',
    enabled: true,
  },

  // AI Security
  giskard: {
    name: 'Giskard',
    category: 'ai_security',
    description: 'LLM vulnerability testing',
    license: 'Apache-2.0',
    version: '2.14.0',
    enabled: true,
  },
};

// Scan profiles
const SCAN_PROFILES: Record<string, {
  name: string;
  description: string;
  tools: string[];
}> = {
  quick: {
    name: 'Quick Scan',
    description: 'Fast security check with essential tools',
    tools: ['trivy', 'gitleaks', 'eslint_security', 'bandit'],
  },
  standard: {
    name: 'Standard Scan',
    description: 'Balanced security analysis',
    tools: ['trivy', 'grype', 'gitleaks', 'eslint_security', 'bandit', 'gosec', 'checkov'],
  },
  comprehensive: {
    name: 'Comprehensive Scan',
    description: 'Full security assessment',
    tools: Object.keys(TOOLS).filter(t =>
      ['sast', 'sca', 'secrets', 'iac'].includes(TOOLS[t].category)
    ),
  },
  api: {
    name: 'API Security',
    description: 'API-focused security testing',
    tools: ['zap', 'nuclei', 'newman', 'restler', 'pact'],
  },
  supply_chain: {
    name: 'Supply Chain',
    description: 'Supply chain security analysis',
    tools: ['syft', 'trivy', 'grype', 'cosign', 'socket', 'gitleaks'],
  },
  compliance: {
    name: 'Compliance',
    description: 'Compliance-focused scanning',
    tools: ['checkov', 'trivy', 'syft', 'opa'],
  },
  pre_commit: {
    name: 'Pre-Commit',
    description: 'Fast checks suitable for pre-commit hooks',
    tools: ['eslint_security', 'gitleaks', 'bandit', 'gosec'],
  },
  usability: {
    name: 'Usability',
    description: 'Accessibility and usability testing',
    tools: ['axe_core', 'pa11y', 'lychee', 'backstopjs'],
  },
  unit_test: {
    name: 'Unit Test',
    description: 'Test quality and coverage analysis',
    tools: ['c8', 'fast_check', 'hypothesis'],
  },
};

// List all tools
export async function listTools(req: Request, res: Response) {
  const querySchema = z.object({
    category: z.string().min(1).optional(),
    language: z.string().min(1).optional(),
  }).passthrough();
  const { category, language } = querySchema.parse(req.query);

  let tools = Object.entries(TOOLS).map(([id, tool]) => ({
    id,
    ...tool,
  }));

  if (category) {
    tools = tools.filter(t => t.category === category);
  }

  if (language) {
    tools = tools.filter(t => !t.languages || t.languages.includes(language));
  }

  return apiSuccess(res, tools);
}

// Get specific tool
export async function getTool(req: Request, res: Response) {
  const { toolId } = z.object({ toolId: z.string().min(1) }).parse(req.params);

  const tool = TOOLS[toolId];
  if (!tool) {
    return apiError(res, 'Tool not found', 404);
  }

  return apiSuccess(res, {
    id: toolId,
    ...tool,
  });
}

// List scan profiles
export async function listProfiles(_req: Request, res: Response) {
  const profiles = Object.entries(SCAN_PROFILES).map(([id, profile]) => ({
    id,
    name: profile.name,
    description: profile.description,
    toolCount: profile.tools.length,
    tools: profile.tools,
  }));

  return apiSuccess(res, profiles);
}

// Get specific profile
export async function getProfile(req: Request, res: Response) {
  const { profileId } = z.object({ profileId: z.string().min(1) }).parse(req.params);

  const profile = SCAN_PROFILES[profileId];
  if (!profile) {
    return apiError(res, 'Profile not found', 404);
  }

  const tools = profile.tools.map(toolId => ({
    id: toolId,
    ...TOOLS[toolId],
  }));

  return apiSuccess(res, {
    id: profileId,
    name: profile.name,
    description: profile.description,
    tools,
  });
}

// Get tools for a language
export async function getToolsForLanguage(req: Request, res: Response) {
  const { language } = z.object({ language: z.string().min(1) }).parse(req.params);

  const tools = Object.entries(TOOLS)
    .filter(([_, tool]) => !tool.languages || tool.languages.includes(language))
    .map(([id, tool]) => ({
      id,
      ...tool,
    }));

  if (tools.length === 0) {
    return apiSuccess(res, {
      language,
      message: `No specific tools for ${language}, but generic tools are available`,
      tools: Object.entries(TOOLS)
        .filter(([_, tool]) => !tool.languages)
        .map(([id, tool]) => ({ id, ...tool })),
    });
  }

  return apiSuccess(res, {
    language,
    tools,
  });
}

// Get tool categories
export async function getCategories(_req: Request, res: Response) {
  const categories = [
    { id: 'sast', name: 'SAST', description: 'Static Application Security Testing' },
    { id: 'dast', name: 'DAST', description: 'Dynamic Application Security Testing' },
    { id: 'sca', name: 'SCA', description: 'Software Composition Analysis' },
    { id: 'secrets', name: 'Secrets', description: 'Secret Detection' },
    { id: 'iac', name: 'IaC', description: 'Infrastructure as Code Security' },
    { id: 'load', name: 'Load Testing', description: 'Performance and Load Testing' },
    { id: 'api', name: 'API Testing', description: 'API Security Testing' },
    { id: 'browser', name: 'Browser Testing', description: 'Browser Automation and Visual Testing' },
    { id: 'supply_chain', name: 'Supply Chain', description: 'Supply Chain Security' },
    { id: 'policy', name: 'Policy', description: 'Policy as Code' },
    { id: 'reporting', name: 'Reporting', description: 'Security Reporting and Management' },
    { id: 'quality', name: 'Quality', description: 'Code and Documentation Quality' },
    { id: 'accessibility', name: 'Accessibility', description: 'Accessibility Testing' },
    { id: 'testing', name: 'Testing', description: 'Test Quality and Coverage' },
    { id: 'ai_security', name: 'AI Security', description: 'AI/LLM Security Testing' },
  ];

  return apiSuccess(res, categories);
}

// Check tool availability/health
export async function checkToolHealth(req: Request, res: Response) {
  const { toolId } = z.object({ toolId: z.string().min(1) }).parse(req.params);

  const tool = TOOLS[toolId];
  if (!tool) {
    return apiError(res, 'Tool not found', 404);
  }

  // In production, this would actually check if the tool container/service is healthy
  // For now, return mock status
  return apiSuccess(res, {
    id: toolId,
    name: tool.name,
    status: tool.enabled ? 'healthy' : 'disabled',
    version: tool.version,
    lastChecked: new Date().toISOString(),
  });
}

// Recommend tools based on project characteristics
export async function recommendTools(req: Request, res: Response) {
  const { languages, hasDocker, hasKubernetes, hasTerraform, targetType } = req.body;

  const recommended: string[] = [];
  const reasons: Record<string, string> = {};

  // Language-specific tools
  if (languages?.includes('python')) {
    recommended.push('bandit');
    reasons.bandit = 'Python code detected';
  }
  if (languages?.includes('go')) {
    recommended.push('gosec');
    reasons.gosec = 'Go code detected';
  }
  if (languages?.includes('javascript') || languages?.includes('typescript')) {
    recommended.push('eslint_security');
    reasons.eslint_security = 'JavaScript/TypeScript code detected';
  }
  if (languages?.includes('java')) {
    recommended.push('pmd');
    reasons.pmd = 'Java code detected';
  }

  // Always recommend core tools
  recommended.push('trivy', 'gitleaks');
  reasons.trivy = 'Essential vulnerability scanner';
  reasons.gitleaks = 'Essential secret detection';

  // Infrastructure tools
  if (hasDocker) {
    if (!recommended.includes('trivy')) recommended.push('trivy');
    recommended.push('grype');
    reasons.grype = 'Container image scanning';
  }
  if (hasKubernetes || hasTerraform) {
    recommended.push('checkov');
    reasons.checkov = 'IaC security scanning';
  }

  // Target type specific
  if (targetType === 'api') {
    recommended.push('zap', 'nuclei');
    reasons.zap = 'API security testing';
    reasons.nuclei = 'Vulnerability scanning';
  }

  // Supply chain
  recommended.push('syft');
  reasons.syft = 'SBOM generation for supply chain security';

  // Deduplicate and build response
  const uniqueTools = [...new Set(recommended)];

  return apiSuccess(res, {
    recommended: uniqueTools.map(toolId => ({
      id: toolId,
      ...TOOLS[toolId],
      reason: reasons[toolId],
    })),
  });
}
