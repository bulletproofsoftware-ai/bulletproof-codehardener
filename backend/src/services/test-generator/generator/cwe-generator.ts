/**
 * TG-002: CWE Generator
 * Generates test cases based on CWE Top 25 (2023) Most Dangerous Software Weaknesses
 */

import { createLogger } from '../../../utils/logger.js';
import type {
  GeneratedTestCase,
  CodeAnalysisResult,
  ExtractedEndpoint,
} from '../types.js';
import { getCategoryObject } from '../types.js';

const logger = createLogger('cwe-generator');

/**
 * CWE Top 25 (2023) Most Dangerous Software Weaknesses
 * Source: https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html
 */
export const CWE_TOP_25_2023: Record<string, {
  id: string;
  name: string;
  rank: number;
  description: string;
  languages: string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  likelihood: 'high' | 'medium' | 'low';
  testApproach: string;
  mitigations: string[];
}> = {
  'CWE-787': {
    id: 'CWE-787',
    name: 'Out-of-bounds Write',
    rank: 1,
    description: 'Software writes data past the end or before the beginning of the intended buffer',
    languages: ['c', 'cpp', 'rust'],
    severity: 'critical',
    likelihood: 'high',
    testApproach: 'buffer-overflow',
    mitigations: [
      'Use memory-safe languages',
      'Bounds checking',
      'Use safe string functions',
      'Address Space Layout Randomization (ASLR)',
    ],
  },
  'CWE-79': {
    id: 'CWE-79',
    name: 'Cross-site Scripting (XSS)',
    rank: 2,
    description: 'Software does not neutralize user-controllable input before output in web page',
    languages: ['javascript', 'typescript', 'php', 'python', 'java', 'ruby'],
    severity: 'high',
    likelihood: 'high',
    testApproach: 'injection',
    mitigations: [
      'Output encoding',
      'Content Security Policy',
      'Input validation',
      'Use framework auto-escaping',
    ],
  },
  'CWE-89': {
    id: 'CWE-89',
    name: 'SQL Injection',
    rank: 3,
    description: 'Software constructs SQL commands using externally-influenced input',
    languages: ['php', 'python', 'java', 'javascript', 'typescript', 'ruby', 'csharp'],
    severity: 'critical',
    likelihood: 'high',
    testApproach: 'injection',
    mitigations: [
      'Parameterized queries',
      'Prepared statements',
      'ORM usage',
      'Input validation',
      'Least privilege database accounts',
    ],
  },
  'CWE-416': {
    id: 'CWE-416',
    name: 'Use After Free',
    rank: 4,
    description: 'Referencing memory after it has been freed',
    languages: ['c', 'cpp'],
    severity: 'critical',
    likelihood: 'medium',
    testApproach: 'memory-safety',
    mitigations: [
      'Use memory-safe languages',
      'Smart pointers',
      'Static analysis tools',
      'Memory sanitizers',
    ],
  },
  'CWE-78': {
    id: 'CWE-78',
    name: 'OS Command Injection',
    rank: 5,
    description: 'Software constructs OS commands using externally-influenced input',
    languages: ['python', 'php', 'ruby', 'javascript', 'typescript', 'java', 'shell'],
    severity: 'critical',
    likelihood: 'high',
    testApproach: 'injection',
    mitigations: [
      'Avoid shell commands',
      'Use language APIs instead of shell',
      'Input validation and sanitization',
      'Allowlist approach for commands',
    ],
  },
  'CWE-20': {
    id: 'CWE-20',
    name: 'Improper Input Validation',
    rank: 6,
    description: 'Software does not validate or incorrectly validates input',
    languages: ['all'],
    severity: 'high',
    likelihood: 'high',
    testApproach: 'fuzzing',
    mitigations: [
      'Input validation on all inputs',
      'Allowlist validation',
      'Schema validation',
      'Type checking',
    ],
  },
  'CWE-125': {
    id: 'CWE-125',
    name: 'Out-of-bounds Read',
    rank: 7,
    description: 'Software reads data past the end or before the beginning of the intended buffer',
    languages: ['c', 'cpp'],
    severity: 'high',
    likelihood: 'medium',
    testApproach: 'memory-safety',
    mitigations: [
      'Bounds checking',
      'Memory-safe languages',
      'Static analysis',
      'Memory sanitizers',
    ],
  },
  'CWE-22': {
    id: 'CWE-22',
    name: 'Path Traversal',
    rank: 8,
    description: 'Software uses external input to construct a pathname without proper neutralization',
    languages: ['all'],
    severity: 'high',
    likelihood: 'high',
    testApproach: 'injection',
    mitigations: [
      'Canonicalize paths',
      'Chroot jails',
      'Input validation',
      'Allowlist file access',
    ],
  },
  'CWE-352': {
    id: 'CWE-352',
    name: 'Cross-Site Request Forgery (CSRF)',
    rank: 9,
    description: 'Web application does not verify that request was intentionally sent by user',
    languages: ['javascript', 'typescript', 'php', 'python', 'java', 'ruby'],
    severity: 'high',
    likelihood: 'medium',
    testApproach: 'authentication',
    mitigations: [
      'CSRF tokens',
      'SameSite cookie attribute',
      'Double submit cookie',
      'Verify origin header',
    ],
  },
  'CWE-434': {
    id: 'CWE-434',
    name: 'Unrestricted Upload of File with Dangerous Type',
    rank: 10,
    description: 'Software allows upload of dangerous file types that can be executed',
    languages: ['php', 'python', 'java', 'javascript', 'typescript', 'ruby'],
    severity: 'critical',
    likelihood: 'medium',
    testApproach: 'file-upload',
    mitigations: [
      'File type validation',
      'Content type verification',
      'Store outside web root',
      'Rename uploaded files',
      'Scan for malware',
    ],
  },
  'CWE-862': {
    id: 'CWE-862',
    name: 'Missing Authorization',
    rank: 11,
    description: 'Software does not perform authorization check when accessing resources',
    languages: ['all'],
    severity: 'high',
    likelihood: 'high',
    testApproach: 'authorization',
    mitigations: [
      'Implement authorization checks',
      'Deny by default',
      'Role-based access control',
      'Attribute-based access control',
    ],
  },
  'CWE-476': {
    id: 'CWE-476',
    name: 'NULL Pointer Dereference',
    rank: 12,
    description: 'Application dereferences a pointer that is expected to be valid but is NULL',
    languages: ['c', 'cpp', 'java', 'csharp'],
    severity: 'medium',
    likelihood: 'medium',
    testApproach: 'null-safety',
    mitigations: [
      'Null checks',
      'Optional types',
      'Nullable annotations',
      'Static analysis',
    ],
  },
  'CWE-287': {
    id: 'CWE-287',
    name: 'Improper Authentication',
    rank: 13,
    description: 'Software does not prove that an entity is who it claims to be',
    languages: ['all'],
    severity: 'critical',
    likelihood: 'high',
    testApproach: 'authentication',
    mitigations: [
      'Strong authentication mechanisms',
      'Multi-factor authentication',
      'Secure session management',
      'Password policies',
    ],
  },
  'CWE-190': {
    id: 'CWE-190',
    name: 'Integer Overflow or Wraparound',
    rank: 14,
    description: 'Software performs calculations that can produce integer overflow',
    languages: ['c', 'cpp', 'java'],
    severity: 'high',
    likelihood: 'medium',
    testApproach: 'numeric',
    mitigations: [
      'Use larger integer types',
      'Check before arithmetic',
      'Use safe math libraries',
      'Compiler flags for overflow detection',
    ],
  },
  'CWE-502': {
    id: 'CWE-502',
    name: 'Deserialization of Untrusted Data',
    rank: 15,
    description: 'Application deserializes untrusted data without verification',
    languages: ['java', 'python', 'php', 'ruby', 'javascript', 'typescript', 'csharp'],
    severity: 'critical',
    likelihood: 'medium',
    testApproach: 'deserialization',
    mitigations: [
      'Avoid native deserialization',
      'Use JSON instead of binary formats',
      'Input validation',
      'Integrity checking',
    ],
  },
  'CWE-77': {
    id: 'CWE-77',
    name: 'Command Injection',
    rank: 16,
    description: 'Software constructs commands using externally-influenced input',
    languages: ['all'],
    severity: 'critical',
    likelihood: 'high',
    testApproach: 'injection',
    mitigations: [
      'Avoid command execution',
      'Input validation',
      'Parameterization',
      'Sandboxing',
    ],
  },
  'CWE-119': {
    id: 'CWE-119',
    name: 'Improper Restriction of Operations within Memory Buffer',
    rank: 17,
    description: 'Software performs operations on memory buffer without proper bounds',
    languages: ['c', 'cpp'],
    severity: 'critical',
    likelihood: 'medium',
    testApproach: 'memory-safety',
    mitigations: [
      'Bounds checking',
      'Memory-safe languages',
      'Static analysis',
      'Memory sanitizers',
    ],
  },
  'CWE-798': {
    id: 'CWE-798',
    name: 'Use of Hard-coded Credentials',
    rank: 18,
    description: 'Software contains hard-coded credentials for authentication',
    languages: ['all'],
    severity: 'critical',
    likelihood: 'high',
    testApproach: 'secrets',
    mitigations: [
      'Use environment variables',
      'Use secrets management',
      'Configuration files outside repository',
      'Secret scanning in CI/CD',
    ],
  },
  'CWE-918': {
    id: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    rank: 19,
    description: 'Server-side application can be made to make requests to unintended locations',
    languages: ['all'],
    severity: 'high',
    likelihood: 'medium',
    testApproach: 'ssrf',
    mitigations: [
      'URL allowlist',
      'Disable unnecessary protocols',
      'Network segmentation',
      'Validate and sanitize URLs',
    ],
  },
  'CWE-306': {
    id: 'CWE-306',
    name: 'Missing Authentication for Critical Function',
    rank: 20,
    description: 'Software does not perform authentication for critical functionality',
    languages: ['all'],
    severity: 'critical',
    likelihood: 'high',
    testApproach: 'authentication',
    mitigations: [
      'Require authentication for all critical functions',
      'Defense in depth',
      'Centralized authentication',
      'Security testing',
    ],
  },
  'CWE-362': {
    id: 'CWE-362',
    name: 'Race Condition',
    rank: 21,
    description: 'Concurrent execution with shared resource can lead to unexpected behavior',
    languages: ['all'],
    severity: 'medium',
    likelihood: 'medium',
    testApproach: 'concurrency',
    mitigations: [
      'Proper synchronization',
      'Atomic operations',
      'Thread-safe data structures',
      'Avoid shared state',
    ],
  },
  'CWE-269': {
    id: 'CWE-269',
    name: 'Improper Privilege Management',
    rank: 22,
    description: 'Software does not properly manage privileges',
    languages: ['all'],
    severity: 'high',
    likelihood: 'medium',
    testApproach: 'authorization',
    mitigations: [
      'Principle of least privilege',
      'Privilege separation',
      'Drop privileges when not needed',
      'Regular privilege audits',
    ],
  },
  'CWE-94': {
    id: 'CWE-94',
    name: 'Code Injection',
    rank: 23,
    description: 'Software constructs code segments using externally-influenced input',
    languages: ['python', 'javascript', 'typescript', 'php', 'ruby'],
    severity: 'critical',
    likelihood: 'high',
    testApproach: 'injection',
    mitigations: [
      'Avoid dynamic code execution',
      'Sandboxing',
      'Input validation',
      'Use safe alternatives',
    ],
  },
  'CWE-863': {
    id: 'CWE-863',
    name: 'Incorrect Authorization',
    rank: 24,
    description: 'Software performs authorization check incorrectly',
    languages: ['all'],
    severity: 'high',
    likelihood: 'high',
    testApproach: 'authorization',
    mitigations: [
      'Centralized authorization logic',
      'Comprehensive testing',
      'Deny by default',
      'Regular security reviews',
    ],
  },
  'CWE-276': {
    id: 'CWE-276',
    name: 'Incorrect Default Permissions',
    rank: 25,
    description: 'Software sets incorrect default permissions on resources',
    languages: ['all'],
    severity: 'medium',
    likelihood: 'high',
    testApproach: 'permissions',
    mitigations: [
      'Restrictive default permissions',
      'Principle of least privilege',
      'Regular permission audits',
      'Infrastructure as code',
    ],
  },
} as const;

export type CWEId = keyof typeof CWE_TOP_25_2023;

export interface CWECategory {
  id: string;
  name: string;
  rank: number;
  description: string;
  languages: readonly string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  likelihood: 'high' | 'medium' | 'low';
  testApproach: string;
  mitigations: readonly string[];
}

/**
 * Test case templates for each CWE category
 */
const CWE_TEST_TEMPLATES: Record<string, Array<{
  name: string;
  description: string;
  type: GeneratedTestCase['type'];
  priority: GeneratedTestCase['priority'];
  applicableCondition: (analysis: CodeAnalysisResult, endpoint?: ExtractedEndpoint) => boolean;
  generateSteps: (analysis: CodeAnalysisResult, endpoint?: ExtractedEndpoint) => string[];
}>> = {
  // CWE-79: XSS
  'CWE-79': [
    {
      name: 'Reflected XSS in Query Parameters',
      description: 'Test for reflected XSS vulnerabilities in URL query parameters',
      type: 'security',
      priority: 'high',
      applicableCondition: (analysis, endpoint) =>
        endpoint?.method === 'GET' && (endpoint?.path?.includes(':') || analysis.languages.some(l => ['javascript', 'typescript', 'php'].includes(l.language))),
      generateSteps: () => [
        'Identify all query parameters accepted by the endpoint',
        'Inject XSS payloads: <script>alert(1)</script>, <img onerror=alert(1) src=x>',
        'Test event handler payloads: onclick, onmouseover, onfocus',
        'Check if output is HTML encoded',
        'Verify Content-Security-Policy header presence',
        'Test DOM-based XSS vectors',
      ],
    },
    {
      name: 'Stored XSS in User Input',
      description: 'Test for stored XSS vulnerabilities in user-submitted content',
      type: 'security',
      priority: 'critical',
      applicableCondition: (analysis, endpoint) =>
        endpoint?.method === 'POST' && (analysis.hasDatabase ?? false),
      generateSteps: () => [
        'Submit XSS payloads in all input fields',
        'Test persistence of XSS across page loads',
        'Verify sanitization of HTML entities',
        'Test rich text editor bypasses',
        'Check for XSS in error messages',
      ],
    },
  ],

  // CWE-89: SQL Injection
  'CWE-89': [
    {
      name: 'SQL Injection in Parameters',
      description: 'Test for SQL injection vulnerabilities in request parameters',
      type: 'security',
      priority: 'critical',
      applicableCondition: (analysis) => analysis.hasDatabase ?? false,
      generateSteps: (_analysis, endpoint) => [
        `Test endpoint ${endpoint?.path || 'parameters'} with SQL injection payloads`,
        "Inject: ' OR '1'='1, ' OR 1=1--, '; DROP TABLE users;--",
        'Test UNION-based injection: UNION SELECT NULL,NULL--',
        'Test blind SQL injection with time delays',
        'Verify parameterized queries are used',
        'Check for error-based information disclosure',
      ],
    },
    {
      name: 'Second-Order SQL Injection',
      description: 'Test for SQL injection that manifests in secondary operations',
      type: 'security',
      priority: 'high',
      applicableCondition: (analysis) => (analysis.hasDatabase ?? false) && (analysis.hasUserInput ?? false),
      generateSteps: () => [
        'Store malicious payload in user profile or settings',
        'Trigger secondary operation that uses stored data',
        'Monitor database queries for injected content',
        'Test batch operations with stored payloads',
      ],
    },
  ],

  // CWE-78: OS Command Injection
  'CWE-78': [
    {
      name: 'Command Injection in Parameters',
      description: 'Test for OS command injection vulnerabilities',
      type: 'security',
      priority: 'critical',
      applicableCondition: (analysis) =>
        (analysis.hasShellCommands ?? false) || analysis.frameworks.some(f => (f.name ?? f.framework)?.toLowerCase().includes('express') || (f.name ?? f.framework)?.toLowerCase().includes('flask')),
      generateSteps: () => [
        'Inject command separators: ;, |, &&, ||, ``,  $()',
        'Test newline injection: %0a, %0d',
        'Try command substitution: $(whoami), `id`',
        'Test encoded payloads: URL encoding, double encoding',
        'Verify commands are not run with elevated privileges',
      ],
    },
  ],

  // CWE-22: Path Traversal
  'CWE-22': [
    {
      name: 'Path Traversal in File Access',
      description: 'Test for directory traversal vulnerabilities in file operations',
      type: 'security',
      priority: 'high',
      applicableCondition: (analysis, endpoint) =>
        endpoint?.path?.includes('file') ||
        endpoint?.path?.includes('download') ||
        endpoint?.path?.includes('upload') ||
        (analysis.hasFileOperations ?? false),
      generateSteps: () => [
        'Test path traversal: ../../../etc/passwd',
        'Try encoded traversal: %2e%2e%2f, ..%252f',
        'Test Windows paths: ..\\..\\windows\\system32',
        'Try null byte injection: file.txt%00.jpg',
        'Verify path canonicalization',
        'Test symbolic link following',
      ],
    },
  ],

  // CWE-352: CSRF
  'CWE-352': [
    {
      name: 'CSRF on State-Changing Operations',
      description: 'Test for missing CSRF protection on state-changing requests',
      type: 'security',
      priority: 'high',
      applicableCondition: (_, endpoint) =>
        !!(endpoint?.method && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(endpoint.method)),
      generateSteps: (_, endpoint) => [
        `Test ${endpoint?.method} ${endpoint?.path} without CSRF token`,
        'Verify CSRF token is required and validated',
        'Test token reuse across sessions',
        'Verify SameSite cookie attribute',
        'Test CORS preflight behavior',
        'Check Referer/Origin header validation',
      ],
    },
  ],

  // CWE-434: File Upload
  'CWE-434': [
    {
      name: 'Dangerous File Upload',
      description: 'Test for unrestricted file upload vulnerabilities',
      type: 'security',
      priority: 'critical',
      applicableCondition: (_, endpoint) =>
        !!(endpoint?.path?.includes('upload') ||
        endpoint?.path?.includes('import') ||
        endpoint?.path?.includes('file')),
      generateSteps: () => [
        'Upload executable files: .php, .jsp, .aspx, .exe',
        'Test double extension: file.php.jpg',
        'Test Content-Type bypass with magic bytes',
        'Upload polyglot files (valid image + script)',
        'Test for path traversal in filename',
        'Verify files are stored outside web root',
        'Check file size limits',
      ],
    },
  ],

  // CWE-862: Missing Authorization
  'CWE-862': [
    {
      name: 'Missing Authorization Checks',
      description: 'Test for missing authorization on protected resources',
      type: 'security',
      priority: 'high',
      applicableCondition: () => true,
      generateSteps: (_, endpoint) => [
        `Access ${endpoint?.path || 'endpoint'} without authentication`,
        'Access with low-privilege user credentials',
        'Test horizontal privilege escalation (access other users data)',
        'Test vertical privilege escalation (access admin functions)',
        'Verify IDOR vulnerabilities with direct object references',
        'Test mass assignment vulnerabilities',
      ],
    },
  ],

  // CWE-287: Improper Authentication
  'CWE-287': [
    {
      name: 'Authentication Bypass',
      description: 'Test for authentication bypass vulnerabilities',
      type: 'security',
      priority: 'critical',
      applicableCondition: (analysis) => analysis.hasAuthentication ?? false,
      generateSteps: () => [
        'Test authentication endpoint with malformed credentials',
        'Test session fixation attacks',
        'Verify password reset token security',
        'Test brute force protection',
        'Check for default credentials',
        'Test JWT vulnerabilities (none algorithm, weak secrets)',
        'Verify multi-factor authentication enforcement',
      ],
    },
  ],

  // CWE-502: Deserialization
  'CWE-502': [
    {
      name: 'Insecure Deserialization',
      description: 'Test for unsafe deserialization vulnerabilities',
      type: 'security',
      priority: 'critical',
      applicableCondition: (analysis) =>
        analysis.languages.some(l => ['java', 'python', 'php', 'ruby'].includes(l.language)),
      generateSteps: () => [
        'Test application deserialization endpoints',
        'Inject serialized objects with malicious payloads',
        'Test for gadget chains (ysoserial for Java)',
        'Verify input validation before deserialization',
        'Test for type confusion attacks',
        'Check for denial of service via nested objects',
      ],
    },
  ],

  // CWE-798: Hardcoded Credentials
  'CWE-798': [
    {
      name: 'Hardcoded Secrets Detection',
      description: 'Test for hardcoded credentials and secrets in codebase',
      type: 'security',
      priority: 'critical',
      applicableCondition: () => true,
      generateSteps: () => [
        'Scan codebase for hardcoded passwords',
        'Search for API keys and tokens',
        'Check configuration files for secrets',
        'Verify secrets are loaded from environment',
        'Test for secrets in client-side code',
        'Check git history for accidentally committed secrets',
      ],
    },
  ],

  // CWE-918: SSRF
  'CWE-918': [
    {
      name: 'Server-Side Request Forgery',
      description: 'Test for SSRF vulnerabilities in URL handling',
      type: 'security',
      priority: 'high',
      applicableCondition: (_, endpoint) =>
        !!(endpoint?.path?.includes('url') ||
        endpoint?.path?.includes('fetch') ||
        endpoint?.path?.includes('proxy') ||
        endpoint?.path?.includes('webhook')),
      generateSteps: () => [
        'Test internal IP access: 127.0.0.1, localhost, 169.254.169.254',
        'Test cloud metadata endpoints',
        'Try protocol smuggling: file://, gopher://, dict://',
        'Test DNS rebinding attacks',
        'Verify URL allowlist implementation',
        'Test bypass with URL encoding and redirects',
      ],
    },
  ],

  // CWE-20: Input Validation
  'CWE-20': [
    {
      name: 'Input Validation Bypass',
      description: 'Test for improper input validation',
      type: 'security',
      priority: 'high',
      applicableCondition: () => true,
      generateSteps: () => [
        'Test boundary values and edge cases',
        'Submit unexpected data types',
        'Test with null, empty, and whitespace values',
        'Send oversized input',
        'Test unicode normalization issues',
        'Verify server-side validation (not just client-side)',
      ],
    },
  ],

  // CWE-94: Code Injection
  'CWE-94': [
    {
      name: 'Code Injection',
      description: 'Test for code injection vulnerabilities',
      type: 'security',
      priority: 'critical',
      applicableCondition: (analysis) =>
        analysis.languages.some(l => ['javascript', 'typescript', 'python', 'php', 'ruby'].includes(l.language)),
      generateSteps: () => [
        'Test for code injection in dynamic evaluation',
        'Test template injection (SSTI)',
        'Inject code in JSON/XML parsers',
        'Test dynamic code execution inputs',
        'Verify sandboxing of dynamic code execution',
      ],
    },
  ],

  // CWE-362: Race Condition
  'CWE-362': [
    {
      name: 'Race Condition Exploitation',
      description: 'Test for race condition vulnerabilities',
      type: 'security',
      priority: 'medium',
      applicableCondition: (analysis) =>
        (analysis.hasDatabase ?? false) || (analysis.hasFileOperations ?? false),
      generateSteps: () => [
        'Send concurrent requests to same endpoint',
        'Test time-of-check to time-of-use (TOCTOU)',
        'Test double-spending scenarios',
        'Verify atomic operations on shared resources',
        'Test file locking mechanisms',
      ],
    },
  ],
};

/**
 * Check if a CWE category is applicable to the given analysis
 */
function isCweApplicable(
  cweId: CWEId,
  analysis: CodeAnalysisResult
): boolean {
  const cwe = CWE_TOP_25_2023[cweId];

  // Check if language is applicable
  if (!cwe.languages.includes('all')) {
    const hasApplicableLanguage = analysis.languages.some(lang =>
      cwe.languages.includes(lang.language)
    );
    if (!hasApplicableLanguage) {
      return false;
    }
  }

  return true;
}

/**
 * Generate test cases based on CWE Top 25 (2023)
 */
export function generateCweTestCases(
  analysis: CodeAnalysisResult,
  endpoints: ExtractedEndpoint[]
): GeneratedTestCase[] {
  logger.info(
    { languageCount: analysis.languages.length, endpointCount: endpoints.length },
    'Generating CWE Top 25 test cases'
  );

  const startTime = Date.now();
  const testCases: GeneratedTestCase[] = [];

  // Generate endpoint-specific test cases
  for (const endpoint of endpoints) {
    for (const [cweId, templates] of Object.entries(CWE_TEST_TEMPLATES)) {
      if (!isCweApplicable(cweId as CWEId, analysis)) {
        continue;
      }

      const cwe = CWE_TOP_25_2023[cweId as CWEId];

      for (const template of templates) {
        if (template.applicableCondition(analysis, endpoint)) {
          testCases.push({
            id: `CWE-${cwe.id}-${endpoint.method}-${endpoint.path.replace(/[^a-zA-Z0-9]/g, '-')}-${template.name.replace(/\s+/g, '-')}`,
            name: `${template.name} - ${endpoint.method} ${endpoint.path}`,
            description: template.description,
            type: template.type,
            priority: template.priority,
            category: {
              primary: cwe.id,
              owasp: mapCweToOwasp(cweId),
              cwe: [cweId],
            },
            steps: template.generateSteps(analysis, endpoint),
            expectedResult: `No ${cwe.name} vulnerability should be present`,
            targetEndpoint: endpoint,
            metadata: {
              severity: cwe.severity,
              likelihood: cwe.likelihood,
              mitigations: [...cwe.mitigations],
              cweRank: cwe.rank,
            },
          });
        }
      }
    }
  }

  // Generate general test cases (not endpoint-specific)
  for (const [cweId, templates] of Object.entries(CWE_TEST_TEMPLATES)) {
    if (!isCweApplicable(cweId as CWEId, analysis)) {
      continue;
    }

    const cwe = CWE_TOP_25_2023[cweId as CWEId];

    for (const template of templates) {
      // Check if this template applies without endpoint context
      if (template.applicableCondition(analysis, undefined)) {
        // Avoid duplicating endpoint-specific tests
        const hasEndpointSpecific = endpoints.some(ep =>
          testCases.some(tc =>
            tc.id.includes(cweId) &&
            tc.targetEndpoint?.path === ep.path
          )
        );

        if (!hasEndpointSpecific || endpoints.length === 0) {
          testCases.push({
            id: `CWE-${cwe.id}-general-${template.name.replace(/\s+/g, '-')}`,
            name: `${template.name} (General)`,
            description: template.description,
            type: template.type,
            priority: template.priority,
            category: {
              primary: cwe.id,
              owasp: mapCweToOwasp(cweId),
              cwe: [cweId],
            },
            steps: template.generateSteps(analysis, undefined),
            expectedResult: `No ${cwe.name} vulnerability should be present`,
            metadata: {
              severity: cwe.severity,
              likelihood: cwe.likelihood,
              mitigations: [...cwe.mitigations],
              cweRank: cwe.rank,
            },
          });
        }
      }
    }
  }

  logger.info(
    {
      testCaseCount: testCases.length,
      durationMs: Date.now() - startTime,
    },
    'CWE test case generation completed'
  );

  return testCases;
}

/**
 * Map CWE to OWASP Top 10 category
 */
function mapCweToOwasp(cweId: string): string {
  const cweToOwaspMap: Record<string, string> = {
    'CWE-79': 'A03:2021',   // XSS -> Injection
    'CWE-89': 'A03:2021',   // SQLi -> Injection
    'CWE-78': 'A03:2021',   // Command Injection -> Injection
    'CWE-77': 'A03:2021',   // Command Injection -> Injection
    'CWE-94': 'A03:2021',   // Code Injection -> Injection
    'CWE-22': 'A01:2021',   // Path Traversal -> Broken Access Control
    'CWE-862': 'A01:2021',  // Missing Authorization -> Broken Access Control
    'CWE-863': 'A01:2021',  // Incorrect Authorization -> Broken Access Control
    'CWE-269': 'A01:2021',  // Improper Privilege -> Broken Access Control
    'CWE-276': 'A01:2021',  // Incorrect Permissions -> Broken Access Control
    'CWE-287': 'A07:2021',  // Improper Authentication -> Identification Failures
    'CWE-306': 'A07:2021',  // Missing Authentication -> Identification Failures
    'CWE-352': 'A01:2021',  // CSRF -> Broken Access Control
    'CWE-434': 'A04:2021',  // File Upload -> Insecure Design
    'CWE-502': 'A08:2021',  // Deserialization -> Software Integrity
    'CWE-798': 'A07:2021',  // Hardcoded Creds -> Identification Failures
    'CWE-918': 'A10:2021',  // SSRF -> SSRF
    'CWE-20': 'A03:2021',   // Input Validation -> Injection
    'CWE-362': 'A04:2021',  // Race Condition -> Insecure Design
    'CWE-787': 'A06:2021',  // Out-of-bounds Write -> Vulnerable Components
    'CWE-416': 'A06:2021',  // Use After Free -> Vulnerable Components
    'CWE-125': 'A06:2021',  // Out-of-bounds Read -> Vulnerable Components
    'CWE-476': 'A06:2021',  // NULL Pointer -> Vulnerable Components
    'CWE-190': 'A06:2021',  // Integer Overflow -> Vulnerable Components
    'CWE-119': 'A06:2021',  // Buffer Overflow -> Vulnerable Components
  };

  return cweToOwaspMap[cweId] || 'A04:2021'; // Default to Insecure Design
}

/**
 * Get CWE coverage statistics for generated test cases
 */
export function getCweCoverage(testCases: GeneratedTestCase[]): Record<string, number> {
  const coverage: Record<string, number> = {};

  for (const testCase of testCases) {
    const category = getCategoryObject(testCase.category);
    if (category.cwe) {
      for (const cweId of category.cwe) {
        coverage[cweId] = (coverage[cweId] || 0) + 1;
      }
    }
  }

  return coverage;
}

/**
 * Get CWE categories sorted by rank
 */
export function getCweByRank(): CWECategory[] {
  return Object.values(CWE_TOP_25_2023)
    .sort((a, b) => a.rank - b.rank);
}

/**
 * Get applicable CWE categories for given languages
 */
export function getApplicableCweForLanguages(languages: string[]): CWECategory[] {
  return Object.values(CWE_TOP_25_2023).filter(cwe =>
    cwe.languages.includes('all') ||
    languages.some(lang => cwe.languages.includes(lang))
  );
}
