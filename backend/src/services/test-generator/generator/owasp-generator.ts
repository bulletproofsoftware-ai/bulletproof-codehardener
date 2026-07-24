/**
 * TG-001: OWASP Test Generator
 * Generates security test cases based on OWASP Top 10 (2021)
 */

import { createLogger } from '../../../utils/logger.js';
import type {
  GeneratedTestCase,
  ExtractedEndpoint,
  CodeAnalysisResult,
} from '../types.js';

const logger = createLogger('owasp-generator');

/**
 * OWASP Top 10 2021 Categories
 */
export const OWASP_TOP_10_2021 = {
  A01: {
    id: 'A01:2021',
    name: 'Broken Access Control',
    description: 'Restrictions on what authenticated users are allowed to do are often not properly enforced.',
    testTypes: ['authorization', 'privilege-escalation', 'idor', 'path-traversal'],
  },
  A02: {
    id: 'A02:2021',
    name: 'Cryptographic Failures',
    description: 'Failures related to cryptography which often lead to exposure of sensitive data.',
    testTypes: ['encryption', 'data-exposure', 'weak-crypto', 'tls-validation'],
  },
  A03: {
    id: 'A03:2021',
    name: 'Injection',
    description: 'User-supplied data is not validated, filtered, or sanitized by the application.',
    testTypes: ['sql-injection', 'nosql-injection', 'command-injection', 'ldap-injection', 'xss'],
  },
  A04: {
    id: 'A04:2021',
    name: 'Insecure Design',
    description: 'Missing or ineffective control design.',
    testTypes: ['business-logic', 'threat-modeling', 'secure-design'],
  },
  A05: {
    id: 'A05:2021',
    name: 'Security Misconfiguration',
    description: 'Missing appropriate security hardening across any part of the application stack.',
    testTypes: ['headers', 'cors', 'error-handling', 'default-credentials'],
  },
  A06: {
    id: 'A06:2021',
    name: 'Vulnerable and Outdated Components',
    description: 'Using components with known vulnerabilities.',
    testTypes: ['dependency-scan', 'version-check', 'cve-scan'],
  },
  A07: {
    id: 'A07:2021',
    name: 'Identification and Authentication Failures',
    description: 'Confirmation of user identity, authentication, and session management.',
    testTypes: ['authentication-bypass', 'session-management', 'brute-force', 'credential-stuffing'],
  },
  A08: {
    id: 'A08:2021',
    name: 'Software and Data Integrity Failures',
    description: 'Code and infrastructure that does not protect against integrity violations.',
    testTypes: ['integrity-check', 'deserialization', 'supply-chain'],
  },
  A09: {
    id: 'A09:2021',
    name: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging, detection, monitoring, and active response.',
    testTypes: ['logging-validation', 'audit-trail', 'monitoring'],
  },
  A10: {
    id: 'A10:2021',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Web application fetches a remote resource without validating user-supplied URL.',
    testTypes: ['ssrf', 'url-validation', 'internal-access'],
  },
};

/**
 * Test case templates for each OWASP category
 */
const TEST_TEMPLATES: Record<string, Array<{
  name: string;
  description: string;
  category: keyof typeof OWASP_TOP_10_2021;
  severity: GeneratedTestCase['severity'];
  testSteps: string[];
  expectedResult: string;
  applicableTo: (analysis: Partial<CodeAnalysisResult>, endpoint?: ExtractedEndpoint) => boolean;
}>> = {
  // A01: Broken Access Control
  'authorization': [
    {
      name: 'Horizontal Privilege Escalation Test',
      description: 'Test if user can access resources belonging to other users',
      category: 'A01',
      severity: 'high',
      testSteps: [
        'Authenticate as User A',
        'Note resource ID owned by User A',
        'Authenticate as User B',
        'Attempt to access User A\'s resource using the noted ID',
        'Verify access is denied',
      ],
      expectedResult: 'Access to other users\' resources should be denied with 403 Forbidden',
      applicableTo: (analysis) => (analysis.authPatterns?.length || 0) > 0,
    },
    {
      name: 'Vertical Privilege Escalation Test',
      description: 'Test if regular user can access admin functionality',
      category: 'A01',
      severity: 'critical',
      testSteps: [
        'Authenticate as regular user',
        'Attempt to access admin endpoints',
        'Attempt to modify user roles',
        'Verify all admin operations are denied',
      ],
      expectedResult: 'Admin functionality should not be accessible to regular users',
      applicableTo: (_analysis, endpoint) =>
        endpoint?.path.includes('admin') || endpoint?.path.includes('manage') || false,
    },
    {
      name: 'IDOR (Insecure Direct Object Reference) Test',
      description: 'Test for direct object reference vulnerabilities',
      category: 'A01',
      severity: 'high',
      testSteps: [
        'Identify endpoints with resource IDs in URL or body',
        'Capture valid resource ID from authenticated request',
        'Modify ID to another valid resource',
        'Verify access control is enforced',
      ],
      expectedResult: 'Should return 403 or 404 for unauthorized resource access',
      applicableTo: (_analysis, endpoint) =>
        /\/:?\w*[iI]d\b/.test(endpoint?.path || '') || /\/\d+/.test(endpoint?.path || ''),
    },
  ],

  // A02: Cryptographic Failures
  'encryption': [
    {
      name: 'Sensitive Data Encryption Test',
      description: 'Verify sensitive data is encrypted at rest and in transit',
      category: 'A02',
      severity: 'critical',
      testSteps: [
        'Identify endpoints handling sensitive data',
        'Verify HTTPS is enforced',
        'Check response headers for security settings',
        'Verify sensitive data is not exposed in URLs',
      ],
      expectedResult: 'All sensitive data should be encrypted and not exposed',
      applicableTo: (analysis) => (analysis.sensitiveData?.length || 0) > 0,
    },
    {
      name: 'TLS Configuration Test',
      description: 'Verify TLS configuration meets security standards',
      category: 'A02',
      severity: 'high',
      testSteps: [
        'Check supported TLS versions',
        'Verify TLS 1.2+ is enforced',
        'Check cipher suites for weak algorithms',
        'Verify certificate validity',
      ],
      expectedResult: 'Only TLS 1.2+ with strong cipher suites should be supported',
      applicableTo: () => true,
    },
  ],

  // A03: Injection
  'sql-injection': [
    {
      name: 'SQL Injection Test',
      description: 'Test for SQL injection vulnerabilities in user inputs',
      category: 'A03',
      severity: 'critical',
      testSteps: [
        'Identify input fields that may interact with database',
        'Test with SQL injection payloads: \' OR 1=1 --, " OR ""="',
        'Test with time-based payloads: \'; WAITFOR DELAY \'0:0:5\'--',
        'Test with UNION-based payloads',
        'Verify application handles payloads safely',
      ],
      expectedResult: 'Application should sanitize inputs and prevent SQL injection',
      applicableTo: (analysis, endpoint) => {
        const hasDbFlow = analysis.dataFlows?.some(f => f.sink.type === 'db') || false;
        const hasParams = endpoint?.method !== 'GET' ||
          (endpoint?.path.includes(':') || endpoint?.path.includes('?'));
        return hasDbFlow || hasParams;
      },
    },
    {
      name: 'NoSQL Injection Test',
      description: 'Test for NoSQL injection vulnerabilities',
      category: 'A03',
      severity: 'critical',
      testSteps: [
        'Identify endpoints using NoSQL databases',
        'Test with NoSQL payloads: {$gt: ""}, {$ne: null}',
        'Test with JavaScript injection in MongoDB',
        'Verify application sanitizes NoSQL queries',
      ],
      expectedResult: 'Application should prevent NoSQL injection attacks',
      applicableTo: (analysis) => {
        const deps = analysis.dependencies || [];
        return deps.some(d =>
          ['mongoose', 'mongodb', 'dynamodb', 'couchbase'].includes(d.name.toLowerCase())
        );
      },
    },
  ],

  'xss': [
    {
      name: 'Reflected XSS Test',
      description: 'Test for reflected cross-site scripting vulnerabilities',
      category: 'A03',
      severity: 'high',
      testSteps: [
        'Identify endpoints that reflect user input',
        'Test with XSS payloads: <script>alert(1)</script>',
        'Test with encoded payloads: %3Cscript%3E',
        'Test with event handlers: <img onerror=alert(1)>',
        'Verify output encoding is applied',
      ],
      expectedResult: 'All user input should be properly encoded in responses',
      applicableTo: (_analysis, endpoint) =>
        endpoint?.method === 'GET' && endpoint?.path.includes(':'),
    },
    {
      name: 'Stored XSS Test',
      description: 'Test for stored cross-site scripting vulnerabilities',
      category: 'A03',
      severity: 'critical',
      testSteps: [
        'Identify endpoints that store user input',
        'Submit XSS payload via form/API',
        'Retrieve and render the stored data',
        'Verify XSS payload is neutralized',
      ],
      expectedResult: 'Stored data should be sanitized and safely rendered',
      applicableTo: (_analysis, endpoint) =>
        endpoint?.method === 'POST' || endpoint?.method === 'PUT',
    },
  ],

  'command-injection': [
    {
      name: 'Command Injection Test',
      description: 'Test for OS command injection vulnerabilities',
      category: 'A03',
      severity: 'critical',
      testSteps: [
        'Identify endpoints that may execute system commands',
        'Test with command separators: ; | && ||',
        'Test with backticks and $() substitution',
        'Verify commands are properly sanitized',
      ],
      expectedResult: 'Application should prevent command injection',
      applicableTo: (analysis) => {
        const hasCommandFlow = analysis.dataFlows?.some(f => f.sink.type === 'command') || false;
        return hasCommandFlow;
      },
    },
  ],

  // A05: Security Misconfiguration
  'headers': [
    {
      name: 'Security Headers Test',
      description: 'Verify security headers are properly configured',
      category: 'A05',
      severity: 'medium',
      testSteps: [
        'Make request to any endpoint',
        'Check for X-Content-Type-Options: nosniff',
        'Check for X-Frame-Options: DENY or SAMEORIGIN',
        'Check for Content-Security-Policy',
        'Check for Strict-Transport-Security',
        'Check for X-XSS-Protection (legacy browsers)',
      ],
      expectedResult: 'All security headers should be present and properly configured',
      applicableTo: () => true,
    },
  ],

  'cors': [
    {
      name: 'CORS Configuration Test',
      description: 'Test CORS configuration for security issues',
      category: 'A05',
      severity: 'medium',
      testSteps: [
        'Send request with Origin header from untrusted domain',
        'Check Access-Control-Allow-Origin response',
        'Verify credentials are not allowed with wildcard origin',
        'Test preflight requests for sensitive methods',
      ],
      expectedResult: 'CORS should only allow trusted origins',
      applicableTo: () => true,
    },
  ],

  // A07: Authentication Failures
  'authentication-bypass': [
    {
      name: 'Authentication Bypass Test',
      description: 'Test for authentication bypass vulnerabilities',
      category: 'A07',
      severity: 'critical',
      testSteps: [
        'Attempt to access protected endpoints without authentication',
        'Test with empty/null authentication tokens',
        'Test with malformed tokens',
        'Test JWT with "none" algorithm',
        'Verify all protected endpoints require valid authentication',
      ],
      expectedResult: 'All protected endpoints should require valid authentication',
      applicableTo: (analysis) => (analysis.authPatterns?.length || 0) > 0,
    },
    {
      name: 'Session Management Test',
      description: 'Test session management security',
      category: 'A07',
      severity: 'high',
      testSteps: [
        'Login and capture session token',
        'Verify token has appropriate expiration',
        'Test session after logout (should be invalid)',
        'Test session fixation by using pre-login token',
        'Verify session is regenerated after privilege change',
      ],
      expectedResult: 'Sessions should be properly managed and invalidated',
      applicableTo: (analysis) => analysis.authPatterns?.some(a => a.type === 'session') || false,
    },
  ],

  'brute-force': [
    {
      name: 'Rate Limiting Test',
      description: 'Test rate limiting on authentication endpoints',
      category: 'A07',
      severity: 'medium',
      testSteps: [
        'Identify login endpoint',
        'Send multiple failed login attempts rapidly',
        'Verify rate limiting is enforced',
        'Check for account lockout after threshold',
      ],
      expectedResult: 'Rate limiting should prevent brute force attacks',
      applicableTo: (_analysis, endpoint) =>
        !!(endpoint?.path.includes('login') || endpoint?.path.includes('auth')),
    },
  ],

  // A10: SSRF
  'ssrf': [
    {
      name: 'Server-Side Request Forgery Test',
      description: 'Test for SSRF vulnerabilities',
      category: 'A10',
      severity: 'high',
      testSteps: [
        'Identify endpoints accepting URLs as input',
        'Test with internal IP addresses (127.0.0.1, localhost)',
        'Test with cloud metadata endpoints (169.254.169.254)',
        'Test with internal hostnames',
        'Verify URL validation prevents internal access',
      ],
      expectedResult: 'Application should block requests to internal resources',
      applicableTo: (analysis) => {
        const hasExternalApiFlow = analysis.dataFlows?.some(f =>
          f.sink.type === 'external_api' && f.source.type === 'user_input'
        ) || false;
        return hasExternalApiFlow;
      },
    },
  ],
};

/**
 * Generate OWASP-based test cases from code analysis
 */
export function generateOwaspTestCases(
  analysis: CodeAnalysisResult,
  endpoints: ExtractedEndpoint[]
): GeneratedTestCase[] {
  logger.info(
    { endpointCount: endpoints.length },
    'Generating OWASP test cases'
  );

  const startTime = Date.now();
  const testCases: GeneratedTestCase[] = [];
  let testIndex = 0;

  // Generate tests for each endpoint
  for (const endpoint of endpoints) {
    for (const [_testType, templates] of Object.entries(TEST_TEMPLATES)) {
      for (const template of templates) {
        if (template.applicableTo(analysis, endpoint)) {
          testIndex++;
          const owaspCategory = OWASP_TOP_10_2021[template.category];

          testCases.push({
            id: `OWASP-${template.category}-${String(testIndex).padStart(3, '0')}`,
            name: `${template.name} - ${endpoint.method} ${endpoint.path}`,
            description: template.description,
            category: 'security',
            type: 'owasp',
            severity: template.severity ?? 'medium',
            priority: template.severity ?? 'medium',
            owaspCategory: owaspCategory.id,
            targetEndpoint: {
              method: endpoint.method,
              path: endpoint.path,
            },
            steps: template.testSteps,
            expectedResult: template.expectedResult,
            metadata: {
              prerequisites: endpoint.auth ? ['Valid authentication token'] : [],
              tags: [owaspCategory.id, template.category, 'security'],
            },
          });
        }
      }
    }
  }

  // Generate general security tests (not endpoint-specific)
  for (const [_testType, templates] of Object.entries(TEST_TEMPLATES)) {
    for (const template of templates) {
      // Check if this is a general test (applies without endpoint)
      if (template.applicableTo(analysis, undefined)) {
        const alreadyGenerated = testCases.some(tc =>
          tc.name.startsWith(template.name) && !tc.targetEndpoint
        );

        if (!alreadyGenerated) {
          testIndex++;
          const owaspCategory = OWASP_TOP_10_2021[template.category];

          testCases.push({
            id: `OWASP-${template.category}-${String(testIndex).padStart(3, '0')}`,
            name: template.name,
            description: template.description,
            category: 'security',
            type: 'owasp',
            severity: template.severity ?? 'medium',
            priority: template.severity ?? 'medium',
            owaspCategory: owaspCategory.id,
            steps: template.testSteps,
            expectedResult: template.expectedResult,
            metadata: {
              prerequisites: [],
              tags: [owaspCategory.id, template.category, 'security', 'general'],
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
    'OWASP test case generation completed'
  );

  return testCases;
}

/**
 * Get OWASP category information
 */
export function getOwaspCategory(categoryId: string): typeof OWASP_TOP_10_2021.A01 | undefined {
  const key = categoryId.replace(':2021', '') as keyof typeof OWASP_TOP_10_2021;
  return OWASP_TOP_10_2021[key];
}

/**
 * Get all OWASP categories
 */
export function getAllOwaspCategories(): typeof OWASP_TOP_10_2021 {
  return OWASP_TOP_10_2021;
}

/**
 * Filter test cases by OWASP category
 */
export function filterByOwaspCategory(
  testCases: GeneratedTestCase[],
  categoryId: string
): GeneratedTestCase[] {
  return testCases.filter(tc => tc.owaspCategory === categoryId);
}

/**
 * Get test case coverage by OWASP category
 */
export function getOwaspCoverage(testCases: GeneratedTestCase[]): Record<string, number> {
  const coverage: Record<string, number> = {};

  for (const category of Object.values(OWASP_TOP_10_2021)) {
    coverage[category.id] = testCases.filter(tc => tc.owaspCategory === category.id).length;
  }

  return coverage;
}
