/** @deprecated Removed from active scanner rotation in v2. Only validated mock config files, doesn't test actual APIs. */
import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-wiremock');

/**
 * WireMock API Mock Validation Scanner
 *
 * Analyzes WireMock mapping files for security-relevant patterns:
 * - Hardcoded credentials in stubs
 * - Missing auth in stub responses
 * - Overly permissive URL patterns
 * - Stubs that return sensitive data without auth checks
 */
export async function runWireMock(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Look for WireMock mappings
    const { stdout: mappingSearch } = await execAsync(
      `find /scan-target -path "*/mappings/*.json" -o -path "*/__files/*.json" -o -name "wiremock*.json" 2>/dev/null`
    );

    const mappingFiles = mappingSearch.trim().split('\n').filter(Boolean);
    if (mappingFiles.length === 0) {
      logger.info('No WireMock mapping files found');
      return {
        scanner: 'wiremock',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        skipReason: 'no_mock_files',
        skipHint: 'No WireMock mapping files (mappings/*.json) found',
      };
    }

    for (const mappingFile of mappingFiles) {
      try {
        const { stdout: content } = await execAsync(`cat "${mappingFile}"`, { maxBuffer: 5 * 1024 * 1024 });
        const mapping = JSON.parse(content);
        const relativePath = mappingFile.replace('/scan-target/', '');

        // Handle single mapping or array of mappings
        const mappings = Array.isArray(mapping) ? mapping : mapping.mappings || [mapping];

        for (const stub of mappings) {
          if (!stub.request) continue;

          // Check for overly permissive URL matching
          if (stub.request.urlPattern === '/.*' || stub.request.urlPathPattern === '/.*') {
            findings.push({
              ruleId: 'WIREMOCK-PERMISSIVE-URL',
              severity: 'medium',
              title: 'WireMock: Overly Permissive URL Pattern',
              description: `Stub matches all URLs with pattern "${stub.request.urlPattern || stub.request.urlPathPattern}". This may mask real API failures during testing.`,
              filePath: relativePath,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: null,
              owaspCategory: 'A04:2021-Insecure Design',
              fixAvailable: true,
              fixDescription: 'Use specific URL patterns to ensure tests validate actual endpoints',
              metadata: { urlPattern: stub.request.urlPattern || stub.request.urlPathPattern },
            });
          }

          // Check for hardcoded secrets in stub responses
          const responseBody = typeof stub.response?.body === 'string'
            ? stub.response.body
            : JSON.stringify(stub.response?.body || '');

          const secretPatterns = [
            { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9+/=]{20,}/i, name: 'API key' },
            { pattern: /(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,}/i, name: 'password' },
            { pattern: /(?:secret|token)\s*[:=]\s*["']?[A-Za-z0-9+/=]{20,}/i, name: 'secret/token' },
            { pattern: /Bearer\s+[A-Za-z0-9._-]{20,}/i, name: 'bearer token' },
          ];

          for (const { pattern, name } of secretPatterns) {
            if (pattern.test(responseBody)) {
              findings.push({
                ruleId: 'WIREMOCK-HARDCODED-SECRET',
                severity: 'high',
                title: `WireMock: Hardcoded ${name} in Stub Response`,
                description: `Stub response body contains what appears to be a hardcoded ${name}. Even in mock data, this can leak into logs and tests.`,
                filePath: relativePath,
                lineNumber: null,
                columnNumber: null,
                codeSnippet: null,
                cweId: 'CWE-798',
                owaspCategory: 'A07:2021-Identification and Authentication Failures',
                fixAvailable: true,
                fixDescription: `Replace hardcoded ${name} with placeholder values (e.g., "mock-api-key-12345")`,
                metadata: { secretType: name },
              });
              break; // One finding per stub is enough
            }
          }

          // Check for stubs returning sensitive data patterns without auth requirements
          const sensitiveDataPatterns = [
            /\bssn\b/i, /social.?security/i, /credit.?card/i,
            /\bccv\b/i, /\bcvv\b/i, /account.?number/i,
          ];

          const hasSensitiveData = sensitiveDataPatterns.some(p => p.test(responseBody));
          const hasAuthRequirement = stub.request.headers?.['Authorization'] ||
            stub.request.headers?.['authorization'] ||
            stub.request.basicAuthCredentials;

          if (hasSensitiveData && !hasAuthRequirement) {
            findings.push({
              ruleId: 'WIREMOCK-SENSITIVE-NO-AUTH',
              severity: 'medium',
              title: 'WireMock: Sensitive Data Returned Without Auth Check',
              description: 'Stub returns response with sensitive data patterns but does not require authentication in the request.',
              filePath: relativePath,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: 'CWE-862',
              owaspCategory: 'A01:2021-Broken Access Control',
              fixAvailable: true,
              fixDescription: 'Add authorization header requirement to stubs that return sensitive data',
              metadata: {},
            });
          }
        }
      } catch {
        logger.warn({ mappingFile }, 'Failed to parse WireMock mapping file');
      }
    }

    logger.info({ findingsCount: findings.length, files: mappingFiles.length }, 'WireMock analysis completed');

    return {
      scanner: 'wiremock',
      success: true,
      findings,
      duration: Date.now() - startTime,
    };
  } catch (error) {
    logger.error({ error }, 'WireMock analysis failed');
    return {
      scanner: 'wiremock',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
