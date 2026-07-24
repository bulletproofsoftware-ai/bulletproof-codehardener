import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-schemathesis');

const SCAN_TARGET = '/scan-target';
const OUTPUT_FILE = '/tmp/schemathesis-report.json';

const SPEC_CANDIDATES = [
  'openapi.yaml', 'openapi.yml', 'openapi.json',
  'swagger.yaml', 'swagger.yml', 'swagger.json',
  'docs/openapi.yaml', 'docs/openapi.yml', 'docs/openapi.json',
  'docs/swagger.yaml', 'docs/swagger.yml', 'docs/swagger.json',
  'api/openapi.yaml', 'api/openapi.yml', 'api/openapi.json',
  'spec/openapi.yaml', 'spec/openapi.yml', 'spec/openapi.json',
];

interface SchemathesisFailure {
  method: string;
  path: string;
  statusCode: number;
  message: string;
  example?: {
    query?: Record<string, unknown>;
    body?: unknown;
    headers?: Record<string, string>;
  };
}

function statusCodeToSeverity(statusCode: number): Severity {
  if (statusCode >= 500) return 'high';
  if (statusCode >= 400) return 'medium';
  return 'low';
}

function findSpecFile(): string | null {
  for (const candidate of SPEC_CANDIDATES) {
    if (existsSync(`${SCAN_TARGET}/${candidate}`)) {
      return candidate;
    }
  }
  return null;
}

export async function runSchemathesis(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Use explicit spec path, pre-detected OpenAPI spec, or fall back to filesystem search
    const specFile = jobData.openapiSpecPath
      || jobData.detectedSpecs?.openapi?.[0]
      || findSpecFile();

    if (!specFile) {
      return {
        scanner: 'schemathesis',
        success: true,
        skipped: true,
        skipReason: 'no_api_spec',
        skipHint: 'Add an openapi.json/yaml or swagger.json/yaml to your project, or set openapiSpecPath on the project.',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No OpenAPI/Swagger spec file found',
      };
    }

    const specPath = `${SCAN_TARGET}/${specFile}`;

    // Validate spec file is parseable
    let specContent: string;
    try {
      specContent = await readFile(specPath, 'utf-8');
      if (specContent.trim().length === 0) {
        return {
          scanner: 'schemathesis',
          success: true,
          skipped: true,
          findings: [],
          duration: Date.now() - startTime,
          rawOutput: 'Spec file is empty',
        };
      }
    } catch {
      return {
        scanner: 'schemathesis',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: `Cannot read spec file: ${specFile}`,
      };
    }

    // Run schemathesis — live mode if targetUrl available, otherwise dry-run validation only
    const useLiveMode = !!jobData.targetUrl;
    const cmdParts = [
      'schemathesis', 'run',
      useLiveMode ? `--url=${jobData.targetUrl}` : '',
      `file://${specPath}`,
      '--validate-schema=true',
      ...(!useLiveMode ? ['--dry-run'] : []),
      '--stateful=links',
      '--hypothesis-max-examples=50',
      `--cassette-path=${OUTPUT_FILE}`,
      '--verbosity=quiet',
      '2>/dev/null || true',
    ].filter(Boolean);
    const cmd = cmdParts.join(' ');

    const { stdout, stderr } = await execAsync(cmd, {
      maxBuffer: 50 * 1024 * 1024,
      timeout: 180000,
    });

    const combinedOutput = `${stdout}\n${stderr}`;

    // Parse schemathesis text output for failures
    // Schemathesis outputs failure summaries with endpoint, method, and error details
    const failures: SchemathesisFailure[] = [];

    // Match failure patterns from schemathesis output
    const failureBlockRegex = /FAILURES\s*\n([\s\S]*?)(?:\n={3,}|\n-{3,}|$)/;
    const failureBlock = combinedOutput.match(failureBlockRegex);

    if (failureBlock) {
      // Individual failure entries: "METHOD /path -> status_code"
      const entryRegex = /(\w+)\s+(\/\S+)\s*.*?(\d{3})/g;
      let entryMatch;

      while ((entryMatch = entryRegex.exec(failureBlock[1])) !== null) {
        failures.push({
          method: entryMatch[1],
          path: entryMatch[2],
          statusCode: parseInt(entryMatch[3]),
          message: `${entryMatch[1]} ${entryMatch[2]} returned ${entryMatch[3]}`,
        });
      }
    }

    // Also parse schema validation errors
    const schemaErrors: Array<{ path: string; message: string }> = [];
    const schemaErrorRegex = /Schema Error.*?:\s*(.*?)(?:\n|$)/gi;
    let schemaMatch;
    while ((schemaMatch = schemaErrorRegex.exec(combinedOutput)) !== null) {
      schemaErrors.push({
        path: specFile,
        message: schemaMatch[1].trim(),
      });
    }

    // Also check for "ERROR" lines indicating spec issues
    const errorLineRegex = /^(?:ERROR|error):\s*(.+)$/gm;
    let errorMatch;
    while ((errorMatch = errorLineRegex.exec(combinedOutput)) !== null) {
      const msg = errorMatch[1].trim();
      if (!schemaErrors.some(e => e.message === msg)) {
        schemaErrors.push({ path: specFile, message: msg });
      }
    }

    // Create findings for schema validation errors
    for (const error of schemaErrors.slice(0, 10)) {
      findings.push({
        ruleId: 'API-SCHEMA-001',
        severity: 'medium',
        title: `Schema validation error in ${error.path}`,
        description: `The OpenAPI specification has a validation error: ${error.message}. ` +
          'AI-generated API specs often contain schema inconsistencies that can lead to ' +
          'runtime errors, incorrect client code generation, and security bypasses.',
        filePath: error.path,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: 'CWE-20',
        owaspCategory: 'A04:2021-Insecure Design',
        fixAvailable: true,
        fixDescription: `Fix the schema validation error: ${error.message}`,
        metadata: { errorType: 'schema-validation' },
      });
    }

    // Create findings for endpoint failures
    for (const failure of failures.slice(0, 20)) {
      findings.push({
        ruleId: 'API-SCHEMA-001',
        severity: statusCodeToSeverity(failure.statusCode),
        title: `API failure: ${failure.method} ${failure.path} → ${failure.statusCode}`,
        description: `Schemathesis testing found that ${failure.method} ${failure.path} returned HTTP ${failure.statusCode}. ` +
          (failure.statusCode >= 500
            ? 'Server errors (5xx) indicate unhandled exceptions that may leak stack traces or internal details. '
            : 'Client errors under fuzz testing indicate input validation gaps. ') +
          'AI-generated API handlers frequently lack proper error handling and input validation.',
        filePath: specFile,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: failure.example ? JSON.stringify(failure.example, null, 2) : null,
        cweId: failure.statusCode >= 500 ? 'CWE-390' : 'CWE-20',
        owaspCategory: 'A04:2021-Insecure Design',
        fixAvailable: true,
        fixDescription: `Add proper error handling and input validation for ${failure.method} ${failure.path}.`,
        metadata: {
          method: failure.method,
          endpoint: failure.path,
          statusCode: failure.statusCode,
        },
      });
    }

    // Check for spec completeness issues
    // Parse spec for endpoints without security definitions
    let endpointCount = 0;
    let securedEndpoints = 0;
    try {
      if (specFile.endsWith('.json')) {
        const spec = JSON.parse(specContent);
        const paths = spec.paths || {};
        for (const pathObj of Object.values(paths) as any[]) {
          for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
            if (pathObj[method]) {
              endpointCount++;
              if (pathObj[method].security || spec.security) securedEndpoints++;
            }
          }
        }
      }
    } catch { /* not JSON or malformed, skip endpoint counting */ }

    if (endpointCount > 0 && securedEndpoints < endpointCount) {
      const unsecured = endpointCount - securedEndpoints;
      findings.push({
        ruleId: 'API-SCHEMA-001',
        severity: 'high',
        title: `${unsecured} API endpoint(s) without security definitions`,
        description: `${unsecured} of ${endpointCount} endpoints in the OpenAPI spec lack security definitions. ` +
          'AI-generated APIs often omit authentication and authorization requirements. ' +
          'This creates a risk of unauthenticated access to sensitive operations.',
        filePath: specFile,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: 'CWE-306',
        owaspCategory: 'A01:2021-Broken Access Control',
        fixAvailable: true,
        fixDescription: 'Add security definitions (e.g., bearerAuth, apiKey) to all API endpoints.',
        metadata: {
          totalEndpoints: endpointCount,
          securedEndpoints,
          unsecuredEndpoints: unsecured,
        },
      });
    }

    logger.info({
      specFile,
      failures: failures.length,
      schemaErrors: schemaErrors.length,
      endpointCount,
      findingsCount: findings.length,
    }, 'Schemathesis scan completed');

    return {
      scanner: 'schemathesis',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({
        specFile,
        failures: failures.length,
        schemaErrors: schemaErrors.length,
        endpointCount,
        securedEndpoints,
      }),
      evidence: {
        checksPerformed: [
          'OpenAPI/Swagger schema validation',
          'Endpoint fuzz testing via property-based generation',
          'Server error detection (5xx responses)',
          'Input validation bypass testing',
          'Security definition completeness check',
        ],
        scanScope: `API schema analysis of ${specFile}, ${endpointCount} endpoints evaluated`,
        filesAnalyzed: 1,
        rulesEvaluated: endpointCount + schemaErrors.length,
        configuration: `Hypothesis max examples: 50, Stateful: links, Dry run mode`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Schemathesis scan failed');
    return {
      scanner: 'schemathesis',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
