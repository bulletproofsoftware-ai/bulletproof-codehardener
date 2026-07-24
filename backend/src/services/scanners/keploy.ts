import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-keploy');
const SCAN_TARGET = '/scan-target';

// ─── Route definition patterns (per framework) ──────────────────

interface RouteDefinition {
  method: string;       // GET, POST, PUT, DELETE, PATCH
  path: string;         // /api/users, /users/:id, etc.
  filePath: string;     // relative file path
  lineNumber: number;
  hasAuthMiddleware: boolean;
  acceptsBody: boolean;
  rawLine: string;
}

interface TestReference {
  method: string;       // GET, POST, PUT, DELETE, PATCH — or '' if unknown
  path: string;         // URL path tested
  filePath: string;
  lineNumber: number;
  testedStatusCodes: number[];
  rawLine: string;
}

// Route patterns for major frameworks
const ROUTE_PATTERNS: Array<{
  regex: RegExp;
  methodIndex: number;
  pathIndex: number;
  frameworks: string[];
}> = [
  // Express/Koa/Hono: app.get('/path', ...) or router.get('/path', ...)
  {
    regex: /(?:app|router|server)\.(get|post|put|delete|patch|all|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: 1,
    pathIndex: 2,
    frameworks: ['express', 'koa', 'hono'],
  },
  // Express: app.use('/path', router) — mount points
  {
    regex: /(?:app|router)\.use\s*\(\s*['"`](\/[^'"`]+)['"`]/gi,
    methodIndex: -1, // use = ALL methods
    pathIndex: 1,
    frameworks: ['express'],
  },
  // FastAPI/Flask: @app.get('/path') or @app.route('/path', methods=['GET'])
  {
    regex: /@(?:app|router|api)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: 1,
    pathIndex: 2,
    frameworks: ['fastapi', 'flask'],
  },
  // Flask: @app.route('/path', methods=['GET', 'POST'])
  {
    regex: /@(?:app|blueprint|bp)\s*\.route\s*\(\s*['"`]([^'"`]+)['"`](?:.*?methods\s*=\s*\[([^\]]+)\])?/gi,
    methodIndex: 2,
    pathIndex: 1,
    frameworks: ['flask'],
  },
  // Django: path('url/', view), re_path(...)
  {
    regex: /(?:path|re_path)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: -1,
    pathIndex: 1,
    frameworks: ['django'],
  },
  // Spring: @GetMapping("/path"), @PostMapping("/path"), @RequestMapping(value="/path", method=...)
  {
    regex: /@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?['"`]?([^'"`)]+)['"`]?/gi,
    methodIndex: 1,
    pathIndex: 2,
    frameworks: ['spring'],
  },
  {
    regex: /@RequestMapping\s*\(\s*(?:value\s*=\s*)?['"`]([^'"`]+)['"`](?:.*?method\s*=\s*RequestMethod\.(\w+))?/gi,
    methodIndex: 2,
    pathIndex: 1,
    frameworks: ['spring'],
  },
  // Go net/http: http.HandleFunc("/path", handler), r.HandleFunc("/path", ...).Methods("GET")
  {
    regex: /(?:http\.HandleFunc|\.HandleFunc|\.Handle)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: -1,
    pathIndex: 1,
    frameworks: ['go-net-http'],
  },
  // Go gorilla/mux or chi: r.Get("/path", handler), r.Post(...)
  {
    regex: /\.(?:Get|Post|Put|Delete|Patch|Options|Head)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: -1,
    pathIndex: 1,
    frameworks: ['go-chi', 'go-mux'],
  },
  // Go gin: r.GET("/path", handler)
  {
    regex: /\.(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: -1,
    pathIndex: 1,
    frameworks: ['go-gin'],
  },
  // NestJS: @Get('/path'), @Post('/path')
  {
    regex: /@(Get|Post|Put|Delete|Patch)\s*\(\s*['"`]?([^'"`)]*?)['"`]?\s*\)/gi,
    methodIndex: 1,
    pathIndex: 2,
    frameworks: ['nestjs'],
  },
  // Next.js API routes: export async function GET/POST/PUT/DELETE/PATCH
  {
    regex: /export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(/gi,
    methodIndex: 1,
    pathIndex: -1, // path inferred from file path
    frameworks: ['nextjs'],
  },
];

// Auth middleware patterns
const AUTH_MIDDLEWARE_PATTERNS = [
  /(?:auth|authenticate|isAuthenticated|requireAuth|protect|guard|verifyToken|jwt|bearer|passport)/i,
  /(?:middleware\.auth|authMiddleware|requireLogin|ensureLoggedIn|checkAuth)/i,
  /@(?:UseGuards|Authorized|RequiresAuth|login_required|permission_required)/i,
  /(?:IsAuthenticated|AllowAnonymous|Authorize)/i,
];

// Test HTTP request patterns
const TEST_REQUEST_PATTERNS: Array<{
  regex: RegExp;
  methodIndex: number;
  pathIndex: number;
}> = [
  // supertest: request(app).get('/path')
  {
    regex: /(?:request|agent)\s*\([\s\S]*?\)\s*\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: 1,
    pathIndex: 2,
  },
  // fetch/axios in tests: fetch('/path'), axios.get('/path')
  {
    regex: /(?:fetch|axios)\s*(?:\.(get|post|put|delete|patch))?\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: 1,
    pathIndex: 2,
  },
  // Python requests: requests.get('http://...'), client.get('/path')
  {
    regex: /(?:requests|client|self\.client|test_client)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: 1,
    pathIndex: 2,
  },
  // Go httptest: req, _ := http.NewRequest("GET", "/path", ...)
  {
    regex: /http\.NewRequest\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: 1,
    pathIndex: 2,
  },
  // Go httptest shorthand: httptest.NewRequest("GET", "/path", ...)
  {
    regex: /httptest\.NewRequest\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: 1,
    pathIndex: 2,
  },
  // Java MockMvc: mockMvc.perform(get("/path"))
  {
    regex: /\.perform\s*\(\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: 1,
    pathIndex: 2,
  },
  // RestAssured: given()...when().get("/path")
  {
    regex: /\.(?:when|then)\s*\(\s*\)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: 1,
    pathIndex: 2,
  },
  // Generic HTTP method + URL in test files
  {
    regex: /(?:method|Method)\s*[:=]\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`][\s\S]*?(?:url|path|endpoint|uri)\s*[:=]\s*['"`]([^'"`]+)['"`]/gi,
    methodIndex: 1,
    pathIndex: 2,
  },
];

// Status code patterns in test files
const STATUS_CODE_PATTERN = /(?:status|statusCode|status_code|code)\s*(?:\(|===?|==|\.toBe\(|\.toEqual\(|\.to\.equal\(|assert.*?)\s*(\d{3})/gi;
const EXPECT_STATUS_PATTERN = /\.(?:expect|assert|should|to_have_status|assert_status)\s*\(\s*(\d{3})\s*\)/gi;

// Source file extensions
const SOURCE_EXTENSIONS = new Set([
  'ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs',
  'py', 'pyi',
  'go',
  'java', 'kt', 'scala',
  'rb',
  'php',
  'rs',
  'cs',
]);

// Test file patterns
const TEST_FILE_PATTERNS = [
  /\.test\.[jt]sx?$/i,
  /\.spec\.[jt]sx?$/i,
  /_test\.go$/i,
  /test_.*\.py$/i,
  /.*_test\.py$/i,
  /Tests?\.java$/i,
  /Tests?\.kt$/i,
  /_test\.rb$/i,
  /Test\.php$/i,
  /.*_test\.rs$/i,
];

const TEST_DIR_PATTERNS = [
  /\/tests?\//i,
  /\/__tests__\//i,
  /\/spec\//i,
  /\/test_/i,
];

// ─── Helpers ─────────────────────────────────────────────────────

function isTestFile(filePath: string): boolean {
  return TEST_FILE_PATTERNS.some(p => p.test(filePath)) ||
    TEST_DIR_PATTERNS.some(p => p.test(filePath));
}

function isSourceFile(filePath: string): boolean {
  const ext = filePath.split('.').pop()?.toLowerCase() || '';
  return SOURCE_EXTENSIONS.has(ext);
}

function normalizeRoutePath(path: string): string {
  // Normalize route params: /users/:id, /users/{id}, /users/<id> all become /users/:param
  return path
    .replace(/\{[^}]+\}/g, ':param')
    .replace(/<[^>]+>/g, ':param')
    .replace(/:[a-zA-Z_]+/g, ':param')
    .replace(/\/+/g, '/')
    .replace(/\/$/, '') || '/';
}

function normalizeTestPath(path: string): string {
  // Strip host/protocol from test URLs, then normalize params
  let cleaned = path.replace(/^https?:\/\/[^/]+/, '');
  // Replace numeric IDs with :param — /users/123 => /users/:param
  cleaned = cleaned.replace(/\/\d+(?=[/\s?]|$)/g, '/:param');
  return normalizeRoutePath(cleaned);
}

function routeMatchesTest(route: RouteDefinition, test: TestReference): boolean {
  const normalizedRoute = normalizeRoutePath(route.path);
  const normalizedTest = normalizeTestPath(test.path);

  if (normalizedRoute !== normalizedTest) return false;

  // Method match (if test specifies a method)
  if (test.method && route.method !== 'ALL') {
    return test.method.toUpperCase() === route.method.toUpperCase();
  }
  return true;
}

function extractStatusCodes(startLine: number, lines: string[]): number[] {
  const codes: number[] = [];
  // Look within ~30 lines of the test request for status assertions
  const windowEnd = Math.min(startLine + 30, lines.length);
  const window = lines.slice(startLine, windowEnd).join('\n');

  let match: RegExpExecArray | null;

  const patterns = [STATUS_CODE_PATTERN, EXPECT_STATUS_PATTERN];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    while ((match = pattern.exec(window)) !== null) {
      const code = parseInt(match[1]);
      if (code >= 100 && code <= 599) {
        codes.push(code);
      }
    }
  }

  return codes;
}

function hasAuthMiddleware(line: string, surroundingLines: string): boolean {
  const combined = line + ' ' + surroundingLines;
  return AUTH_MIDDLEWARE_PATTERNS.some(p => p.test(combined));
}

// ─── File Discovery ──────────────────────────────────────────────
// Note: exec() here uses only hardcoded paths (SCAN_TARGET constant),
// no user input is interpolated — safe from injection.

async function discoverFiles(): Promise<{ sourceFiles: string[]; testFiles: string[] }> {
  const sourceFiles: string[] = [];
  const testFiles: string[] = [];

  try {
    const { stdout } = await execAsync(
      `find ${SCAN_TARGET} -type f ` +
        `-not -path '*/.git/*' ` +
        `-not -path '*/node_modules/*' ` +
        `-not -path '*/.venv/*' ` +
        `-not -path '*/venv/*' ` +
        `-not -path '*/__pycache__/*' ` +
        `-not -path '*/.next/*' ` +
        `-not -path '*/dist/*' ` +
        `-not -path '*/build/*' ` +
        `-not -path '*/.cache/*' ` +
        `-not -path '*/vendor/*' ` +
        `2>/dev/null | head -50000`,
      { maxBuffer: 20 * 1024 * 1024, timeout: 30000 }
    );

    for (const filePath of stdout.trim().split('\n').filter(Boolean)) {
      if (!isSourceFile(filePath)) continue;

      if (isTestFile(filePath)) {
        testFiles.push(filePath);
      } else {
        sourceFiles.push(filePath);
      }
    }
  } catch (error) {
    logger.warn({ error }, 'File discovery failed');
  }

  return { sourceFiles, testFiles };
}

// ─── Route Extraction ────────────────────────────────────────────

async function extractRoutes(sourceFiles: string[]): Promise<RouteDefinition[]> {
  const routes: RouteDefinition[] = [];

  for (const filePath of sourceFiles) {
    try {
      const content = await readFile(filePath, 'utf-8');
      const lines = content.split('\n');
      const relativePath = filePath.replace(`${SCAN_TARGET}/`, '');

      for (const routePattern of ROUTE_PATTERNS) {
        routePattern.regex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = routePattern.regex.exec(content)) !== null) {
          const method = routePattern.methodIndex === -1
            ? 'ALL'
            : (match[routePattern.methodIndex] || 'ALL').toUpperCase();

          let path: string;
          if (routePattern.pathIndex === -1) {
            // Next.js: infer from file path (e.g., app/api/users/route.ts => /api/users)
            path = relativePath
              .replace(/^(?:src\/)?app/, '')
              .replace(/\/route\.[jt]sx?$/, '')
              .replace(/\/page\.[jt]sx?$/, '') || '/';
          } else {
            path = match[routePattern.pathIndex] || '/';
          }

          // Skip mount points that are clearly middleware, not routes
          if (path === '/' && method === 'ALL') continue;

          // Determine line number from match index
          const beforeMatch = content.substring(0, match.index);
          const lineNumber = beforeMatch.split('\n').length;

          // Check for auth middleware in surrounding context (5 lines around)
          const startCtx = Math.max(0, lineNumber - 5);
          const endCtx = Math.min(lines.length, lineNumber + 5);
          const surroundingLines = lines.slice(startCtx, endCtx).join('\n');
          const lineContent = lines[lineNumber - 1] || '';

          // Determine if body-accepting method
          const acceptsBody = ['POST', 'PUT', 'PATCH', 'ALL'].includes(method);

          routes.push({
            method: method === 'ALL' ? 'ALL' : method,
            path,
            filePath: relativePath,
            lineNumber,
            hasAuthMiddleware: hasAuthMiddleware(lineContent, surroundingLines),
            acceptsBody,
            rawLine: lineContent.trim(),
          });
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  return routes;
}

// ─── Test Reference Extraction ───────────────────────────────────

async function extractTestReferences(testFiles: string[]): Promise<TestReference[]> {
  const refs: TestReference[] = [];

  for (const filePath of testFiles) {
    try {
      const content = await readFile(filePath, 'utf-8');
      const lines = content.split('\n');
      const relativePath = filePath.replace(`${SCAN_TARGET}/`, '');

      for (const testPattern of TEST_REQUEST_PATTERNS) {
        testPattern.regex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = testPattern.regex.exec(content)) !== null) {
          const method = (match[testPattern.methodIndex] || '').toUpperCase();
          const path = match[testPattern.pathIndex] || '';

          if (!path || path.length > 200) continue;

          const beforeMatch = content.substring(0, match.index);
          const lineNumber = beforeMatch.split('\n').length;

          // Extract status codes tested near this request
          const testedStatusCodes = extractStatusCodes(lineNumber - 1, lines);

          refs.push({
            method: method || '',
            path,
            filePath: relativePath,
            lineNumber,
            testedStatusCodes,
            rawLine: lines[lineNumber - 1]?.trim() || '',
          });
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  return refs;
}

// ─── OpenAPI Spec Parsing ────────────────────────────────────────

interface SpecEndpoint {
  method: string;
  path: string;
  hasAuth: boolean;
}

const SPEC_CANDIDATES = [
  'openapi.yaml', 'openapi.yml', 'openapi.json',
  'swagger.yaml', 'swagger.yml', 'swagger.json',
  'docs/openapi.yaml', 'docs/openapi.yml', 'docs/openapi.json',
  'docs/swagger.yaml', 'docs/swagger.yml', 'docs/swagger.json',
  'api/openapi.yaml', 'api/openapi.yml', 'api/openapi.json',
  'spec/openapi.yaml', 'spec/openapi.yml', 'spec/openapi.json',
];

async function parseOpenAPISpec(): Promise<{ specFile: string; endpoints: SpecEndpoint[] } | null> {
  for (const candidate of SPEC_CANDIDATES) {
    const fullPath = `${SCAN_TARGET}/${candidate}`;
    if (!existsSync(fullPath)) continue;

    try {
      const content = await readFile(fullPath, 'utf-8');
      if (!content.trim()) continue;

      // Only parse JSON specs for reliability (YAML would need a dependency)
      if (candidate.endsWith('.json')) {
        const spec = JSON.parse(content);
        const endpoints: SpecEndpoint[] = [];
        const globalSecurity = !!spec.security;

        for (const [path, pathObj] of Object.entries(spec.paths || {}) as [string, any][]) {
          for (const method of ['get', 'post', 'put', 'delete', 'patch']) {
            if (pathObj[method]) {
              endpoints.push({
                method: method.toUpperCase(),
                path,
                hasAuth: !!(pathObj[method].security || globalSecurity),
              });
            }
          }
        }

        if (endpoints.length > 0) {
          return { specFile: candidate, endpoints };
        }
      }
    } catch {
      // Not parseable, skip
    }
  }
  return null;
}

// ─── Scanner Entry Point ─────────────────────────────────────────

export async function runKeploy(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Keploy requires a target URL for live API test recording/replay
    // In static analysis mode we still run route coverage checks without it
    if (jobData.targetUrl) {
      logger.info({ targetUrl: jobData.targetUrl }, 'Target URL available for Keploy');
    }

    // 1. Discover source and test files
    const { sourceFiles, testFiles } = await discoverFiles();

    if (sourceFiles.length === 0) {
      logger.info('No source files found');
      return {
        scanner: 'keploy',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No source files detected in the scan target. Ensure your code is in the project root.',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No source files found in scan target',
      };
    }

    // 2. Extract route definitions from source files
    const routes = await extractRoutes(sourceFiles);

    if (routes.length === 0 && testFiles.length === 0) {
      logger.info('No API routes or test files found');
      return {
        scanner: 'keploy',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No API route definitions or test files detected. Keploy analyzes HTTP endpoint test coverage.',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No API routes or test files detected',
      };
    }

    // 3. Extract test references from test files
    const testRefs = await extractTestReferences(testFiles);

    // 4. Parse OpenAPI spec if present
    const specData = await parseOpenAPISpec();

    let rulesEvaluated = 0;

    // ── KEPLOY-001: Untested API endpoints ──────────────────────

    // Deduplicate routes by normalized path+method
    const seenRoutes = new Set<string>();
    const uniqueRoutes = routes.filter(r => {
      const key = `${r.method}:${normalizeRoutePath(r.path)}`;
      if (seenRoutes.has(key)) return false;
      seenRoutes.add(key);
      return true;
    });

    for (const route of uniqueRoutes) {
      rulesEvaluated++;
      const hasCoveringTest = testRefs.some(test => routeMatchesTest(route, test));

      if (!hasCoveringTest) {
        findings.push({
          ruleId: 'KEPLOY-001',
          severity: 'high',
          title: `Untested API endpoint: ${route.method} ${route.path}`,
          description: `The endpoint ${route.method} ${route.path} is defined in the codebase but has no corresponding API test. ` +
            'Untested endpoints are a significant risk in AI-generated codebases because the AI may produce handlers ' +
            'with incorrect logic, missing input validation, or broken error handling that goes undetected without tests.',
          filePath: route.filePath,
          lineNumber: route.lineNumber,
          columnNumber: null,
          codeSnippet: route.rawLine || null,
          cweId: 'CWE-1164',
          owaspCategory: 'A04:2021-Insecure Design',
          fixAvailable: true,
          fixDescription: `Add an API test for ${route.method} ${route.path} that validates the response status, body structure, and error handling.`,
          metadata: {
            method: route.method,
            endpoint: route.path,
            rule: 'untested-endpoint',
          },
        });
      }
    }

    // ── KEPLOY-002: Missing error response tests ────────────────

    for (const route of uniqueRoutes) {
      rulesEvaluated++;
      const coveringTests = testRefs.filter(test => routeMatchesTest(route, test));

      if (coveringTests.length === 0) continue; // Already flagged by KEPLOY-001

      const allTestedCodes = coveringTests.flatMap(t => t.testedStatusCodes);
      const hasHappyPath = allTestedCodes.some(c => c >= 200 && c < 300);
      const hasErrorPath = allTestedCodes.some(c => c >= 400);

      if (hasHappyPath && !hasErrorPath) {
        findings.push({
          ruleId: 'KEPLOY-002',
          severity: 'medium',
          title: `Missing error response tests: ${route.method} ${route.path}`,
          description: `Tests for ${route.method} ${route.path} only validate success responses (2xx) but never test error scenarios (4xx/5xx). ` +
            'Error handling in AI-generated code is frequently incomplete or entirely absent. Without error path tests, ' +
            'missing validation, broken auth checks, and unhandled exceptions may reach production.',
          filePath: coveringTests[0].filePath,
          lineNumber: coveringTests[0].lineNumber,
          columnNumber: null,
          codeSnippet: coveringTests[0].rawLine || null,
          cweId: 'CWE-394',
          owaspCategory: 'A04:2021-Insecure Design',
          fixAvailable: true,
          fixDescription: `Add tests for ${route.method} ${route.path} that verify 400 (bad input), 401/403 (unauthorized), 404 (not found), and 500 (server error) responses.`,
          metadata: {
            method: route.method,
            endpoint: route.path,
            testedStatusCodes: allTestedCodes,
            rule: 'missing-error-tests',
          },
        });
      }
    }

    // ── KEPLOY-003: No request validation tests ─────────────────

    for (const route of uniqueRoutes) {
      if (!route.acceptsBody) continue;
      rulesEvaluated++;

      const coveringTests = testRefs.filter(test => routeMatchesTest(route, test));

      if (coveringTests.length === 0) continue; // Already flagged by KEPLOY-001

      // Check if any test sends a body AND checks for 400/422
      const allTestedCodes = coveringTests.flatMap(t => t.testedStatusCodes);
      const hasValidationTest = allTestedCodes.some(c => c === 400 || c === 422);

      if (!hasValidationTest) {
        findings.push({
          ruleId: 'KEPLOY-003',
          severity: 'medium',
          title: `No request validation tests: ${route.method} ${route.path}`,
          description: `The endpoint ${route.method} ${route.path} accepts request bodies but no test sends invalid or malformed data to verify input validation. ` +
            'AI-generated handlers often accept any input without validation, leading to data corruption, injection attacks, ' +
            'and runtime crashes when malformed data reaches business logic.',
          filePath: route.filePath,
          lineNumber: route.lineNumber,
          columnNumber: null,
          codeSnippet: route.rawLine || null,
          cweId: 'CWE-20',
          owaspCategory: 'A03:2021-Injection',
          fixAvailable: true,
          fixDescription: `Add tests for ${route.method} ${route.path} that send invalid payloads (missing required fields, wrong types, oversized values) and verify 400/422 responses.`,
          metadata: {
            method: route.method,
            endpoint: route.path,
            rule: 'missing-validation-tests',
          },
        });
      }
    }

    // ── KEPLOY-004: Missing auth test coverage ──────────────────

    for (const route of uniqueRoutes) {
      if (!route.hasAuthMiddleware) continue;
      rulesEvaluated++;

      const coveringTests = testRefs.filter(test => routeMatchesTest(route, test));

      if (coveringTests.length === 0) continue; // Already flagged by KEPLOY-001

      const allTestedCodes = coveringTests.flatMap(t => t.testedStatusCodes);
      const hasUnauthorizedTest = allTestedCodes.some(c => c === 401 || c === 403);

      if (!hasUnauthorizedTest) {
        findings.push({
          ruleId: 'KEPLOY-004',
          severity: 'high',
          title: `Missing auth rejection test: ${route.method} ${route.path}`,
          description: `The endpoint ${route.method} ${route.path} uses authentication middleware but no test verifies that unauthorized requests are rejected (401/403). ` +
            'Without explicit auth rejection tests, broken authentication logic may silently pass, allowing unauthenticated access to protected resources.',
          filePath: route.filePath,
          lineNumber: route.lineNumber,
          columnNumber: null,
          codeSnippet: route.rawLine || null,
          cweId: 'CWE-306',
          owaspCategory: 'A01:2021-Broken Access Control',
          fixAvailable: true,
          fixDescription: `Add a test for ${route.method} ${route.path} that sends a request without valid credentials and asserts a 401 or 403 response.`,
          metadata: {
            method: route.method,
            endpoint: route.path,
            rule: 'missing-auth-tests',
          },
        });
      }
    }

    // ── KEPLOY-005: API contract gaps (OpenAPI spec vs tests) ───

    if (specData) {
      const { specFile, endpoints: specEndpoints } = specData;

      for (const specEndpoint of specEndpoints) {
        rulesEvaluated++;
        const hasCoveringTest = testRefs.some(test => {
          const normalizedSpec = normalizeRoutePath(specEndpoint.path);
          const normalizedTest = normalizeTestPath(test.path);
          if (normalizedSpec !== normalizedTest) return false;
          if (test.method) return test.method.toUpperCase() === specEndpoint.method;
          return true;
        });

        if (!hasCoveringTest) {
          findings.push({
            ruleId: 'KEPLOY-005',
            severity: 'medium',
            title: `API contract gap: ${specEndpoint.method} ${specEndpoint.path} defined in spec but untested`,
            description: `The endpoint ${specEndpoint.method} ${specEndpoint.path} is defined in the OpenAPI specification (${specFile}) but has no corresponding API test. ` +
              'Spec-defined endpoints without tests mean the contract is unverified — the implementation may drift from the spec, ' +
              'returning wrong status codes, incorrect response schemas, or missing required fields.',
            filePath: specFile,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: 'CWE-1164',
            owaspCategory: 'A04:2021-Insecure Design',
            fixAvailable: true,
            fixDescription: `Add API tests for ${specEndpoint.method} ${specEndpoint.path} that validate the response matches the OpenAPI spec contract.`,
            metadata: {
              method: specEndpoint.method,
              endpoint: specEndpoint.path,
              specFile,
              rule: 'spec-test-gap',
            },
          });
        }
      }

      // Also check for tests hitting endpoints NOT in the spec
      const specPaths = new Set(specEndpoints.map(e => `${e.method}:${normalizeRoutePath(e.path)}`));

      for (const testRef of testRefs) {
        if (!testRef.method || !testRef.path) continue;
        rulesEvaluated++;
        const testKey = `${testRef.method.toUpperCase()}:${normalizeTestPath(testRef.path)}`;

        // Skip if path is clearly not an API path
        if (!testRef.path.startsWith('/')) continue;

        const inSpec = specPaths.has(testKey) ||
          // Also check without method for flexible matching
          specEndpoints.some(e => normalizeRoutePath(e.path) === normalizeTestPath(testRef.path));

        if (!inSpec) {
          findings.push({
            ruleId: 'KEPLOY-005',
            severity: 'medium',
            title: `API contract gap: ${testRef.method} ${testRef.path} tested but not in spec`,
            description: `A test exercises ${testRef.method} ${testRef.path} but this endpoint is not defined in the OpenAPI specification (${specFile}). ` +
              'Either the spec is outdated and needs updating, or the test is hitting a dead/removed endpoint.',
            filePath: testRef.filePath,
            lineNumber: testRef.lineNumber,
            columnNumber: null,
            codeSnippet: testRef.rawLine || null,
            cweId: 'CWE-1164',
            owaspCategory: 'A04:2021-Insecure Design',
            fixAvailable: true,
            fixDescription: `Either add ${testRef.method} ${testRef.path} to the OpenAPI spec or remove the test if the endpoint no longer exists.`,
            metadata: {
              method: testRef.method,
              endpoint: testRef.path,
              specFile,
              rule: 'test-not-in-spec',
            },
          });
        }
      }
    }

    // Summary stats
    const untestedCount = findings.filter(f => f.ruleId === 'KEPLOY-001').length;
    const missingErrorCount = findings.filter(f => f.ruleId === 'KEPLOY-002').length;
    const missingValidationCount = findings.filter(f => f.ruleId === 'KEPLOY-003').length;
    const missingAuthCount = findings.filter(f => f.ruleId === 'KEPLOY-004').length;
    const contractGapCount = findings.filter(f => f.ruleId === 'KEPLOY-005').length;

    logger.info({
      routes: uniqueRoutes.length,
      testFiles: testFiles.length,
      testRefs: testRefs.length,
      untestedCount,
      missingErrorCount,
      missingValidationCount,
      missingAuthCount,
      contractGapCount,
      findingsCount: findings.length,
    }, 'Keploy API test coverage analysis completed');

    return {
      scanner: 'keploy',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({
        routesDetected: uniqueRoutes.length,
        testFilesFound: testFiles.length,
        testReferencesFound: testRefs.length,
        specEndpoints: specData?.endpoints.length || 0,
        untestedEndpoints: untestedCount,
        missingErrorTests: missingErrorCount,
        missingValidationTests: missingValidationCount,
        missingAuthTests: missingAuthCount,
        contractGaps: contractGapCount,
      }, null, 2),
      evidence: {
        checksPerformed: [
          'API endpoint discovery (Express, FastAPI, Flask, Django, Spring, Go, NestJS, Next.js)',
          'Test file HTTP request pattern matching',
          'Untested endpoint cross-referencing (KEPLOY-001)',
          'Error response test coverage analysis (KEPLOY-002)',
          'Request validation test coverage analysis (KEPLOY-003)',
          'Authentication test coverage analysis (KEPLOY-004)',
          'OpenAPI/Swagger contract gap detection (KEPLOY-005)',
        ],
        scanScope: `Analyzed ${uniqueRoutes.length} API routes across ${sourceFiles.length} source files, ${testRefs.length} test references across ${testFiles.length} test files` +
          (specData ? `, ${specData.endpoints.length} OpenAPI spec endpoints` : ''),
        filesAnalyzed: sourceFiles.length + testFiles.length,
        rulesEvaluated,
        configuration: 'Static analysis mode (regex-based pattern matching, no AST parsing)',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Keploy API test coverage analysis failed');
    return {
      scanner: 'keploy',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
