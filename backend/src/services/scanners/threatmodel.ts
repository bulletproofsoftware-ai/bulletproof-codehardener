import { open, readdir } from 'fs/promises';
import { join, extname } from 'path';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const logger = createLogger('scanner-threatmodel');
const SCAN_TARGET = '/scan-target';

// File extensions to analyze for threat patterns
const SOURCE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py',
  '.go',
  '.java',
  '.rb',
  '.php',
]);

// Directories to skip during recursive traversal
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.venv', 'venv', '__pycache__',
  '.next', 'dist', 'build', '.cache', '.tox', 'vendor',
  'coverage', '.nyc_output', '.pytest_cache',
]);

// Maximum file size to analyze (1 MB)
const MAX_FILE_SIZE = 1024 * 1024;

// ─── STRIDE Threat Categories ────────────────────────────────────

interface ThreatRule {
  id: string;
  category: 'Spoofing' | 'Tampering' | 'Repudiation' | 'Information Disclosure' | 'Denial of Service' | 'Elevation of Privilege';
  severity: Severity;
  cweId: string;
  title: string;
  description: string;
  fixDescription: string;
  /** Patterns to match — each entry is { regex, context } where context gives human-readable explanation */
  patterns: Array<{ regex: RegExp; context: string }>;
}

const THREAT_RULES: ThreatRule[] = [
  // ─── Spoofing (S) ─────────────────────────────────────────────
  {
    id: 'STRIDE-S-001',
    category: 'Spoofing',
    severity: 'high',
    cweId: 'CWE-287',
    title: 'Endpoint without authentication check',
    description:
      'A route handler was detected without apparent authentication middleware or checks. ' +
      'Without authentication, any client can impersonate a legitimate user. ' +
      'This maps to the STRIDE Spoofing category (CWE-287: Improper Authentication).',
    fixDescription:
      'Add authentication middleware to all non-public routes. Use established auth libraries ' +
      '(passport, express-jwt, Flask-Login) rather than custom implementations. ' +
      'Verify JWT signatures with jwt.verify(), never just jwt.decode().',
    patterns: [
      // Express/Koa routes without auth-like middleware in handler chain
      {
        regex: /(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`][^'"`]+['"`]\s*,\s*(?:async\s+)?\(?(?:req|ctx)\b/gi,
        context: 'Route handler without auth middleware in the handler chain',
      },
      // jwt.decode used instead of jwt.verify
      {
        regex: /jwt\.decode\s*\(/gi,
        context: 'JWT decoded without signature verification — use jwt.verify() instead',
      },
      // Cookie without httpOnly
      {
        regex: /httpOnly\s*:\s*false/gi,
        context: 'Cookie set without httpOnly flag — vulnerable to XSS session theft',
      },
      // Cookie without secure flag
      {
        regex: /secure\s*:\s*false/gi,
        context: 'Cookie set without secure flag — transmitted over plaintext HTTP',
      },
      // Python Flask route without login_required
      {
        regex: /@app\.route\s*\([^)]+\)\s*\n\s*def\s+(?!login|register|health|public|static)/gi,
        context: 'Flask route without @login_required decorator',
      },
    ],
  },

  // ─── Tampering (T) ────────────────────────────────────────────
  {
    id: 'STRIDE-T-001',
    category: 'Tampering',
    severity: 'high',
    cweId: 'CWE-20',
    title: 'Input used without validation',
    description:
      'User-supplied input is consumed without apparent validation or sanitization. ' +
      'Unvalidated input can lead to SQL injection, command injection, and data corruption. ' +
      'This maps to the STRIDE Tampering category (CWE-20: Improper Input Validation).',
    fixDescription:
      'Validate all user input using schema validators (zod, joi, pydantic, marshmallow). ' +
      'Use parameterized queries for database access. Never use string concatenation to build SQL queries.',
    patterns: [
      // SQL string concatenation
      {
        regex: /(?:query|execute|raw|sql)\s*\(\s*['"`].*\$\{.*req\b/gi,
        context: 'SQL query built with template literal containing request data',
      },
      {
        regex: /(?:query|execute|raw|sql)\s*\(\s*['"`].*\+\s*(?:req\.(?:body|query|params)|request\.(?:form|args|json))/gi,
        context: 'SQL query built with string concatenation of request data',
      },
      // Direct use of req.body in database operations without validation
      {
        regex: /\.(?:create|insert|update|save|findOne|findById)\s*\(\s*req\.body\b/gi,
        context: 'Request body passed directly to database operation without schema validation',
      },
      // Python f-string/format in SQL
      {
        regex: /cursor\.execute\s*\(\s*f['"]/gi,
        context: 'Python SQL query using f-string — vulnerable to SQL injection',
      },
      {
        regex: /cursor\.execute\s*\(\s*['"].*\.format\s*\(/gi,
        context: 'Python SQL query using .format() — vulnerable to SQL injection',
      },
      // JSON.parse of request body without schema validation (raw usage)
      {
        regex: /JSON\.parse\s*\(\s*req\.body\b/gi,
        context: 'Parsing request body as JSON without schema validation',
      },
      // Go sql.Query with fmt.Sprintf
      {
        regex: /(?:db|tx)\.(?:Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf/gi,
        context: 'Go SQL query built with fmt.Sprintf — use parameterized queries instead',
      },
    ],
  },

  // ─── Repudiation (R) ──────────────────────────────────────────
  {
    id: 'STRIDE-R-001',
    category: 'Repudiation',
    severity: 'medium',
    cweId: 'CWE-778',
    title: 'Security-critical operation without audit logging',
    description:
      'A security-sensitive operation (authentication, data modification, admin action) was detected ' +
      'without corresponding audit logging. Without audit trails, malicious actions cannot be traced back ' +
      'to their source. This maps to the STRIDE Repudiation category (CWE-778: Insufficient Logging).',
    fixDescription:
      'Add structured audit logging for all authentication events, data modifications, and admin operations. ' +
      'Log the who (user ID), what (action), when (timestamp), and outcome (success/failure). ' +
      'Use a centralized logging system with tamper-evident storage.',
    patterns: [
      // Login/auth handlers without log/audit statements
      {
        regex: /(?:async\s+)?(?:function\s+)?(?:login|authenticate|signIn|sign_in)\s*\(/gi,
        context: 'Login/authentication handler — verify audit logging is present',
      },
      // DELETE endpoints
      {
        regex: /(?:app|router)\.delete\s*\(\s*['"`][^'"`]+['"`]/gi,
        context: 'DELETE endpoint — should log deletion events for audit trail',
      },
      // Role/permission changes
      {
        regex: /(?:role|permission|access|privilege)\s*(?:=|:)\s*(?:req\.body|request\.(?:form|json))/gi,
        context: 'Role/permission change from user input — must be audit logged',
      },
      // Password reset without logging
      {
        regex: /(?:async\s+)?(?:function\s+)?(?:resetPassword|reset_password|changePassword|change_password)\s*\(/gi,
        context: 'Password change handler — verify audit logging is present',
      },
    ],
  },

  // ─── Information Disclosure (I) ───────────────────────────────
  {
    id: 'STRIDE-I-001',
    category: 'Information Disclosure',
    severity: 'high',
    cweId: 'CWE-209',
    title: 'Error message leaking internal details',
    description:
      'Error handling code appears to expose internal implementation details (stack traces, ' +
      'database errors, file paths) in responses to clients. This information aids attackers ' +
      'in reconnaissance. This maps to the STRIDE Information Disclosure category ' +
      '(CWE-209: Generation of Error Message Containing Sensitive Information).',
    fixDescription:
      'Return generic error messages to clients. Log detailed errors server-side only. ' +
      'Use error handling middleware that sanitizes responses in production. ' +
      'Never send raw exception objects, stack traces, or database error messages to clients.',
    patterns: [
      // Sending raw error/exception in response
      {
        regex: /catch\s*\(\s*\w+\s*\)\s*\{[^}]*res\.(?:send|json|status\([^)]*\)\.(?:send|json))\s*\(\s*(?:e|err|error)\b/gis,
        context: 'Raw error object sent in HTTP response — leaks internals',
      },
      {
        regex: /\.send\s*\(\s*(?:e|err|error)\.(?:message|stack)\s*\)/gi,
        context: 'Error message/stack trace sent directly in response',
      },
      // Logging sensitive data
      {
        regex: /console\.log\s*\(.*(?:password|secret|token|apiKey|api_key|credentials|ssn|credit.?card)/gi,
        context: 'Sensitive data logged to console',
      },
      // Debug mode enabled in production config
      {
        regex: /DEBUG\s*=\s*(?:True|true|1|'true'|"true")/gi,
        context: 'Debug mode enabled — may expose internals in production',
      },
      // Stack trace in response
      {
        regex: /\.(?:send|json|render)\s*\([^)]*\.stack\b/gi,
        context: 'Stack trace sent in HTTP response',
      },
      // Python traceback in response
      {
        regex: /traceback\.format_exc\s*\(\)/gi,
        context: 'Python traceback included — may leak in response',
      },
    ],
  },

  // ─── Denial of Service (D) ────────────────────────────────────
  {
    id: 'STRIDE-D-001',
    category: 'Denial of Service',
    severity: 'medium',
    cweId: 'CWE-400',
    title: 'Missing resource consumption limits',
    description:
      'Code patterns suggest missing rate limiting, unbounded queries, or uncontrolled resource ' +
      'consumption. Without limits, attackers can exhaust server resources. ' +
      'This maps to the STRIDE Denial of Service category (CWE-400: Uncontrolled Resource Consumption).',
    fixDescription:
      'Add rate limiting middleware (express-rate-limit, flask-limiter). Set pagination limits on all ' +
      'database queries. Restrict file upload sizes. Audit regex patterns for ReDoS vulnerability ' +
      '(avoid nested quantifiers like (a+)+).',
    patterns: [
      // Database queries without LIMIT
      {
        regex: /\.find\s*\(\s*(?:\{[^}]*\})?\s*\)\s*(?!.*\.(?:limit|take|first|findFirst|paginate))/gi,
        context: 'Database query without .limit() — may return unbounded results',
      },
      // File upload without size limits
      {
        regex: /(?:multer|upload|formidable)\s*\(\s*(?:\{\s*\}|\))/gi,
        context: 'File upload middleware without size limits configured',
      },
      // ReDoS-vulnerable regex patterns (nested quantifiers)
      {
        regex: /new RegExp\s*\([^)]*[+*]\s*\)\s*[+*]/gi,
        context: 'Regex with nested quantifiers — vulnerable to ReDoS',
      },
      {
        regex: /\/(?:[^/]*\([^)]*[+*][^)]*\)[+*][^/]*)\//g,
        context: 'Regex literal with nested quantifiers — vulnerable to ReDoS',
      },
      // request.get without timeout
      {
        regex: /(?:axios|fetch|request|http\.get|urllib)\s*\([^)]*\)\s*(?!.*timeout)/gi,
        context: 'HTTP request without timeout — may hang indefinitely',
      },
    ],
  },

  // ─── Elevation of Privilege (E) ───────────────────────────────
  {
    id: 'STRIDE-E-001',
    category: 'Elevation of Privilege',
    severity: 'critical',
    cweId: 'CWE-269',
    title: 'Authorization based on client-provided data',
    description:
      'Authorization decisions appear to rely on client-supplied values (request body role, ' +
      'client-provided user ID for resource access). Attackers can modify these values to ' +
      'escalate privileges. This maps to the STRIDE Elevation of Privilege category ' +
      '(CWE-269: Improper Privilege Management).',
    fixDescription:
      'Never trust client-provided role or permission data. Derive user identity and roles from ' +
      'server-side session or verified JWT. Use middleware to verify roles before route handlers. ' +
      'Implement proper ownership checks (IDOR prevention) using server-side user context.',
    patterns: [
      // Role from request body used in authorization
      {
        regex: /req\.body\.(?:role|isAdmin|is_admin|permission|access_level|userType|user_type)\b/gi,
        context: 'Authorization role taken from request body — client can set arbitrary role',
      },
      // Admin check based on client data
      {
        regex: /(?:req\.body|request\.(?:form|json))\[?\s*['"`]?(?:role|isAdmin|is_admin)['"`]?\]?\s*===?\s*['"`]admin['"`]/gi,
        context: 'Admin check based on client-provided value — trivially bypassed',
      },
      // Direct object reference without ownership check
      {
        regex: /(?:findById|find_by_id|get)\s*\(\s*req\.params\.(?:id|userId|user_id)\b/gi,
        context: 'Direct object reference from URL parameter — potential IDOR vulnerability',
      },
      // Admin routes without role middleware
      {
        regex: /(?:app|router)\.(?:get|post|put|delete)\s*\(\s*['"`]\/admin\b[^'"`]*['"`]\s*,\s*(?:async\s+)?\(?(?:req|ctx)\b/gi,
        context: 'Admin route without role verification middleware',
      },
      // Python: no permission check on admin view
      {
        regex: /@app\.route\s*\(\s*['"]\/admin[^'"]*['"]/gi,
        context: 'Flask admin route — verify permission decorators are applied',
      },
      // Setting user role without verification
      {
        regex: /\.(?:update|set)\s*\(\s*\{[^}]*role\s*:\s*req\.body/gi,
        context: 'User role updated from request body — must verify requesting user has permission',
      },
    ],
  },
];

// ─── File Discovery ──────────────────────────────────────────────

async function collectSourceFiles(dir: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(currentDir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(currentDir, { withFileTypes: true });
    } catch {
      return; // Permission denied or directory doesn't exist
    }

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          await walk(join(currentDir, entry.name));
        }
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (SOURCE_EXTENSIONS.has(ext)) {
          files.push(join(currentDir, entry.name));
        }
      }
    }
  }

  await walk(dir);
  return files;
}

// ─── Pattern Matching Engine ─────────────────────────────────────

interface MatchResult {
  rule: ThreatRule;
  filePath: string;
  lineNumber: number;
  codeSnippet: string;
  patternContext: string;
}

function analyzeFileContent(
  content: string,
  filePath: string,
  rules: ThreatRule[],
): MatchResult[] {
  const results: MatchResult[] = [];
  const lines = content.split('\n');

  for (const rule of rules) {
    for (const pattern of rule.patterns) {
      // Reset regex state for each file (global flag)
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        // Calculate the line number from the character offset
        const upToMatch = content.slice(0, match.index);
        const lineNumber = upToMatch.split('\n').length;

        // Extract the code snippet (matched line plus one line of context on each side)
        const lineIdx = lineNumber - 1;
        const snippetStart = Math.max(0, lineIdx - 1);
        const snippetEnd = Math.min(lines.length, lineIdx + 2);
        const codeSnippet = lines.slice(snippetStart, snippetEnd).join('\n');

        results.push({
          rule,
          filePath: filePath.replace(`${SCAN_TARGET}/`, ''),
          lineNumber,
          codeSnippet: codeSnippet.slice(0, 500),
          patternContext: pattern.context,
        });

        // Prevent infinite loop on zero-length matches
        if (match[0].length === 0) {
          regex.lastIndex++;
        }
      }
    }
  }

  return results;
}

// ─── Deduplication ───────────────────────────────────────────────

/**
 * Deduplicate findings that match the same rule on the same line.
 * Multiple patterns in a rule can flag the same line; keep only the first match.
 */
function deduplicateMatches(matches: MatchResult[]): MatchResult[] {
  const seen = new Set<string>();
  return matches.filter(m => {
    const key = `${m.rule.id}:${m.filePath}:${m.lineNumber}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── Scanner Entry Point ─────────────────────────────────────────

export async function runThreatModel(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Discover source files recursively
    const sourceFiles = await collectSourceFiles(SCAN_TARGET);

    if (sourceFiles.length === 0) {
      logger.info('No source files found for STRIDE threat analysis');
      return {
        scanner: 'threatmodel',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No source files found matching supported extensions',
        evidence: {
          checksPerformed: ['File discovery'],
          scanScope: 'No source files found in scan target',
          filesAnalyzed: 0,
          rulesEvaluated: 0,
        },
      };
    }

    logger.info({ fileCount: sourceFiles.length }, 'Starting STRIDE threat model analysis');

    let allMatches: MatchResult[] = [];
    let filesAnalyzed = 0;
    let filesSkipped = 0;

    for (const filePath of sourceFiles) {
      try {
        // Open once and size the file through the descriptor. stat()ing the
        // path and then readFile()ing it resolves the path twice, so the bytes
        // read are not guaranteed to be the bytes that were size-checked —
        // the MAX_FILE_SIZE guard could be walked straight past
        // (CodeQL js/file-system-race).
        const handle = await open(filePath, 'r');
        let content: string | null = null;

        try {
          const { size } = await handle.stat();
          if (size <= MAX_FILE_SIZE) {
            content = await handle.readFile('utf-8');
          }
        } finally {
          await handle.close();
        }

        // Skip oversized files
        if (content === null) {
          filesSkipped++;
          continue;
        }

        filesAnalyzed++;

        const matches = analyzeFileContent(content, filePath, THREAT_RULES);
        allMatches.push(...matches);
      } catch (error) {
        logger.debug({ filePath, error }, 'Failed to read file — skipping');
        filesSkipped++;
      }
    }

    // Deduplicate matches (same rule + same file + same line)
    allMatches = deduplicateMatches(allMatches);

    // Convert matches to normalized findings
    for (const match of allMatches) {
      findings.push({
        ruleId: match.rule.id,
        severity: match.rule.severity,
        title: `[${match.rule.category}] ${match.rule.title}`,
        description: `${match.rule.description}\n\nDetected pattern: ${match.patternContext}`,
        filePath: match.filePath,
        lineNumber: match.lineNumber,
        columnNumber: null,
        codeSnippet: match.codeSnippet,
        cweId: match.rule.cweId,
        owaspCategory: mapStrideToOwasp(match.rule.category),
        fixAvailable: true,
        fixDescription: match.rule.fixDescription,
        metadata: {
          strideCategory: match.rule.category,
          strideLetter: match.rule.category[0],
          patternContext: match.patternContext,
          analysisType: 'static-regex',
        },
      });
    }

    // Aggregate category counts for summary
    const categoryCounts: Record<string, number> = {};
    for (const match of allMatches) {
      categoryCounts[match.rule.category] = (categoryCounts[match.rule.category] || 0) + 1;
    }

    const totalRulesEvaluated = THREAT_RULES.reduce(
      (sum, rule) => sum + rule.patterns.length,
      0,
    );

    logger.info(
      {
        filesAnalyzed,
        filesSkipped,
        totalFindings: findings.length,
        categoryCounts,
      },
      'STRIDE threat model analysis completed',
    );

    return {
      scanner: 'threatmodel',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({
        filesAnalyzed,
        filesSkipped,
        totalFindings: findings.length,
        byCategory: categoryCounts,
      }, null, 2),
      evidence: {
        checksPerformed: [
          'Spoofing: Authentication bypass detection (missing auth middleware, JWT misuse, insecure cookies)',
          'Tampering: Input validation analysis (SQL injection, unvalidated input, template injection)',
          'Repudiation: Audit logging verification (auth events, data modifications, admin actions)',
          'Information Disclosure: Error handling analysis (stack trace leaks, sensitive data logging, debug mode)',
          'Denial of Service: Resource limit detection (unbounded queries, upload limits, ReDoS patterns)',
          'Elevation of Privilege: Authorization analysis (client-controlled roles, IDOR, missing role checks)',
        ],
        scanScope: `STRIDE analysis of ${filesAnalyzed} source files across ${sourceFiles.length} discovered files`,
        filesAnalyzed,
        rulesEvaluated: totalRulesEvaluated,
        configuration: `${THREAT_RULES.length} STRIDE rules with ${totalRulesEvaluated} detection patterns`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'STRIDE threat model analysis failed');
    return {
      scanner: 'threatmodel',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

// ─── Helpers ─────────────────────────────────────────────────────

function mapStrideToOwasp(category: string): string {
  switch (category) {
    case 'Spoofing':
      return 'A07:2021-Identification and Authentication Failures';
    case 'Tampering':
      return 'A03:2021-Injection';
    case 'Repudiation':
      return 'A09:2021-Security Logging and Monitoring Failures';
    case 'Information Disclosure':
      return 'A01:2021-Broken Access Control';
    case 'Denial of Service':
      return 'A05:2021-Security Misconfiguration';
    case 'Elevation of Privilege':
      return 'A01:2021-Broken Access Control';
    default:
      return 'A00:2021-Unknown';
  }
}
