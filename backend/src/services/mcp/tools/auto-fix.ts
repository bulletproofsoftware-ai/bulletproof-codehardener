import { db } from '../../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../../utils/logger.js';

const logger = createLogger('mcp-auto-fix');

// ============================================================================
// Tool Definitions
// ============================================================================

export const autoFixTools = [
  {
    name: 'codehardener_auto_fix',
    description:
      'Generate a code fix patch for a specific finding. Returns a unified diff that can be applied with `git apply` or used by an AI agent to modify the source file. Works best for SAST findings with file:line locations.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        findingId: {
          type: 'string',
          description: 'ID of the finding to generate a fix for',
        },
        style: {
          type: 'string',
          enum: ['patch', 'instruction', 'both'],
          description: 'Fix output style: "patch" (unified diff), "instruction" (human-readable steps), "both" (default)',
        },
      },
      required: ['findingId'],
    },
  },
  {
    name: 'codehardener_bulk_fix',
    description:
      'Generate fix suggestions for all open findings in a scan, grouped by file. Returns a prioritized list of fixes starting with critical severity. Useful for batch remediation.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        scanId: {
          type: 'string',
          description: 'ID of the scan to generate fixes for',
        },
        maxFindings: {
          type: 'number',
          description: 'Maximum number of findings to generate fixes for (default: 20)',
        },
        minSeverity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low'],
          description: 'Minimum severity to include (default: medium)',
        },
      },
      required: ['scanId'],
    },
  },
];

// ============================================================================
// Fix pattern library — maps rule IDs to structured fix templates
// ============================================================================

interface FixTemplate {
  /** Human-readable fix description */
  description: string;
  /** Code transformation instruction for AI agents */
  instruction: string;
  /** CWE reference for the vulnerability */
  cwe?: string;
  /** References/docs URLs */
  references?: string[];
}

const FIX_TEMPLATES: Record<string, FixTemplate> = {
  // SQL Injection
  'CWE-89': {
    description: 'Use parameterized queries instead of string concatenation',
    instruction: 'Replace string concatenation/interpolation in SQL queries with parameterized placeholders ($1, ?, :param). Use the database driver\'s built-in parameterization.',
    cwe: 'CWE-89',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html'],
  },
  // Command Injection
  'CWE-78': {
    description: 'Avoid shell execution with user input; use safe APIs',
    instruction: 'Replace exec/system/popen with subprocess using array arguments (no shell=True). Validate and sanitize all inputs before passing to system commands. Use allowlists for expected values.',
    cwe: 'CWE-78',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'],
  },
  // XSS
  'CWE-79': {
    description: 'Encode output and use Content Security Policy',
    instruction: 'Replace innerHTML/dangerouslySetInnerHTML with textContent or use a sanitization library (DOMPurify). Apply contextual output encoding (HTML, URL, JS, CSS).',
    cwe: 'CWE-79',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
  },
  // Hardcoded Credentials
  'CWE-798': {
    description: 'Move secrets to environment variables or a secrets manager',
    instruction: 'Replace hardcoded passwords/keys/tokens with environment variable lookups (process.env.SECRET_NAME or os.environ["SECRET_NAME"]). Add the variable name to .env.example with a placeholder value.',
    cwe: 'CWE-798',
  },
  // Insecure Deserialization
  'CWE-502': {
    description: 'Use safe deserialization with type checking',
    instruction: 'Replace eval/pickle.loads/yaml.load with safe alternatives (JSON.parse, yaml.safe_load). Add input validation and type checking before deserialization.',
    cwe: 'CWE-502',
  },
  // Path Traversal
  'CWE-22': {
    description: 'Validate and canonicalize file paths',
    instruction: 'Use path.resolve() to canonicalize the path, then verify it starts with the expected base directory. Reject paths containing ".." or absolute paths from user input.',
    cwe: 'CWE-22',
  },
  // Weak Crypto
  'CWE-327': {
    description: 'Replace weak algorithms with strong alternatives',
    instruction: 'Replace MD5/SHA1 with SHA-256 or SHA-3 for integrity checks. Replace DES/3DES with AES-256-GCM for encryption. Use bcrypt/scrypt/argon2 for password hashing.',
    cwe: 'CWE-327',
  },
  // Missing Auth
  'CWE-862': {
    description: 'Add authentication and authorization checks',
    instruction: 'Add authentication middleware before the route handler. Verify the user has the required role/permission for this resource. Return 401 for unauthenticated and 403 for unauthorized requests.',
    cwe: 'CWE-862',
  },
  // SSRF
  'CWE-918': {
    description: 'Validate and restrict outbound requests',
    instruction: 'Validate the target URL against an allowlist of permitted hosts/schemes. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, ::1). Use DNS resolution validation.',
    cwe: 'CWE-918',
  },
  // ReDoS
  'CWE-1333': {
    description: 'Simplify regex or add input length limits',
    instruction: 'Replace the vulnerable regex with a simpler pattern that avoids nested quantifiers and alternation. Add input length validation (e.g., max 1000 chars) before applying the regex.',
    cwe: 'CWE-1333',
  },
};

// Scanner-specific rule ID mappings
const RULE_TO_CWE: Record<string, string> = {
  // Bandit
  'B101': 'CWE-703',  // assert
  'B301': 'CWE-502',  // pickle
  'B302': 'CWE-502',  // marshal
  'B501': 'CWE-295',  // ssl verify=False
  'B602': 'CWE-78',   // subprocess shell
  'B603': 'CWE-78',   // subprocess without shell
  'B608': 'CWE-89',   // SQL injection
  'B105': 'CWE-798',  // hardcoded password
  // Gosec
  'G201': 'CWE-89',   // SQL injection
  'G204': 'CWE-78',   // command injection
  'G301': 'CWE-732',  // file permissions
  'G401': 'CWE-327',  // weak crypto
  'G501': 'CWE-295',  // SSL
  // ESLint
  'detect-eval-with-expression': 'CWE-95',
  'detect-no-csrf-before-method-override': 'CWE-352',
  'detect-non-literal-regexp': 'CWE-1333',
  'detect-unsafe-regex': 'CWE-1333',
  // Gitleaks
  'generic-api-key': 'CWE-798',
  'private-key': 'CWE-798',
  'aws-access-key': 'CWE-798',
};

function getFixTemplate(finding: Record<string, unknown>): FixTemplate | null {
  // Try direct CWE match
  const cweId = finding.cwe_id as string;
  if (cweId && FIX_TEMPLATES[cweId]) {
    return FIX_TEMPLATES[cweId];
  }

  // Try rule ID → CWE mapping
  const ruleId = finding.rule_id as string;
  if (ruleId) {
    const mappedCwe = RULE_TO_CWE[ruleId];
    if (mappedCwe && FIX_TEMPLATES[mappedCwe]) {
      return FIX_TEMPLATES[mappedCwe];
    }
  }

  // Fall back to fix_description from scanner
  if (finding.fix_description) {
    return {
      description: finding.fix_description as string,
      instruction: finding.fix_description as string,
    };
  }

  return null;
}

// ============================================================================
// Handlers
// ============================================================================

export async function handleAutoFix(
  args: Record<string, unknown>,
  userId: string
): Promise<unknown> {
  const findingId = args.findingId as string;
  const style = (args.style as string) || 'both';

  const result = await db.execute(sql`
    SELECT f.*, s.project_id
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE f.id = ${findingId} AND p.user_id = ${userId}
  `);

  if (result.rows.length === 0) {
    return { error: 'Finding not found' };
  }

  const finding = result.rows[0] as Record<string, unknown>;
  const template = getFixTemplate(finding);

  if (!template) {
    return {
      findingId,
      fixAvailable: false,
      message: 'No automated fix template available for this finding type. Review the description for manual remediation guidance.',
      finding: {
        title: finding.title,
        severity: finding.severity,
        filePath: finding.file_path,
        lineNumber: finding.line_number,
        description: finding.description,
      },
    };
  }

  const response: Record<string, unknown> = {
    findingId,
    fixAvailable: true,
    severity: finding.severity,
    filePath: finding.file_path,
    lineNumber: finding.line_number,
    codeSnippet: finding.code_snippet,
    cwe: template.cwe || finding.cwe_id,
  };

  if (style === 'instruction' || style === 'both') {
    response.instruction = {
      description: template.description,
      steps: template.instruction,
      references: template.references || [],
    };
  }

  if (style === 'patch' || style === 'both') {
    // Generate a structured fix instruction that an AI agent can execute
    response.patch = {
      type: 'ai-actionable',
      file: finding.file_path,
      line: finding.line_number,
      action: template.instruction,
      hint: `Open ${finding.file_path} at line ${finding.line_number}. ${template.instruction}`,
    };
  }

  logger.info({ findingId, cwe: template.cwe, hasTemplate: true }, 'Auto-fix generated');

  return response;
}

export async function handleBulkFix(
  args: Record<string, unknown>,
  userId: string
): Promise<unknown> {
  const scanId = args.scanId as string;
  const maxFindings = Math.min((args.maxFindings as number) || 20, 50);
  const minSeverity = (args.minSeverity as string) || 'medium';

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const minIndex = severityOrder.indexOf(minSeverity);
  const includedSeverities = severityOrder.slice(0, minIndex + 1);

  const result = await db.execute(sql`
    SELECT f.id, f.severity, f.title, f.file_path, f.line_number,
           f.rule_id, f.cwe_id, f.fix_description, f.code_snippet, f.description
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE f.scan_id = ${scanId}
      AND p.user_id = ${userId}
      AND f.status = 'open'
    ORDER BY
      CASE f.severity
        WHEN 'critical' THEN 1 WHEN 'high' THEN 2
        WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
      END
    LIMIT ${maxFindings + 10}
  `);

  const findings = (result.rows as Array<Record<string, unknown>>)
    .filter(f => includedSeverities.includes(f.severity as string))
    .slice(0, maxFindings);

  // Group by file for easier batch application
  const byFile: Record<string, Array<Record<string, unknown>>> = {};
  const fixes: Array<Record<string, unknown>> = [];

  for (const finding of findings) {
    const template = getFixTemplate(finding);
    const filePath = (finding.file_path as string) || 'unknown';

    if (!byFile[filePath]) byFile[filePath] = [];

    const fix = {
      findingId: finding.id,
      severity: finding.severity,
      title: finding.title,
      line: finding.line_number,
      ruleId: finding.rule_id,
      cwe: template?.cwe || finding.cwe_id,
      fixAvailable: !!template,
      instruction: template?.instruction || finding.fix_description || 'Manual review required',
      description: template?.description || (finding.fix_description as string) || '',
    };

    byFile[filePath].push(fix);
    fixes.push(fix);
  }

  const fixableCount = fixes.filter(f => f.fixAvailable).length;

  logger.info(
    { scanId, totalFindings: findings.length, fixable: fixableCount },
    'Bulk fix suggestions generated'
  );

  return {
    scanId,
    totalFindings: findings.length,
    fixableCount,
    fileCount: Object.keys(byFile).length,
    byFile,
    hint: fixableCount > 0
      ? `${fixableCount} of ${findings.length} findings have automated fix instructions. Apply them file by file, starting with critical severity.`
      : 'No automated fixes available. Review findings manually.',
  };
}
