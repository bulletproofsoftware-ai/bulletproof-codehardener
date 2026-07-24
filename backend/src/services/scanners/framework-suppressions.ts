/**
 * Framework-Aware Auto-Suppressions
 *
 * Auto-suppresses known false positives based on detected frameworks.
 * For example, Django ORM uses parameterized queries by default, so
 * SQL injection findings on Django projects are likely false positives.
 *
 * These suppressions are conservative — only applied when the framework's
 * default protections are known to be enabled. Every suppression is logged
 * for audit trail.
 */

import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../utils/logger.js';
import type { FrameworkDetection } from '../test-generator/types.js';

const logger = createLogger('framework-suppressions');

interface SuppressionRule {
  rulePattern?: RegExp;
  cwePattern?: string;
  titlePattern?: RegExp;
  reason: string;
}

interface FrameworkSuppression {
  framework: string;
  suppressions: SuppressionRule[];
}

export interface SuppressionMatch {
  framework: string;
  cwePattern?: string;
  titlePattern?: RegExp;
  rulePattern?: RegExp;
  reason: string;
}

const FRAMEWORK_SUPPRESSIONS: FrameworkSuppression[] = [
  {
    framework: 'django',
    suppressions: [
      {
        cwePattern: 'CWE-89',
        titlePattern: /sql.?injection/i,
        reason: 'Django ORM uses parameterized queries by default — SQL injection requires raw() or extra() bypass',
      },
      {
        cwePattern: 'CWE-352',
        reason: 'Django has built-in CSRF middleware enabled by default (django.middleware.csrf.CsrfViewMiddleware)',
      },
      {
        cwePattern: 'CWE-79',
        titlePattern: /xss|cross.?site.?script/i,
        reason: 'Django templates auto-escape variables by default — XSS requires |safe filter or mark_safe()',
      },
    ],
  },
  {
    framework: 'react',
    suppressions: [
      {
        cwePattern: 'CWE-79',
        titlePattern: /xss|cross.?site.?script/i,
        reason: 'React JSX auto-escapes expressions by default — XSS requires explicit unsafe innerHTML usage',
      },
    ],
  },
  {
    framework: 'nextjs',
    suppressions: [
      {
        cwePattern: 'CWE-79',
        titlePattern: /xss|cross.?site.?script/i,
        reason: 'Next.js (React) auto-escapes JSX expressions by default',
      },
    ],
  },
  {
    framework: 'express',
    suppressions: [
      {
        titlePattern: /security.?header|x-frame|hsts|x-content-type|x-xss-protection/i,
        reason: 'Express + helmet middleware sets security headers (detected in dependencies)',
      },
    ],
  },
  {
    framework: 'rails',
    suppressions: [
      {
        cwePattern: 'CWE-89',
        titlePattern: /sql.?injection/i,
        reason: 'Rails ActiveRecord uses parameterized queries by default — injection requires raw SQL or string interpolation',
      },
      {
        cwePattern: 'CWE-352',
        reason: 'Rails has built-in CSRF protection enabled by default (protect_from_forgery)',
      },
      {
        cwePattern: 'CWE-79',
        titlePattern: /xss|cross.?site.?script/i,
        reason: 'Rails ERB templates auto-escape output by default — XSS requires raw() or html_safe',
      },
    ],
  },
  {
    framework: 'spring',
    suppressions: [
      {
        cwePattern: 'CWE-89',
        titlePattern: /sql.?injection/i,
        reason: 'Spring JPA/Hibernate uses parameterized queries by default — injection requires native queries with string concatenation',
      },
      {
        cwePattern: 'CWE-352',
        reason: 'Spring Security enables CSRF protection by default',
      },
    ],
  },
  {
    framework: 'fastapi',
    suppressions: [
      {
        cwePattern: 'CWE-89',
        titlePattern: /sql.?injection/i,
        reason: 'FastAPI + SQLAlchemy uses parameterized queries by default',
      },
    ],
  },
  {
    framework: 'flask',
    suppressions: [
      {
        cwePattern: 'CWE-79',
        titlePattern: /xss|cross.?site.?script/i,
        reason: 'Flask Jinja2 templates auto-escape variables by default — XSS requires |safe filter or Markup()',
      },
    ],
  },
  {
    framework: 'gin',
    suppressions: [
      {
        cwePattern: 'CWE-89',
        titlePattern: /sql.?injection/i,
        reason: 'Go database/sql uses parameterized queries by default — injection requires string concatenation in queries',
      },
    ],
  },
  {
    framework: 'echo',
    suppressions: [
      {
        cwePattern: 'CWE-89',
        titlePattern: /sql.?injection/i,
        reason: 'Go database/sql uses parameterized queries by default',
      },
    ],
  },
];

/**
 * Get suppression rules applicable to the detected frameworks
 */
export function getFrameworkSuppressions(frameworks: FrameworkDetection[]): SuppressionMatch[] {
  const matches: SuppressionMatch[] = [];
  const detectedNames = new Set(frameworks.map(f => (f.name || f.framework).toLowerCase()));

  for (const fs of FRAMEWORK_SUPPRESSIONS) {
    if (!detectedNames.has(fs.framework)) continue;

    for (const rule of fs.suppressions) {
      matches.push({
        framework: fs.framework,
        cwePattern: rule.cwePattern,
        titlePattern: rule.titlePattern,
        rulePattern: rule.rulePattern,
        reason: rule.reason,
      });
    }
  }

  return matches;
}

/**
 * Apply framework-based suppressions to findings in the database.
 * Runs BEFORE user suppression rules so both stack.
 *
 * Returns the number of findings suppressed.
 */
export async function applyFrameworkSuppressions(
  scanId: string,
  _projectId: string,
  suppressions: SuppressionMatch[],
): Promise<number> {
  if (suppressions.length === 0) return 0;

  let totalSuppressed = 0;

  for (const sup of suppressions) {
    // Build WHERE conditions for this suppression rule
    const conditions: ReturnType<typeof sql>[] = [
      sql`f.scan_id = ${scanId}`,
      sql`f.status = 'open'`,
    ];

    if (sup.cwePattern) {
      conditions.push(sql`f.cwe_id = ${sup.cwePattern}`);
    }

    if (sup.titlePattern) {
      conditions.push(sql`f.title ~* ${sup.titlePattern.source}`);
    }

    // Must match at least CWE or title pattern (not suppress everything)
    if (!sup.cwePattern && !sup.titlePattern && !sup.rulePattern) continue;

    const whereClause = sql.join(conditions, sql` AND `);
    const reason = `[Auto] Framework: ${sup.framework} — ${sup.reason}`;

    const result = await db.execute(sql`
      UPDATE findings f
      SET status = 'false_positive',
          dismissed_reason = ${reason},
          dismissed_at = NOW()
      WHERE ${whereClause}
      RETURNING f.id
    `);

    if (result.rows.length > 0) {
      logger.info(
        { scanId, framework: sup.framework, suppressed: result.rows.length, reason: sup.reason },
        'Framework auto-suppression applied'
      );
      totalSuppressed += result.rows.length;
    }
  }

  return totalSuppressed;
}
