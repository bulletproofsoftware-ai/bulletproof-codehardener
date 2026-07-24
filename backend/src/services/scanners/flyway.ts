/** @deprecated Removed from active scanner rotation in v2. Static SQL migration analysis; OpenGrep covers SQL injection patterns. */
import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-flyway');

/**
 * Flyway / Database Migration Security Analyzer
 *
 * Analyzes SQL migration files for:
 * - Privilege escalation (GRANT ALL, SUPERUSER)
 * - Missing rollback migrations
 * - Data exposure (SELECT * in migrations)
 * - Schema changes without proper constraints
 * - Hardcoded credentials in migrations
 */
export async function runFlyway(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Look for migration files (Flyway, Knex, Drizzle, Prisma, generic SQL)
    const { stdout: migrationSearch } = await execAsync(
      `find /scan-target \\( ` +
      `-path "*/migrations/*.sql" -o ` +
      `-path "*/db/migrate/*.sql" -o ` +
      `-path "*/flyway/sql/*.sql" -o ` +
      `-path "*/migration/*.sql" -o ` +
      `-name "V[0-9]*__*.sql" ` +
      `\\) 2>/dev/null | head -200`
    );

    const migrationFiles = migrationSearch.trim().split('\n').filter(Boolean);
    if (migrationFiles.length === 0) {
      logger.info('No database migration files found');
      return {
        scanner: 'flyway',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        skipReason: 'no_matching_files',
        skipHint: 'No SQL migration files found',
      };
    }

    for (const migFile of migrationFiles) {
      try {
        const { stdout: content } = await execAsync(`cat "${migFile}"`, { maxBuffer: 5 * 1024 * 1024 });
        const relativePath = migFile.replace('/scan-target/', '');
        const upperContent = content.toUpperCase();

        // Check for privilege escalation
        const privPatterns = [
          { pattern: /GRANT\s+ALL/i, name: 'GRANT ALL', severity: 'high' as const },
          { pattern: /SUPERUSER/i, name: 'SUPERUSER', severity: 'critical' as const },
          { pattern: /WITH\s+GRANT\s+OPTION/i, name: 'WITH GRANT OPTION', severity: 'high' as const },
          { pattern: /CREATE\s+ROLE.*SUPERUSER/i, name: 'CREATE SUPERUSER ROLE', severity: 'critical' as const },
          { pattern: /ALTER\s+ROLE.*SUPERUSER/i, name: 'ALTER TO SUPERUSER', severity: 'critical' as const },
        ];

        for (const { pattern, name, severity } of privPatterns) {
          if (pattern.test(content)) {
            findings.push({
              ruleId: 'FLYWAY-PRIVILEGE-ESCALATION',
              severity,
              title: `Migration: Privilege Escalation - ${name}`,
              description: `Migration uses ${name} which grants excessive database privileges. Follow principle of least privilege.`,
              filePath: relativePath,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: 'CWE-250',
              owaspCategory: 'A01:2021-Broken Access Control',
              fixAvailable: true,
              fixDescription: `Replace ${name} with specific GRANT statements (e.g., GRANT SELECT, INSERT ON table TO role)`,
              metadata: { pattern: name },
            });
          }
        }

        // Check for hardcoded credentials
        const credPatterns = [
          /PASSWORD\s*=?\s*'[^']+'/i,
          /SET\s+PASSWORD\s/i,
          /CREATE\s+USER.*IDENTIFIED\s+BY\s+'[^']+'/i,
          /CREATE\s+ROLE.*PASSWORD\s+'[^']+'/i,
        ];

        for (const pattern of credPatterns) {
          if (pattern.test(content)) {
            findings.push({
              ruleId: 'FLYWAY-HARDCODED-CREDS',
              severity: 'critical',
              title: 'Migration: Hardcoded Database Credentials',
              description: 'Migration file contains hardcoded passwords. Use environment variables or secrets management.',
              filePath: relativePath,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: 'CWE-798',
              owaspCategory: 'A07:2021-Identification and Authentication Failures',
              fixAvailable: true,
              fixDescription: 'Use psql variable substitution (:password) or handle credentials outside migrations',
              metadata: {},
            });
            break;
          }
        }

        // Check for DROP without IF EXISTS (risky in production)
        if (/DROP\s+TABLE\s+(?!IF\s+EXISTS)/i.test(content)) {
          findings.push({
            ruleId: 'FLYWAY-UNSAFE-DROP',
            severity: 'medium',
            title: 'Migration: DROP TABLE Without IF EXISTS',
            description: 'DROP TABLE without IF EXISTS can fail in environments where the table does not exist, breaking migration chains.',
            filePath: relativePath,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: null,
            owaspCategory: 'A04:2021-Insecure Design',
            fixAvailable: true,
            fixDescription: 'Use DROP TABLE IF EXISTS to make migrations idempotent',
            metadata: {},
          });
        }

        // Check for data exposure patterns
        if (/SELECT\s+\*\s+FROM\s+\w+.*INTO/i.test(content) || /INSERT\s+INTO.*SELECT\s+\*/i.test(content)) {
          findings.push({
            ruleId: 'FLYWAY-SELECT-STAR',
            severity: 'low',
            title: 'Migration: SELECT * in Data Migration',
            description: 'Using SELECT * in data migration copies all columns including potentially sensitive ones. Specify exact columns.',
            filePath: relativePath,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: 'CWE-200',
            owaspCategory: 'A01:2021-Broken Access Control',
            fixAvailable: true,
            fixDescription: 'Explicitly list columns instead of using SELECT *',
            metadata: {},
          });
        }

        // Check for missing transactions in DDL
        if (
          (upperContent.includes('ALTER TABLE') || upperContent.includes('DROP TABLE')) &&
          !upperContent.includes('BEGIN') &&
          !upperContent.includes('START TRANSACTION')
        ) {
          findings.push({
            ruleId: 'FLYWAY-NO-TRANSACTION',
            severity: 'low',
            title: 'Migration: DDL Without Explicit Transaction',
            description: 'Schema changes without explicit transaction wrapping. Some databases auto-commit DDL which prevents rollback on failure.',
            filePath: relativePath,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: null,
            owaspCategory: 'A04:2021-Insecure Design',
            fixAvailable: true,
            fixDescription: 'Wrap DDL statements in BEGIN/COMMIT blocks for atomicity',
            metadata: {},
          });
        }
      } catch {
        logger.warn({ migFile }, 'Failed to read migration file');
      }
    }

    logger.info({ findingsCount: findings.length, files: migrationFiles.length }, 'Migration analysis completed');

    return {
      scanner: 'flyway',
      success: true,
      findings,
      duration: Date.now() - startTime,
    };
  } catch (error) {
    logger.error({ error }, 'Migration analysis failed');
    return {
      scanner: 'flyway',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
