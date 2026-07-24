/**
 * GDPR Data Subject Rights Service
 *
 * Implements:
 *   - Article 15: Right of access (data export)
 *   - Article 17: Right to erasure
 *   - Article 20: Right to data portability
 *   - Processing records (Article 30)
 */

import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('gdpr-service');

function toISO(val: unknown): string {
  if (!val) return '';
  if (val instanceof Date) return val.toISOString();
  return String(val);
}

export interface DataExport {
  exportedAt: string;
  dataSubject: {
    id: string;
    email: string;
    name: string | null;
    createdAt: string;
  };
  projects: Array<{
    id: string;
    name: string;
    repositoryUrl: string | null;
    createdAt: string;
  }>;
  scans: Array<{
    id: string;
    projectId: string;
    status: string;
    profile: string;
    score: number | null;
    createdAt: string;
  }>;
  findings: Array<{
    id: string;
    scanId: string;
    scanner: string;
    severity: string;
    title: string;
    filePath: string | null;
    createdAt: string;
  }>;
  attestations: Array<{
    id: string;
    scanId: string;
    signedAt: string | null;
  }>;
  apiKeys: Array<{
    id: string;
    keyPrefix: string;
    scopes: string[];
    createdAt: string;
    lastUsedAt: string | null;
  }>;
  processingRecords: Array<{
    action: string;
    timestamp: string;
    purpose: string;
    legalBasis: string;
  }>;
}

export interface ErasureResult {
  erasedAt: string;
  userId: string;
  erasedRecords: {
    projects: number;
    scans: number;
    findings: number;
    attestations: number;
    apiKeys: number;
    teamMemberships: number;
    oauthAccounts: number;
    notifications: number;
    user: boolean;
  };
}

export interface ProcessingRecord {
  id: string;
  userId: string;
  action: string;
  purpose: string;
  legalBasis: string;
  dataCategories: string[];
  recipientCategories: string[];
  retentionPeriod: string;
  createdAt: string;
}

/**
 * Export all user data (Article 15 & 20)
 * Returns a complete portable data package.
 */
export async function exportUserData(userId: string): Promise<DataExport> {
  // Log the export request
  await logProcessingActivity(userId, 'data_export', 'GDPR Article 15/20 — data subject access request', 'legal_obligation');

  // Fetch user
  const userResult = await db.execute(
    sql`SELECT id, email, name, created_at FROM users WHERE id = ${userId}`
  );
  if (userResult.rows.length === 0) {
    throw new Error('User not found');
  }
  const user = userResult.rows[0] as any;

  // Fetch projects
  const projectsResult = await db.execute(
    sql`SELECT id, name, repo_url, created_at FROM projects WHERE user_id = ${userId} ORDER BY created_at`
  );

  // Fetch scans
  const scansResult = await db.execute(
    sql`SELECT s.id, s.project_id, s.status, s.profile, s.score, s.created_at
        FROM scans s JOIN projects p ON p.id = s.project_id
        WHERE p.user_id = ${userId} ORDER BY s.created_at`
  );

  // Fetch findings (without full descriptions to keep export manageable)
  const findingsResult = await db.execute(
    sql`SELECT f.id, f.scan_id, f.scanner, f.severity, f.title, f.file_path, f.created_at
        FROM findings f JOIN projects p ON p.id = f.project_id
        WHERE p.user_id = ${userId} ORDER BY f.created_at`
  );

  // Fetch attestations
  const attestResult = await db.execute(
    sql`SELECT a.id, a.scan_id, a.created_at
        FROM attestations a JOIN scans s ON s.id = a.scan_id
        JOIN projects p ON p.id = s.project_id
        WHERE p.user_id = ${userId} ORDER BY a.created_at`
  );

  // Fetch API keys (never expose key hashes)
  const apiKeysResult = await db.execute(
    sql`SELECT id, key_prefix, permissions, created_at, last_used_at
        FROM api_keys WHERE user_id = ${userId} ORDER BY created_at`
  );

  // Processing records
  const records = await getProcessingRecords(userId);

  logger.info({ userId }, 'GDPR data export completed');

  return {
    exportedAt: new Date().toISOString(),
    dataSubject: {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: toISO(user.created_at),
    },
    projects: (projectsResult.rows as any[]).map(r => ({
      id: r.id,
      name: r.name,
      repositoryUrl: r.repo_url,
      createdAt: toISO(r.created_at),
    })),
    scans: (scansResult.rows as any[]).map(r => ({
      id: r.id,
      projectId: r.project_id,
      status: r.status,
      profile: r.profile,
      score: r.score,
      createdAt: toISO(r.created_at),
    })),
    findings: (findingsResult.rows as any[]).map(r => ({
      id: r.id,
      scanId: r.scan_id,
      scanner: r.scanner,
      severity: r.severity,
      title: r.title,
      filePath: r.file_path,
      createdAt: toISO(r.created_at),
    })),
    attestations: (attestResult.rows as any[]).map(r => ({
      id: r.id,
      scanId: r.scan_id,
      signedAt: toISO(r.created_at),
    })),
    apiKeys: (apiKeysResult.rows as any[]).map(r => ({
      id: r.id,
      keyPrefix: r.key_prefix,
      scopes: r.permissions || [],
      createdAt: toISO(r.created_at),
      lastUsedAt: toISO(r.last_used_at),
    })),
    processingRecords: records.map(r => ({
      action: r.action,
      timestamp: r.createdAt,
      purpose: r.purpose,
      legalBasis: r.legalBasis,
    })),
  };
}

/**
 * Erase all user data (Article 17)
 * Cascading delete of all user-owned data.
 */
export async function eraseUserData(userId: string): Promise<ErasureResult> {
  await logProcessingActivity(userId, 'data_erasure', 'GDPR Article 17 — right to erasure', 'legal_obligation');

  // Count records before deletion for audit
  const counts = {
    projects: 0,
    scans: 0,
    findings: 0,
    attestations: 0,
    apiKeys: 0,
    teamMemberships: 0,
    oauthAccounts: 0,
    notifications: 0,
    user: false,
  };

  // Count existing records
  const countResults = await Promise.all([
    db.execute(sql`SELECT COUNT(*) as c FROM projects WHERE user_id = ${userId}`),
    db.execute(sql`SELECT COUNT(*) as c FROM scans s JOIN projects p ON p.id = s.project_id WHERE p.user_id = ${userId}`),
    db.execute(sql`SELECT COUNT(*) as c FROM findings f JOIN projects p ON p.id = f.project_id WHERE p.user_id = ${userId}`),
    db.execute(sql`SELECT COUNT(*) as c FROM api_keys WHERE user_id = ${userId}`),
    db.execute(sql`SELECT COUNT(*) as c FROM team_members WHERE user_id = ${userId}`),
    db.execute(sql`SELECT COUNT(*) as c FROM oauth_accounts WHERE user_id = ${userId}`),
    db.execute(sql`SELECT COUNT(*) as c FROM notifications WHERE user_id = ${userId}`),
  ]);

  counts.projects = parseInt((countResults[0].rows[0] as any).c, 10);
  counts.scans = parseInt((countResults[1].rows[0] as any).c, 10);
  counts.findings = parseInt((countResults[2].rows[0] as any).c, 10);
  counts.apiKeys = parseInt((countResults[3].rows[0] as any).c, 10);
  counts.teamMemberships = parseInt((countResults[4].rows[0] as any).c, 10);
  counts.oauthAccounts = parseInt((countResults[5].rows[0] as any).c, 10);
  counts.notifications = parseInt((countResults[6].rows[0] as any).c, 10);

  // Delete in dependency order (most tables cascade from projects or users)
  // Projects cascade: scans → findings, attestations
  await db.execute(sql`DELETE FROM api_keys WHERE user_id = ${userId}`);
  await db.execute(sql`DELETE FROM team_members WHERE user_id = ${userId}`);
  await db.execute(sql`DELETE FROM oauth_accounts WHERE user_id = ${userId}`);
  await db.execute(sql`DELETE FROM notifications WHERE user_id = ${userId}`);
  await db.execute(sql`DELETE FROM projects WHERE user_id = ${userId}`);
  await db.execute(sql`DELETE FROM sso_sessions WHERE user_id = ${userId}`);

  // Anonymize the user record instead of hard-deleting (retain for audit trail)
  await db.execute(
    sql`UPDATE users SET
          email = 'deleted-' || id || '@erased.codehardener.com',
          name = NULL,
          password_hash = NULL,
          avatar_url = NULL,
          sso_provider = NULL,
          sso_subject_id = NULL,
          updated_at = NOW()
        WHERE id = ${userId}`
  );
  counts.user = true;

  logger.info({ userId, counts }, 'GDPR data erasure completed');

  return {
    erasedAt: new Date().toISOString(),
    userId,
    erasedRecords: counts,
  };
}

/**
 * Log a processing activity (Article 30)
 */
export async function logProcessingActivity(
  userId: string,
  action: string,
  purpose: string,
  legalBasis: string,
  dataCategories: string[] = ['security_scan_data'],
  recipientCategories: string[] = ['data_subject']
): Promise<void> {
  await db.execute(
    sql`INSERT INTO processing_records (user_id, action, purpose, legal_basis, data_categories, recipient_categories)
        VALUES (${userId}, ${action}, ${purpose}, ${legalBasis},
                ${JSON.stringify(dataCategories)}::jsonb,
                ${JSON.stringify(recipientCategories)}::jsonb)`
  );
}

/**
 * Get processing records for a user (Article 30)
 */
export async function getProcessingRecords(userId: string): Promise<ProcessingRecord[]> {
  const result = await db.execute(
    sql`SELECT id, user_id, action, purpose, legal_basis,
               data_categories, recipient_categories, retention_period, created_at
        FROM processing_records WHERE user_id = ${userId}
        ORDER BY created_at DESC`
  );

  return (result.rows as any[]).map(r => ({
    id: r.id,
    userId: r.user_id,
    action: r.action,
    purpose: r.purpose,
    legalBasis: r.legal_basis,
    dataCategories: r.data_categories || [],
    recipientCategories: r.recipient_categories || [],
    retentionPeriod: r.retention_period || '2 years',
    createdAt: toISO(r.created_at),
  }));
}
