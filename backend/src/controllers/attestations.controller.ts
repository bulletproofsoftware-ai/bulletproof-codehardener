import type { Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendSuccess, sendCreated, sendValidationError } from '../utils/apiResponse.js';
import { NotFoundError } from '../middleware/errorHandler.js';
import { createLogger } from '../utils/logger.js';
import {
  createScanAttestation,
  signAttestation,
  verifyAttestation,
  generateAttestationBundle,
} from '../services/assurance/attestation.js';
import { calculateQualityScore } from '../services/assurance/quality-score.js';

const logger = createLogger('attestations-controller');

// Transform database row to API response format
function transformAttestation(row: Record<string, unknown>) {
  // The DB column is attestation_json, not predicate
  const predicateData = row.attestation_json || row.predicate;

  // Extract score from predicate JSON if available
  let score = 0;
  if (predicateData) {
    const predicate = typeof predicateData === 'string'
      ? JSON.parse(predicateData as string)
      : predicateData;
    score = predicate?.scanResults?.score ?? predicate?.score ?? 0;
  }

  return {
    id: row.id,
    scanId: row.scan_id,
    projectId: row.project_id,
    projectName: row.project_name,
    score,
    attestationType: row.attestation_type,
    predicateType: row.predicate_type || row.attestation_type,
    subjectName: row.subject_name,
    subjectDigest: row.subject_digest,
    predicate: predicateData,
    signature: row.signature ? '***SIGNED***' : null,
    signatureAlgorithm: row.signature_algorithm,
    hasCertificate: !!row.certificate,
    rekorLogId: row.rekor_log_id,
    rekorLogIndex: row.rekor_log_index,
    transparencyLogUrl: row.transparency_log_url,
    signedAt: row.created_at,
    createdAt: row.created_at,
    isSigned: !!row.signature,
    isVerifiable: !!row.signature && !!row.certificate,
  };
}

export async function listAttestations(req: Request, res: Response) {
  const querySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    scanId: z.string().uuid().optional(),
  }).passthrough();
  const { page, limit, scanId } = querySchema.parse(req.query);
  const offset = (page - 1) * limit;

  let whereClause = sql`p.user_id = ${req.user!.id}`;

  if (scanId) {
    whereClause = sql`${whereClause} AND a.scan_id = ${scanId}`;
  }

  const [attestations, countResult] = await Promise.all([
    db.execute(sql`
      SELECT a.*, s.project_id, p.name as project_name
      FROM attestations a
      JOIN scans s ON s.id = a.scan_id
      JOIN projects p ON p.id = s.project_id
      WHERE ${whereClause}
      ORDER BY a.created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `),
    db.execute(sql`
      SELECT COUNT(*) as count FROM attestations a
      JOIN scans s ON s.id = a.scan_id
      JOIN projects p ON p.id = s.project_id
      WHERE ${whereClause}
    `),
  ]);

  const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string);
  const transformedAttestations = attestations.rows.map(row =>
    transformAttestation(row as Record<string, unknown>)
  );

  return sendSuccess(res, transformedAttestations, 200, {
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  });
}

export async function getAttestation(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    SELECT a.*, s.project_id, p.name as project_name
    FROM attestations a
    JOIN scans s ON s.id = a.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE a.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Attestation not found');
  }

  return sendSuccess(res, transformAttestation(result.rows[0] as Record<string, unknown>));
}

const createAttestationSchema = z.object({
  scanId: z.string().uuid(),
});

export async function createAttestationFromScan(req: Request, res: Response) {
  const validation = createAttestationSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { scanId } = validation.data;

  // Verify scan ownership and get scan data
  const scanResult = await db.execute(sql`
    SELECT s.*, p.name as project_name, p.id as project_id
    FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE s.id = ${scanId} AND p.user_id = ${req.user!.id}
  `);

  if (scanResult.rows.length === 0) {
    throw new NotFoundError('Scan not found');
  }

  const scan = scanResult.rows[0] as any;

  // Check if attestation already exists
  const existingAttestation = await db.execute(sql`
    SELECT id, signature FROM attestations WHERE scan_id = ${scanId}
  `);

  if (existingAttestation.rows.length > 0) {
    const existing = existingAttestation.rows[0] as any;
    if (existing.signature) {
      // Already signed — return as-is
      return sendSuccess(res, {
        id: existing.id,
        message: 'Attestation already exists for this scan',
      }, 200);
    }
    // Unsigned — fall through to re-sign it
    return await resignExistingAttestation(req, res, existing.id);
  }

  // Check scan is completed
  if (scan.status !== 'completed') {
    return sendValidationError(res, [
      { path: ['scanId'], message: 'Scan must be completed before creating attestation' },
    ]);
  }

  // Parse findings count
  const findingsCount = scan.findings_count || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0,
  };

  // Create attestation
  const attestation = await createScanAttestation(
    scanId,
    scan.project_id,
    scan.project_name,
    {
      profile: scan.profile || 'standard',
      scannersUsed: ['trivy', 'gitleaks', 'opengrep', 'checkov', 'nuclei'],
      startTime: new Date(scan.started_at),
      endTime: new Date(scan.completed_at),
      duration: scan.duration || 0,
      findings: {
        critical: findingsCount.critical || 0,
        high: findingsCount.high || 0,
        medium: findingsCount.medium || 0,
        low: findingsCount.low || 0,
        info: findingsCount.info || 0,
        total: findingsCount.total || 0,
      },
      score: scan.score ?? calculateQualityScore({
        critical: findingsCount.critical || 0,
        high: findingsCount.high || 0,
        medium: findingsCount.medium || 0,
        low: findingsCount.low || 0,
        info: findingsCount.info || 0,
        total: findingsCount.total || 0,
      }).score,
      qualityLevel: scan.quality_level || calculateQualityScore({
        critical: findingsCount.critical || 0,
        high: findingsCount.high || 0,
        medium: findingsCount.medium || 0,
        low: findingsCount.low || 0,
        info: findingsCount.info || 0,
        total: findingsCount.total || 0,
      }).qualityLevel,
    }
  );

  // Sign attestation (Sigstore first, local Ed25519 fallback)
  const sigResult = await signAttestation(attestation);
  if (sigResult) {
    attestation.signature = sigResult.signature;
    attestation.signatureAlgorithm = sigResult.algorithm;
    attestation.certificate = sigResult.certificate;
    attestation.rekorLogId = sigResult.rekorLogId;
  }

  // Store in database
  await db.execute(sql`
    INSERT INTO attestations (
      id, scan_id, attestation_type, subject_name, subject_digest,
      predicate_type, attestation_json, signature, signature_algorithm,
      certificate, rekor_log_id, transparency_log_url, created_at
    ) VALUES (
      ${attestation.id},
      ${attestation.scanId},
      ${'in-toto'},
      ${attestation.subject.name},
      ${attestation.subject.digest.sha256},
      ${attestation.predicate.type},
      ${JSON.stringify(attestation.predicate)},
      ${attestation.signature || null},
      ${attestation.signatureAlgorithm || null},
      ${attestation.certificate || null},
      ${attestation.rekorLogId || null},
      ${attestation.rekorLogId ? `https://search.sigstore.dev/?logIndex=${attestation.rekorLogId}` : null},
      ${attestation.timestamp}
    )
  `);

  logger.info(
    { attestationId: attestation.id, scanId, signed: !!sigResult, algorithm: sigResult?.algorithm },
    'Attestation created'
  );

  return sendCreated(res, {
    id: attestation.id,
    scanId: attestation.scanId,
    isSigned: !!attestation.signature,
    signatureAlgorithm: attestation.signatureAlgorithm || null,
    rekorLogId: attestation.rekorLogId || null,
    transparencyLogUrl: attestation.rekorLogId
      ? `https://search.sigstore.dev/?logIndex=${attestation.rekorLogId}`
      : null,
    createdAt: attestation.timestamp,
  });
}

export async function verifyAttestationEndpoint(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  // Get attestation with full data
  const result = await db.execute(sql`
    SELECT a.*, s.project_id, p.name as project_name
    FROM attestations a
    JOIN scans s ON s.id = a.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE a.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Attestation not found');
  }

  const row = result.rows[0] as any;

  // Check if attestation has a real signature (not the legacy 'unsigned' string)
  const hasSignature = row.signature && row.signature !== 'unsigned';
  const hasCertificate = !!row.certificate;

  if (!hasSignature || !hasCertificate) {
    return sendSuccess(res, {
      valid: false,
      message: 'This attestation was created without a cryptographic signature. Sigstore/cosign signing is not configured in this environment.',
      error: 'Attestation is not signed',
      unsigned: true,
      canVerify: false,
    });
  }

  // Reconstruct attestation for verification
  const attestation = {
    id: row.id,
    scanId: row.scan_id,
    projectId: row.project_id,
    timestamp: row.created_at,
    subject: {
      name: row.subject_name,
      digest: { sha256: row.subject_digest },
    },
    predicate: row.attestation_json || row.predicate,
    signature: row.signature,
    signatureAlgorithm: row.signature_algorithm,
    certificate: row.certificate,
    rekorLogId: row.rekor_log_id,
  };

  const verifyResult = await verifyAttestation(attestation);

  return sendSuccess(res, {
    valid: verifyResult.valid,
    message: verifyResult.valid ? 'Signature verified successfully' : (verifyResult.error || null),
    error: verifyResult.error || null,
    unsigned: false,
    canVerify: true,
    signatureAlgorithm: row.signature_algorithm || null,
    rekorLogId: row.rekor_log_id,
    transparencyLogUrl: row.transparency_log_url,
  });
}

/**
 * Re-sign an existing unsigned attestation.
 * Reconstructs the attestation object from DB, signs it, and updates the record.
 */
async function resignExistingAttestation(req: Request, res: Response, attestationId: string) {
  const result = await db.execute(sql`
    SELECT a.*, s.project_id, p.name as project_name
    FROM attestations a
    JOIN scans s ON s.id = a.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE a.id = ${attestationId} AND p.user_id = ${req.user!.id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Attestation not found');
  }

  const row = result.rows[0] as any;

  if (row.signature) {
    return sendSuccess(res, {
      id: row.id,
      message: 'Attestation is already signed',
      isSigned: true,
      signatureAlgorithm: row.signature_algorithm,
    }, 200);
  }

  // Reconstruct attestation for signing
  const attestation = {
    id: row.id,
    scanId: row.scan_id,
    projectId: row.project_id,
    timestamp: row.created_at,
    subject: {
      name: row.subject_name,
      digest: { sha256: row.subject_digest },
    },
    predicate: row.attestation_json || row.predicate,
    signature: undefined as string | undefined,
    signatureAlgorithm: undefined as string | undefined,
    certificate: undefined as string | undefined,
    rekorLogId: undefined as string | undefined,
  };

  const sigResult = await signAttestation(attestation);
  if (!sigResult) {
    logger.error({ attestationId }, 'Re-sign attempt failed — no signing method available');
    return sendSuccess(res, {
      id: attestationId,
      message: 'Attestation exists but signing failed',
      isSigned: false,
    }, 200);
  }

  // Update DB with signature
  await db.execute(sql`
    UPDATE attestations
    SET signature = ${sigResult.signature},
        signature_algorithm = ${sigResult.algorithm},
        certificate = ${sigResult.certificate},
        rekor_log_id = ${sigResult.rekorLogId || null},
        transparency_log_url = ${sigResult.rekorLogId ? `https://search.sigstore.dev/?logIndex=${sigResult.rekorLogId}` : null}
    WHERE id = ${attestationId}
  `);

  logger.info(
    { attestationId, algorithm: sigResult.algorithm },
    'Unsigned attestation re-signed successfully'
  );

  return sendSuccess(res, {
    id: attestationId,
    message: 'Attestation re-signed successfully',
    isSigned: true,
    signatureAlgorithm: sigResult.algorithm,
    rekorLogId: sigResult.rekorLogId || null,
  });
}

export async function resignAttestationEndpoint(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  return resignExistingAttestation(req, res, id);
}

export async function downloadAttestationBundle(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  // Get attestation with full data
  const result = await db.execute(sql`
    SELECT a.*, s.project_id
    FROM attestations a
    JOIN scans s ON s.id = a.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE a.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Attestation not found');
  }

  const row = result.rows[0] as any;

  // Reconstruct attestation for bundle generation
  const attestation = {
    id: row.id,
    scanId: row.scan_id,
    projectId: row.project_id,
    timestamp: row.created_at,
    subject: {
      name: row.subject_name,
      digest: { sha256: row.subject_digest },
    },
    predicate: row.attestation_json || row.predicate,
    signatureAlgorithm: row.signature_algorithm,
    signature: row.signature,
    certificate: row.certificate,
    rekorLogId: row.rekor_log_id,
  };

  const bundle = generateAttestationBundle(attestation);

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="attestation-${id}.json"`);
  res.send(bundle);
}
