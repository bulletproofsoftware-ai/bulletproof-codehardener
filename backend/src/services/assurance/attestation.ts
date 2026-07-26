import { exec } from 'child_process';
import { promisify } from 'util';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  randomUUID,
} from 'crypto';
import { writeFile, readFile, mkdir, mkdtemp, rm, link, rename } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { createLogger } from '../../utils/logger.js';
import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';

const execAsync = promisify(exec);
const logger = createLogger('attestation');

// Directory for local signing keys (scanner container runs as non-root user)
const KEYS_DIR = process.env.SIGNING_KEYS_DIR || '/app/keys';
const PRIVATE_KEY_PATH = `${KEYS_DIR}/attestation-signing.pem`;
const PUBLIC_KEY_PATH = `${KEYS_DIR}/attestation-signing.pub`;

export interface ScanAttestation {
  id: string;
  scanId: string;
  projectId: string;
  timestamp: string;
  subject: AttestationSubject;
  predicate: ScanPredicate;
  signature?: string;
  signatureAlgorithm?: string;
  certificate?: string;
  rekorLogId?: string;
}

interface AttestationSubject {
  name: string;
  digest: { sha256: string };
}

interface ScanPredicate {
  type: 'https://codehardener.com/scan/v1';
  scanMetadata: {
    scanId: string;
    profile: string;
    scannersUsed: string[];
    startTime: string;
    endTime: string;
    duration: number;
  };
  findings: {
    total: number;
    bySeverity: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
  };
  score: number;
  qualityLevel: string;
  sbom?: {
    format: string;
    packageCount: number;
    generatedAt: string;
  };
}

/**
 * Read the signing keypair off disk. Returns null if it has not been created
 * yet; any other error (permissions, unreadable key) is surfaced.
 *
 * The private key file is the single source of truth and the public half is
 * derived from it. Two files cannot be created in one step, so reading both
 * would let a caller arriving mid-creation see half a keypair — which is
 * exactly the race this function exists to avoid. PUBLIC_KEY_PATH is written
 * for operators who need to hand the key out; nothing reads it back.
 */
async function readSigningKeys(): Promise<{ privateKey: string; publicKey: string } | null> {
  let privateKey: string;
  try {
    privateKey = await readFile(PRIVATE_KEY_PATH, 'utf-8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }

  const publicKey = createPublicKey(privateKey)
    .export({ type: 'spki', format: 'pem' })
    .toString();

  return { privateKey, publicKey };
}

/**
 * Ensure local signing keypair exists. Generate if missing.
 * Uses Ed25519 for fast, compact signatures.
 */
async function ensureSigningKeys(): Promise<{ privateKey: string; publicKey: string }> {
  const existing = await readSigningKeys();
  if (existing) {
    return existing;
  }

  // Create keys directory
  await mkdir(KEYS_DIR, { recursive: true });

  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });

  // Publish the keypair through a staging directory rather than writing
  // straight to PRIVATE_KEY_PATH. The old existsSync()-then-writeFile sequence
  // left a window in which the path could be replaced by a symlink and the
  // Ed25519 *private* key written through it, and in which two workers
  // starting together would each write a different keypair over the other.
  //
  // link() is the commit: it is atomic, it fails with EEXIST instead of
  // clobbering, it will not follow a symlink at the destination, and it only
  // ever exposes a file whose contents are already complete.
  const stagingDir = await mkdtemp(join(KEYS_DIR, '.staging-'));
  try {
    const stagedPrivate = join(stagingDir, 'private.pem');
    const stagedPublic = join(stagingDir, 'public.pem');
    await writeFile(stagedPrivate, privateKey, { mode: 0o600 });
    await writeFile(stagedPublic, publicKey, { mode: 0o644 });

    try {
      await link(stagedPrivate, PRIVATE_KEY_PATH);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
        throw error;
      }
      // Another worker committed first. Use its key and discard ours, so every
      // worker in the process group signs with the same key.
      const winner = await readSigningKeys();
      if (!winner) {
        throw error;
      }
      return winner;
    }

    // We own the keypair now, so the public half is ours to publish. rename()
    // replaces any stale .pub left behind by an interrupted earlier run, and
    // replaces a symlink rather than writing through it.
    await rename(stagedPublic, PUBLIC_KEY_PATH);
  } finally {
    await rm(stagingDir, { recursive: true, force: true }).catch(() => {});
  }

  logger.info({ keysDir: KEYS_DIR }, 'Generated new Ed25519 signing keypair for attestations');

  return { privateKey, publicKey };
}

/**
 * Create an in-toto style attestation for a scan result
 */
export async function createScanAttestation(
  scanId: string,
  projectId: string,
  projectName: string,
  scanResult: {
    profile: string;
    scannersUsed: string[];
    startTime: Date;
    endTime: Date;
    duration: number;
    findings: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
      total: number;
    };
    score: number;
    qualityLevel: string;
  }
): Promise<ScanAttestation> {
  const attestationId = randomUUID();
  const timestamp = new Date().toISOString();

  // Create content hash for subject
  const contentToHash = JSON.stringify({
    scanId,
    projectId,
    findings: scanResult.findings,
    score: scanResult.score,
    timestamp,
  });
  const contentHash = createHash('sha256').update(contentToHash).digest('hex');

  const attestation: ScanAttestation = {
    id: attestationId,
    scanId,
    projectId,
    timestamp,
    subject: {
      name: projectName,
      digest: { sha256: contentHash },
    },
    predicate: {
      type: 'https://codehardener.com/scan/v1',
      scanMetadata: {
        scanId,
        profile: scanResult.profile,
        scannersUsed: scanResult.scannersUsed,
        startTime: scanResult.startTime.toISOString(),
        endTime: scanResult.endTime.toISOString(),
        duration: scanResult.duration,
      },
      findings: {
        total: scanResult.findings.total,
        bySeverity: {
          critical: scanResult.findings.critical,
          high: scanResult.findings.high,
          medium: scanResult.findings.medium,
          low: scanResult.findings.low,
          info: scanResult.findings.info,
        },
      },
      score: scanResult.score,
      qualityLevel: scanResult.qualityLevel,
    },
  };

  logger.info({ attestationId, scanId }, 'Created scan attestation');

  return attestation;
}

/**
 * Sign attestation using Sigstore (cosign) if available,
 * falling back to local Ed25519 signing.
 */
export async function signAttestation(
  attestation: ScanAttestation
): Promise<{ signature: string; certificate: string; rekorLogId: string; algorithm: string } | null> {
  // Try Sigstore first
  const sigstoreResult = await signWithSigstore(attestation);
  if (sigstoreResult) {
    return { ...sigstoreResult, algorithm: 'sigstore-cosign' };
  }

  // Fall back to local Ed25519 signing
  const localResult = await signWithLocalKey(attestation);
  if (localResult) {
    return { ...localResult, algorithm: 'ed25519-local' };
  }

  return null;
}

/**
 * Sign with Sigstore/cosign (requires cosign binary + OIDC identity)
 */
async function signWithSigstore(
  attestation: ScanAttestation
): Promise<{ signature: string; certificate: string; rekorLogId: string } | null> {
  // mkdtemp creates a 0700 directory with a random suffix, atomically. The
  // previous `/tmp/attestation-<id>.<ext>` names were predictable, and cosign
  // is told to WRITE the signature and certificate to two of them — another
  // local user could pre-create those paths as symlinks and capture or
  // substitute the signing output (CodeQL js/insecure-temporary-file).
  const workDir = await mkdtemp(join(tmpdir(), 'attestation-'));
  const tempFile = join(workDir, 'attestation.json');
  const sigFile = join(workDir, 'attestation.sig');
  const certFile = join(workDir, 'attestation.crt');

  try {
    await writeFile(tempFile, JSON.stringify(attestation, null, 2));

    const { stdout } = await execAsync(
      `cosign sign-blob --yes --output-signature ${sigFile} --output-certificate ${certFile} ${tempFile} 2>&1`,
      { timeout: 10000 }
    );

    const rekorMatch = stdout.match(/tlog entry created with index: (\d+)/);
    const rekorLogId = rekorMatch ? rekorMatch[1] : null;

    const signature = await readFile(sigFile, 'utf-8');
    const certificate = await readFile(certFile, 'utf-8');

    logger.info(
      { attestationId: attestation.id, rekorLogId },
      'Attestation signed with Sigstore'
    );

    return {
      signature: signature.trim(),
      certificate: certificate.trim(),
      rekorLogId: rekorLogId || '',
    };
  } catch {
    logger.debug(
      { attestationId: attestation.id },
      'Sigstore not available, will use local signing'
    );
    return null;
  } finally {
    // Remove the whole mkdtemp directory, not the three files individually —
    // cosign may leave other output behind and the directory itself must go.
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * Sign with local Ed25519 keypair.
 * The public key PEM is stored as the "certificate" field for verification.
 */
async function signWithLocalKey(
  attestation: ScanAttestation
): Promise<{ signature: string; certificate: string; rekorLogId: string } | null> {
  try {
    const { privateKey, publicKey } = await ensureSigningKeys();

    // Sign using deterministic fields that survive DB round-trip without change.
    // subject.digest.sha256 already covers scan content + timestamp via createScanAttestation.
    const payload = `${attestation.id}:${attestation.scanId}:${attestation.subject.digest.sha256}`;

    // Ed25519 uses crypto.sign directly (null algorithm — Ed25519 has built-in hashing)
    const signature = cryptoSign(null, Buffer.from(payload), privateKey).toString('base64');

    logger.info(
      { attestationId: attestation.id },
      'Attestation signed with local Ed25519 key'
    );

    return {
      signature,
      certificate: publicKey.trim(),
      rekorLogId: '',
    };
  } catch (error) {
    logger.error(
      { error, attestationId: attestation.id },
      'Local signing failed'
    );
    return null;
  }
}

/**
 * Verify an attestation signature.
 * Supports both Sigstore (cosign) and local Ed25519 signatures.
 */
export async function verifyAttestation(
  attestation: ScanAttestation
): Promise<{ valid: boolean; error?: string }> {
  if (!attestation.signature || !attestation.certificate) {
    return { valid: false, error: 'Attestation is not signed' };
  }

  // Detect if this is a local Ed25519 signature (certificate is a PEM public key)
  if (attestation.certificate.includes('PUBLIC KEY')) {
    return verifyWithLocalKey(attestation);
  }

  // Otherwise try cosign verification
  return verifyWithSigstore(attestation);
}

/**
 * Verify with local Ed25519 public key
 */
function verifyWithLocalKey(
  attestation: ScanAttestation
): { valid: boolean; error?: string } {
  try {
    // Must match the payload format used in signWithLocalKey
    const payload = `${attestation.id}:${attestation.scanId}:${attestation.subject.digest.sha256}`;

    // Ed25519 uses crypto.verify directly (null algorithm — Ed25519 has built-in hashing)
    const valid = cryptoVerify(
      null,
      Buffer.from(payload),
      attestation.certificate!,
      Buffer.from(attestation.signature!, 'base64')
    );

    if (valid) {
      logger.info({ attestationId: attestation.id }, 'Attestation verified with local key');
    } else {
      logger.warn({ attestationId: attestation.id }, 'Attestation signature mismatch');
    }

    return { valid, error: valid ? undefined : 'Signature verification failed' };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Local verification failed';
    logger.warn({ error, attestationId: attestation.id }, 'Local attestation verification failed');
    return { valid: false, error: errorMsg };
  }
}

/**
 * Verify with Sigstore/cosign
 */
async function verifyWithSigstore(
  attestation: ScanAttestation
): Promise<{ valid: boolean; error?: string }> {
  // Same reasoning as signWithSigstore, and it matters more here: these three
  // files are the inputs to `cosign verify-blob`, so swapping them at a
  // predictable path would decide the outcome of the verification.
  const workDir = await mkdtemp(join(tmpdir(), 'verify-'));
  const tempFile = join(workDir, 'attestation.json');
  const sigFile = join(workDir, 'attestation.sig');
  const certFile = join(workDir, 'attestation.crt');

  try {
    await writeFile(tempFile, JSON.stringify(attestation, null, 2));
    await writeFile(sigFile, attestation.signature!);
    await writeFile(certFile, attestation.certificate!);

    await execAsync(
      `cosign verify-blob --signature ${sigFile} --certificate ${certFile} --certificate-identity-regexp ".*" --certificate-oidc-issuer-regexp ".*" ${tempFile}`,
      { timeout: 30000 }
    );

    logger.info({ attestationId: attestation.id }, 'Attestation verified with Sigstore');
    return { valid: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Sigstore verification failed';
    logger.warn({ error, attestationId: attestation.id }, 'Sigstore attestation verification failed');
    return { valid: false, error: errorMsg };
  } finally {
    // Remove the whole mkdtemp directory, not the three files individually —
    // cosign may leave other output behind and the directory itself must go.
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * Store attestation in database
 */
export async function storeAttestation(attestation: ScanAttestation): Promise<void> {
  await db.execute(sql`
    INSERT INTO attestations (
      id, scan_id, attestation_type, subject_name, subject_digest,
      predicate_type, attestation_json, signature, signature_algorithm,
      certificate, rekor_log_id, created_at
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
      ${attestation.timestamp}
    )
  `);

  logger.info({ attestationId: attestation.id }, 'Attestation stored in database');
}

/**
 * Get attestation by scan ID
 */
export async function getAttestationByScanId(scanId: string): Promise<ScanAttestation | null> {
  const result = await db.execute(sql`
    SELECT * FROM attestations WHERE scan_id = ${scanId}
  `);

  if (result.rows.length === 0) {
    return null;
  }

  const row = result.rows[0] as Record<string, unknown>;

  return {
    id: row.id as string,
    scanId: row.scan_id as string,
    projectId: '',
    timestamp: row.created_at as string,
    subject: {
      name: row.subject_name as string,
      digest: { sha256: row.subject_digest as string },
    },
    predicate: row.predicate as ScanPredicate,
    signature: row.signature as string | undefined,
    signatureAlgorithm: row.signature_algorithm as string | undefined,
    certificate: row.certificate as string | undefined,
    rekorLogId: row.rekor_log_id as string | undefined,
  };
}

/**
 * Generate attestation bundle (for download/verification)
 */
export function generateAttestationBundle(attestation: ScanAttestation): string {
  const bundle = {
    mediaType: 'application/vnd.codehardener.attestation+json',
    attestation: {
      _type: 'https://in-toto.io/Statement/v0.1',
      subject: [attestation.subject],
      predicateType: attestation.predicate.type,
      predicate: attestation.predicate,
    },
    signatureAlgorithm: attestation.signatureAlgorithm || 'unknown',
    signatures: attestation.signature
      ? [
          {
            keyid: attestation.signatureAlgorithm === 'ed25519-local' ? 'local-ed25519' : '',
            sig: attestation.signature,
            cert: attestation.certificate,
          },
        ]
      : [],
    rekorBundle: attestation.rekorLogId
      ? {
          logId: attestation.rekorLogId,
          logIndex: attestation.rekorLogId,
        }
      : null,
  };

  return JSON.stringify(bundle, null, 2);
}
