import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import {
  listAttestations,
  getAttestation,
  createAttestationFromScan,
  verifyAttestationEndpoint,
  downloadAttestationBundle,
  resignAttestationEndpoint,
} from '../controllers/attestations.controller.js';

const router = Router();

// List attestations with pagination
router.get('/', authenticate, asyncHandler(listAttestations));

// Get single attestation
router.get('/:id', authenticate, asyncHandler(getAttestation));

// Generate attestation from completed scan
router.post('/', authenticate, asyncHandler(createAttestationFromScan));

// Re-sign unsigned attestation
router.post('/:id/resign', authenticate, asyncHandler(resignAttestationEndpoint));

// Verify attestation signature
router.get('/:id/verify', authenticate, asyncHandler(verifyAttestationEndpoint));

// Download attestation bundle
router.get('/:id/bundle', authenticate, asyncHandler(downloadAttestationBundle));

export { router as attestationsRoutes };
