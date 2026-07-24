import type { DetectedProjectContext } from '../../types/index.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('smart-selection');

/** Profiles that support DAST augmentation (must match PROFILE_SCANNERS in pipeline.ts) */
const DAST_PROFILES = new Set(['comprehensive', 'security', 'api']);

interface ScanContext {
  targetUrl?: string;
  containerImage?: string;
  detectedSpecs?: DetectedProjectContext;
}

/**
 * Context-aware scanner augmentation. Given a base scanner list (from profile + language scope),
 * adds additional scanners based on available DAST context.
 *
 * Does NOT remove scanners — that happens inside each scanner's skip logic so skip reasons
 * are always visible in the Scanner Coverage UI.
 */
export function augmentScannersWithContext(
  baseScanners: string[],
  profile: string,
  context: ScanContext,
): string[] {
  const scanners = [...baseScanners];
  const addIfMissing = (scanner: string) => {
    if (!scanners.includes(scanner)) {
      scanners.push(scanner);
    }
  };

  const isDastProfile = DAST_PROFILES.has(profile);

  // targetUrl → DAST, accessibility, browser
  if (context.targetUrl && isDastProfile) {
    addIfMissing('zap');
    addIfMissing('nuclei');
    addIfMissing('pa11y');
  }

  // OpenAPI specs → API testing
  if (context.detectedSpecs?.openapi?.length) {
    addIfMissing('spectral');
    if (isDastProfile) {
      addIfMissing('schemathesis');
      addIfMissing('restler');
    }
  }

  // Postman collections → Newman
  if (context.detectedSpecs?.postmanCollections?.length) {
    addIfMissing('newman');
  }

  // Pact contracts → Pact
  if (context.detectedSpecs?.pactContracts?.length) {
    addIfMissing('pact');
  }

  // Container image → Dockle (Trivy/Grype get image mode but are already in most profiles)
  if (context.containerImage) {
    addIfMissing('dockle');
  }

  if (scanners.length > baseScanners.length) {
    const added = scanners.filter(s => !baseScanners.includes(s));
    logger.info({ profile, added }, 'Context-aware scanner augmentation');
  }

  return scanners;
}
