import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-cosign');

export async function runCosign(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  // Require an explicit container image reference from project settings
  if (!jobData.containerImage) {
    logger.info('No containerImage set — skipping cosign signature verification');
    return {
      scanner: 'cosign',
      success: true,
      skipped: true,
      skipReason: 'no_container_image',
      skipHint: 'Add Container Image in Project Settings to verify signatures',
      findings: [],
      duration: Date.now() - startTime,
    };
  }

  const imageRef = jobData.containerImage;

  try {
    const rawOutputParts: string[] = [];

    try {
      // Try strict verification first with known OIDC issuers
      let output = '';
      let usedWildcard = false;

      try {
        const strictResult = await execAsync(
          `cosign verify ${imageRef} --certificate-oidc-issuer=https://token.actions.githubusercontent.com --certificate-identity-regexp=".*" 2>&1`,
          { timeout: 30000 }
        );
        output = strictResult.stdout + strictResult.stderr;
      } catch {
        // Strict verification failed, fall back to wildcard (maximum compatibility)
        usedWildcard = true;
        const wildcardResult = await execAsync(
          `cosign verify ${imageRef} --certificate-identity-regexp=".*" --certificate-oidc-issuer-regexp=".*" 2>&1 || true`,
          { timeout: 30000 }
        );
        output = wildcardResult.stdout + wildcardResult.stderr;
      }

      rawOutputParts.push(output);

      // If wildcard was used and verification succeeded, add a low-severity advisory
      if (usedWildcard && !output.includes('no matching signatures') && !output.includes('could not find') && !output.includes('Error:') && !output.includes('FAILED')) {
        findings.push({
          ruleId: 'COSIGN-WILDCARD-ISSUER',
          severity: 'low',
          title: `Cosign: Wildcard OIDC Issuer Used for Verification`,
          description: `Container image "${imageRef}" was verified using a wildcard OIDC issuer. Strict issuer verification (GitHub Actions) failed. The signature is valid but the issuer could not be pinned to a known provider.`,
          filePath: null,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: 'CWE-295',
          owaspCategory: 'A08:2021-Software and Data Integrity Failures',
          fixAvailable: true,
          fixDescription: 'Sign images using a well-known OIDC issuer (e.g., GitHub Actions, Google Cloud Build) for stricter verification',
          metadata: {
            image: imageRef,
            verificationMode: 'wildcard',
          },
        });
      }

      if (output.includes('no matching signatures') || output.includes('could not find')) {
        findings.push({
          ruleId: 'COSIGN-UNSIGNED',
          severity: 'medium',
          title: `Cosign: Unsigned Container Image`,
          description: `Container image "${imageRef}" has no Sigstore signature`,
          filePath: null,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: 'CWE-494',
          owaspCategory: 'A08:2021-Software and Data Integrity Failures',
          fixAvailable: true,
          fixDescription: 'Use signed container images or sign images with cosign',
          metadata: {
            image: imageRef,
          },
        });
      } else if (output.includes('Error:') || output.includes('FAILED')) {
        findings.push({
          ruleId: 'COSIGN-VERIFY-FAIL',
          severity: 'high',
          title: `Cosign: Signature Verification Failed`,
          description: `Container image "${imageRef}" signature verification failed`,
          filePath: null,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: 'CWE-347',
          owaspCategory: 'A08:2021-Software and Data Integrity Failures',
          fixAvailable: false,
          fixDescription: 'Investigate signature verification failure',
          metadata: {
            image: imageRef,
            error: output.substring(0, 300),
          },
        });
      }
      // If verification succeeds with strict issuer, no finding needed
    } catch {
      // Verification failed or timed out
      findings.push({
        ruleId: 'COSIGN-CHECK-FAIL',
        severity: 'low',
        title: `Cosign: Could Not Verify Image`,
        description: `Could not check signature for "${imageRef}" (image may not exist in registry)`,
        filePath: null,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: 'A08:2021-Software and Data Integrity Failures',
        fixAvailable: false,
        fixDescription: 'Ensure image is pushed to registry before verification',
        metadata: {
          image: imageRef,
        },
      });
    }

    logger.info({ findingsCount: findings.length, image: imageRef }, 'Cosign signature verification completed');

    return {
      scanner: 'cosign',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: rawOutputParts.join('\n'),
      evidence: {
        checksPerformed: [
          'Sigstore signature verification',
          'OIDC issuer validation (strict + wildcard fallback)',
        ],
        scanScope: `Cosign signature verification for ${imageRef}`,
        configuration: `Image: ${imageRef}`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Cosign signature verification failed');
    return {
      scanner: 'cosign',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
