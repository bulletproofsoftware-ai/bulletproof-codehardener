/** @deprecated Removed from active scanner rotation in v2. Virtually no projects use .layout/.link files. Cosign + Sigstore cover attestation. */
import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-in-toto');

interface InTotoLink {
  _type: string;
  name: string;
  materials: Record<string, { sha256: string }>;
  products: Record<string, { sha256: string }>;
  byproducts: {
    return_value?: number;
    stdout?: string;
    stderr?: string;
  };
  environment: Record<string, string>;
}

export async function runInToto(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Look for in-toto layout and link files
    const rawOutputParts: string[] = [];

    const { stdout: layoutSearch } = await execAsync(
      `find /scan-target -name "*.layout" -o -name "root.layout" 2>/dev/null | head -1`
    );

    const { stdout: linkSearch } = await execAsync(
      `find /scan-target -name "*.link" 2>/dev/null`
    );

    const layoutFile = layoutSearch.trim();
    const linkFiles = linkSearch.trim().split('\n').filter(Boolean);

    if (!layoutFile && linkFiles.length === 0) {
      logger.info('No in-toto attestation files found');
      return {
        scanner: 'in-toto',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        skipReason: 'no_matching_files',
        skipHint: 'No in-toto layout or link metadata files found',
      };
    }

    // Analyze link files for supply chain issues
    for (const linkFile of linkFiles) {
      try {
        const { stdout: linkContent } = await execAsync(`cat "${linkFile}"`);
        rawOutputParts.push(linkContent);
        const link: { signed: InTotoLink } = JSON.parse(linkContent);

        // Check for failed build steps
        if (link.signed.byproducts?.return_value && link.signed.byproducts.return_value !== 0) {
          findings.push({
            ruleId: 'INTOTO-STEP-FAILED',
            severity: 'high',
            title: `in-toto: Build Step Failed - ${link.signed.name}`,
            description: `Build step "${link.signed.name}" returned non-zero exit code: ${link.signed.byproducts.return_value}`,
            filePath: linkFile.replace('/scan-target/', ''),
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: 'CWE-693',
            owaspCategory: 'A08:2021-Software and Data Integrity Failures',
            fixAvailable: false,
            fixDescription: 'Investigate and fix the failed build step',
            metadata: {
              stepName: link.signed.name,
              returnValue: link.signed.byproducts.return_value,
              stderr: link.signed.byproducts.stderr?.substring(0, 500),
            },
          });
        }

        // Check for missing materials or products
        const materials = Object.keys(link.signed.materials || {});
        const products = Object.keys(link.signed.products || {});

        if (materials.length === 0 && products.length > 0) {
          findings.push({
            ruleId: 'INTOTO-NO-MATERIALS',
            severity: 'medium',
            title: `in-toto: Missing Materials - ${link.signed.name}`,
            description: `Build step "${link.signed.name}" has no recorded input materials`,
            filePath: linkFile.replace('/scan-target/', ''),
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: 'CWE-1127',
            owaspCategory: 'A08:2021-Software and Data Integrity Failures',
            fixAvailable: false,
            fixDescription: 'Ensure build step properly records input materials',
            metadata: {
              stepName: link.signed.name,
              productsCount: products.length,
            },
          });
        }
      } catch {
        findings.push({
          ruleId: 'INTOTO-INVALID-LINK',
          severity: 'medium',
          title: 'in-toto: Invalid Link File',
          description: `Could not parse link file: ${linkFile}`,
          filePath: linkFile.replace('/scan-target/', ''),
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: 'A08:2021-Software and Data Integrity Failures',
          fixAvailable: false,
          fixDescription: 'Ensure link file is valid JSON',
          metadata: {},
        });
      }
    }

    // Verify layout if present
    if (layoutFile) {
      try {
        // Attempt verification
        const { stderr } = await execAsync(
          `python3 -m in_toto.verifylib --layout ${layoutFile} --layout-keys /scan-target/*.pub 2>&1 || echo "verification failed"`,
          { timeout: 60000 }
        );

        if (stderr.includes('verification failed') || stderr.includes('Error')) {
          findings.push({
            ruleId: 'INTOTO-VERIFY-FAIL',
            severity: 'critical',
            title: 'in-toto: Supply Chain Verification Failed',
            description: 'Supply chain layout verification failed - artifacts may be tampered',
            filePath: layoutFile.replace('/scan-target/', ''),
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: 'CWE-494',
            owaspCategory: 'A08:2021-Software and Data Integrity Failures',
            fixAvailable: false,
            fixDescription: 'Review supply chain and ensure all attestations are valid',
            metadata: {
              error: stderr.substring(0, 500),
            },
          });
        }
      } catch {
        logger.warn('in-toto verification could not be performed (missing keys or deps)');
      }
    }

    logger.info({ findingsCount: findings.length }, 'in-toto supply chain analysis completed');

    return {
      scanner: 'in-toto',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: rawOutputParts.join('\n'),
    };
  } catch (error) {
    logger.error({ error }, 'in-toto supply chain analysis failed');
    return {
      scanner: 'in-toto',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
