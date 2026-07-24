import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-pact');

export async function runPact(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Use pre-detected Pact contracts from project context, fall back to filesystem search
    let pactFiles = (jobData.detectedSpecs?.pactContracts || []).map(f => `/scan-target/${f}`);

    if (pactFiles.length === 0) {
      const { stdout: pactSearch } = await execAsync(
        `find /scan-target -name "*.pact.json" -o -name "*-pact.json" 2>/dev/null`
      );
      pactFiles = pactSearch.trim().split('\n').filter(Boolean);
    }

    if (pactFiles.length === 0) {
      logger.info('No Pact contract files found');
      return {
        scanner: 'pact',
        success: true,
        skipped: true,
        skipReason: 'no_pact_contracts',
        skipHint: 'Add *.pact.json or *-pact.json contract files to your project to enable Pact contract testing analysis.',
        findings: [],
        duration: Date.now() - startTime,
      };
    }

    for (const pactFile of pactFiles) {
      try {
        // Read and parse pact file
        const { stdout: pactContent } = await execAsync(`cat "${pactFile}"`);
        const pact = JSON.parse(pactContent);

        // Check for security-relevant patterns in contracts
        const interactions = pact.interactions || [];

        for (const interaction of interactions) {
          const request = interaction.request || {};
          const response = interaction.response || {};

          // Check for insecure patterns in contract
          if (request.headers) {
            // Check for hardcoded auth tokens
            const authHeader = request.headers['Authorization'] || request.headers['authorization'];
            if (authHeader && !authHeader.includes('{{') && !authHeader.includes('$')) {
              findings.push({
                ruleId: 'PACT-HARDCODED-AUTH',
                severity: 'high',
                title: 'Pact: Hardcoded Authorization in Contract',
                description: `Contract "${interaction.description}" contains hardcoded authorization header`,
                filePath: pactFile.replace('/scan-target/', ''),
                lineNumber: null,
                columnNumber: null,
                codeSnippet: null,
                cweId: 'CWE-798',
                owaspCategory: 'A07:2021-Identification and Authentication Failures',
                fixAvailable: true,
                fixDescription: 'Use environment variables or match patterns for auth headers',
                metadata: {
                  consumer: pact.consumer?.name,
                  provider: pact.provider?.name,
                  interaction: interaction.description,
                },
              });
            }
          }

          // Check for missing security headers in expected responses
          if (response.status === 200 && response.headers) {
            const securityHeaders = ['Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options'];
            const missingHeaders = securityHeaders.filter(
              h => !response.headers[h] && !response.headers[h.toLowerCase()]
            );

            if (missingHeaders.length > 0) {
              findings.push({
                ruleId: 'PACT-MISSING-SECURITY-HEADERS',
                severity: 'low',
                title: 'Pact: Contract Missing Security Headers',
                description: `Contract expects responses without: ${missingHeaders.join(', ')}`,
                filePath: pactFile.replace('/scan-target/', ''),
                lineNumber: null,
                columnNumber: null,
                codeSnippet: null,
                cweId: null,
                owaspCategory: 'A05:2021-Security Misconfiguration',
                fixAvailable: true,
                fixDescription: 'Update contract to expect security headers',
                metadata: {
                  missingHeaders,
                  interaction: interaction.description,
                },
              });
            }
          }
        }
      } catch {
        logger.warn({ pactFile }, 'Failed to parse pact file');
      }
    }

    logger.info({ findingsCount: findings.length, pactFiles: pactFiles.length }, 'Pact contract analysis completed');

    return {
      scanner: 'pact',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: pactFiles.map(f => f.replace('/scan-target/', '')).join('\n'),
    };
  } catch (error) {
    logger.error({ error }, 'Pact analysis failed');
    return {
      scanner: 'pact',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
