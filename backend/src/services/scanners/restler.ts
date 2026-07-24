import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';
import type { Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-restler');

function mapBugSeverity(bugType: string): Severity {
  const severityMap: Record<string, Severity> = {
    '500': 'high',
    'UseAfterFree': 'critical',
    'InvalidDynamicObject': 'medium',
    'PayloadBodyChecker': 'high',
    'ResourceHierarchy': 'medium',
  };
  return severityMap[bugType] || 'medium';
}

export async function runRESTler(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Use explicit spec path, pre-detected OpenAPI spec, or fall back to filesystem search
    let specFile = jobData.openapiSpecPath
      ? `/scan-target/${jobData.openapiSpecPath}`
      : jobData.detectedSpecs?.openapi?.[0]
        ? `/scan-target/${jobData.detectedSpecs.openapi[0]}`
        : '';

    if (!specFile) {
      const { stdout: specSearch } = await execAsync(
        `find /scan-target -name "openapi.json" -o -name "openapi.yaml" -o -name "swagger.json" -o -name "swagger.yaml" 2>/dev/null | head -1`
      );
      specFile = specSearch.trim();
    }

    if (!specFile) {
      logger.info('No OpenAPI/Swagger spec found for RESTler');
      return {
        scanner: 'restler',
        success: true,
        skipped: true,
        skipReason: 'no_api_spec',
        skipHint: 'Add an openapi.json/yaml or swagger.json/yaml to your project, or set openapiSpecPath on the project.',
        findings: [],
        duration: Date.now() - startTime,
      };
    }

    const outputDir = `/tmp/restler-output-${Date.now()}`;
    let bugsOutput = '';

    // Compile spec for RESTler
    await execAsync(`mkdir -p ${outputDir}`);

    try {
      // RESTler compile step
      await execAsync(
        `python3 -m restler compile --api_spec "${specFile}" --output_dir ${outputDir}/Compile 2>/dev/null || true`,
        { timeout: 60000 }
      );

      // RESTler quick fuzz — use targetUrl if provided, otherwise default to localhost:8080
      let targetIp = 'localhost';
      let targetPort = '8080';
      if (jobData.targetUrl) {
        try {
          const parsed = new URL(jobData.targetUrl);
          targetIp = parsed.hostname;
          targetPort = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
        } catch { /* use defaults */ }
      }

      await execAsync(
        `python3 -m restler fuzz-lean --grammar_file ${outputDir}/Compile/grammar.py --dictionary_file ${outputDir}/Compile/dict.json --target_ip ${targetIp} --target_port ${targetPort} --time_budget 60 --output_dir ${outputDir}/Fuzz 2>/dev/null || true`,
        { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }
      );

      // Check for bugs found
      const { stdout: bugsStdout } = await execAsync(`cat ${outputDir}/Fuzz/RestlerResults/bugs/* 2>/dev/null || echo ""`);
      bugsOutput = bugsStdout;

      if (bugsOutput.trim()) {
        // Parse bug files
        const bugFiles = bugsOutput.split('---').filter(Boolean);
        for (const bugContent of bugFiles) {
          const lines = bugContent.split('\n');
          const typeLine = lines.find(l => l.includes('Bug Type:'));
          const endpointLine = lines.find(l => l.includes('Endpoint:'));
          const statusLine = lines.find(l => l.includes('Status:'));

          if (typeLine) {
            const bugType = typeLine.replace('Bug Type:', '').trim();
            const endpoint = endpointLine?.replace('Endpoint:', '').trim() || 'Unknown';
            const status = statusLine?.replace('Status:', '').trim() || '';

            findings.push({
              ruleId: `RESTLER-${bugType.toUpperCase().replace(/\s+/g, '-')}`,
              severity: mapBugSeverity(bugType),
              title: `RESTler: ${bugType}`,
              description: `API fuzzing detected ${bugType} vulnerability at ${endpoint}`,
              filePath: specFile.replace('/scan-target/', ''),
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: getCWEForBug(bugType),
              owaspCategory: 'A03:2021-Injection',
              fixAvailable: false,
              fixDescription: 'Review and fix the API endpoint to handle malformed inputs',
              metadata: {
                endpoint,
                status,
                bugType,
              },
            });
          }
        }
      }
    } catch (innerError) {
      logger.warn('RESTler fuzzing did not complete (requires running target)');
      return {
        scanner: 'restler',
        success: false,
        findings: [],
        duration: Date.now() - startTime,
        error: `RESTler compile/fuzz failed: ${innerError instanceof Error ? innerError.message : 'Unknown error'}`,
      };
    }

    logger.info({ findingsCount: findings.length }, 'RESTler API fuzzing completed');

    return {
      scanner: 'restler',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: bugsOutput,
    };
  } catch (error) {
    logger.error({ error }, 'RESTler API fuzzing failed');
    return {
      scanner: 'restler',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

function getCWEForBug(bugType: string): string | null {
  const cweMap: Record<string, string> = {
    '500': 'CWE-754',
    'UseAfterFree': 'CWE-416',
    'InvalidDynamicObject': 'CWE-20',
    'PayloadBodyChecker': 'CWE-20',
  };
  return cweMap[bugType] || null;
}
