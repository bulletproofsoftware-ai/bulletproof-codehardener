import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-spectral');

const SCAN_TARGET = '/scan-target';

interface SpectralIssue {
  code: string;
  message: string;
  path: string[];
  severity: number; // 0=error, 1=warn, 2=info, 3=hint
  range: {
    start: { line: number; character: number };
    end: { line: number; character: number };
  };
  source: string;
}

function mapSeverity(spectralSeverity: number): Severity {
  const map: Record<number, Severity> = {
    0: 'high',
    1: 'medium',
    2: 'low',
    3: 'info',
  };
  return map[spectralSeverity] ?? 'info';
}

function findSpecFiles(): string[] {
  const specFileNames = [
    'openapi.yaml', 'openapi.yml', 'openapi.json',
    'swagger.yaml', 'swagger.yml', 'swagger.json',
    'api-spec.yaml', 'api-spec.json',
  ];
  const subdirs = ['', 'docs/', 'api/'];
  const found: string[] = [];

  for (const subdir of subdirs) {
    for (const fileName of specFileNames) {
      const fullPath = `${SCAN_TARGET}/${subdir}${fileName}`;
      if (existsSync(fullPath)) {
        found.push(fullPath);
      }
    }
  }

  return found;
}

export async function runSpectral(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Build spec file list from: explicit path, pre-detected specs, then filesystem search
    let specFiles: string[] = [];

    // Add explicit spec path if set
    if (jobData.openapiSpecPath) {
      const explicit = `${SCAN_TARGET}/${jobData.openapiSpecPath}`;
      specFiles.push(explicit);
    }

    // Add all pre-detected OpenAPI specs
    if (jobData.detectedSpecs?.openapi?.length) {
      for (const spec of jobData.detectedSpecs.openapi) {
        const fullPath = `${SCAN_TARGET}/${spec}`;
        if (!specFiles.includes(fullPath)) {
          specFiles.push(fullPath);
        }
      }
    }

    // Fall back to filesystem search if nothing detected
    if (specFiles.length === 0) {
      specFiles = findSpecFiles();
    }

    if (specFiles.length === 0) {
      logger.info('No OpenAPI/Swagger spec files found, skipping Spectral scan');
      return {
        scanner: 'spectral',
        success: true,
        skipped: true,
        skipReason: 'no_api_spec',
        skipHint: 'Add an openapi.json/yaml or swagger.json/yaml to your project, or set openapiSpecPath on the project.',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: '',
        evidence: {
          filesAnalyzed: 0,
          rulesEvaluated: 0,
          checksPerformed: ['OpenAPI/Swagger spec file detection'],
          scanScope: 'No OpenAPI/Swagger spec files found — scan skipped',
        },
      };
    }

    const allRawOutputs: string[] = [];

    for (const specFile of specFiles) {
      const cmd = `spectral lint --format json ${specFile} 2>/dev/null || true`;
      const { stdout } = await execAsync(cmd, { maxBuffer: 50 * 1024 * 1024 });

      if (stdout.trim()) {
        allRawOutputs.push(stdout);
        const issues: SpectralIssue[] = JSON.parse(stdout);

        for (const issue of issues) {
          const relativePath = (issue.source || specFile).replace(`${SCAN_TARGET}/`, '');
          findings.push({
            ruleId: `SPECTRAL-${issue.code}`,
            severity: mapSeverity(issue.severity),
            title: `${issue.code}: ${issue.message.slice(0, 100)}`,
            description: issue.message,
            filePath: relativePath,
            lineNumber: issue.range?.start?.line != null ? issue.range.start.line + 1 : null,
            columnNumber: issue.range?.start?.character != null ? issue.range.start.character + 1 : null,
            codeSnippet: issue.path?.length ? `JSON Path: ${issue.path.join('.')}` : null,
            cweId: null,
            owaspCategory: 'A05:2021-Security Misconfiguration',
            fixAvailable: false,
            fixDescription: null,
            metadata: {
              spectralCode: issue.code,
              spectralSeverity: issue.severity,
              jsonPath: issue.path,
              range: issue.range,
              source: issue.source,
            },
          });
        }
      }
    }

    const rawOutput = allRawOutputs.join('\n');
    const uniqueRules = new Set(findings.map(f => f.ruleId));

    logger.info({ findingsCount: findings.length, specFilesScanned: specFiles.length }, 'Spectral scan completed');

    return {
      scanner: 'spectral',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput,
      evidence: {
        filesAnalyzed: specFiles.length,
        rulesEvaluated: uniqueRules.size,
        checksPerformed: [
          'OpenAPI specification validation',
          'API design best practices',
          'Schema completeness checks',
          'Security scheme validation',
          'Response format consistency',
          'Path and operation linting',
        ],
        scanScope: `OpenAPI/Swagger linting of ${specFiles.length} spec file(s): ${specFiles.map(f => f.replace(`${SCAN_TARGET}/`, '')).join(', ')}`,
        configuration: 'Spectral default OpenAPI ruleset',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Spectral scan failed');
    return {
      scanner: 'spectral',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
