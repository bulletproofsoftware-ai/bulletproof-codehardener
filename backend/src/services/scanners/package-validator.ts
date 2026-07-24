import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const logger = createLogger('scanner-package-validator');

const SCAN_TARGET = '/scan-target';
const CONCURRENCY = 10;
const REQUEST_TIMEOUT = 5000;

interface PackageInfo {
  name: string;
  version: string;
  ecosystem: 'npm' | 'pypi' | 'go';
  source: string; // lockfile path
}

interface ValidationResult {
  pkg: PackageInfo;
  exists: boolean;
  statusCode: number;
  error?: string;
}

// ─── Lockfile Parsers ────────────────────────────────────────────

function parsePackageJson(content: string, filePath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  try {
    const pkg = JSON.parse(content);
    for (const [name, version] of Object.entries(pkg.dependencies || {})) {
      packages.push({ name, version: String(version), ecosystem: 'npm', source: filePath });
    }
    for (const [name, version] of Object.entries(pkg.devDependencies || {})) {
      packages.push({ name, version: String(version), ecosystem: 'npm', source: filePath });
    }
  } catch { /* invalid JSON, skip */ }
  return packages;
}

function parseRequirementsTxt(content: string, filePath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('-') || line.startsWith('--')) continue;
    const cleaned = line.split('#')[0].trim().replace(/\[.*?\]/g, '');
    const match = cleaned.match(/^([a-zA-Z0-9_.-]+)\s*(?:[><=~!]+\s*([a-zA-Z0-9_.*-]+))?/);
    if (match?.[1]) {
      packages.push({
        name: match[1],
        version: match[2] || '',
        ecosystem: 'pypi',
        source: filePath,
      });
    }
  }
  return packages;
}

function parseGoMod(content: string, filePath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/g);
  const lines = requireBlock
    ? requireBlock.flatMap(b => b.replace(/require\s*\(/, '').replace(/\)/, '').split('\n'))
    : content.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('//') || line.startsWith('module ') || line.startsWith('go ')) continue;
    const match = line.match(/^([a-zA-Z0-9_./-]+)\s+(v[a-zA-Z0-9_.-]+)/);
    if (match) {
      packages.push({
        name: match[1],
        version: match[2],
        ecosystem: 'go',
        source: filePath,
      });
    }
  }
  return packages;
}

// ─── Registry Validators ─────────────────────────────────────────

function getRegistryUrl(pkg: PackageInfo): string {
  switch (pkg.ecosystem) {
    case 'npm':
      return `https://registry.npmjs.org/${encodeURIComponent(pkg.name)}`;
    case 'pypi':
      return `https://pypi.org/pypi/${encodeURIComponent(pkg.name)}/json`;
    case 'go':
      return `https://proxy.golang.org/${pkg.name}/@latest`;
  }
}

async function validatePackage(pkg: PackageInfo): Promise<ValidationResult> {
  const url = getRegistryUrl(pkg);
  try {
    const response = await fetch(url, {
      method: 'HEAD',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
      headers: { 'Accept': 'application/json' },
    });
    return {
      pkg,
      exists: response.ok,
      statusCode: response.status,
    };
  } catch (error) {
    // Network error or timeout — don't flag as hallucinated
    return {
      pkg,
      exists: true, // fail open
      statusCode: 0,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

async function validateBatch(packages: PackageInfo[]): Promise<ValidationResult[]> {
  const results: ValidationResult[] = [];
  for (let i = 0; i < packages.length; i += CONCURRENCY) {
    const batch = packages.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.allSettled(batch.map(validatePackage));
    for (const result of batchResults) {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      }
    }
  }
  return results;
}

// ─── Scanner Entry Point ─────────────────────────────────────────

export async function runPackageValidator(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];
  const allPackages: PackageInfo[] = [];

  try {
    // Discover lockfiles
    const lockfiles: Array<{ path: string; parser: (c: string, p: string) => PackageInfo[] }> = [];

    // npm
    for (const name of ['package.json']) {
      const fullPath = `${SCAN_TARGET}/${name}`;
      if (existsSync(fullPath)) {
        lockfiles.push({ path: fullPath, parser: parsePackageJson });
      }
    }

    // PyPI
    for (const name of ['requirements.txt', 'requirements/base.txt', 'requirements/prod.txt']) {
      const fullPath = `${SCAN_TARGET}/${name}`;
      if (existsSync(fullPath)) {
        lockfiles.push({ path: fullPath, parser: parseRequirementsTxt });
      }
    }
    // Also try Pipfile (just the [packages] section)
    if (existsSync(`${SCAN_TARGET}/Pipfile`)) {
      lockfiles.push({ path: `${SCAN_TARGET}/Pipfile`, parser: parseRequirementsTxt });
    }

    // Go
    if (existsSync(`${SCAN_TARGET}/go.mod`)) {
      lockfiles.push({ path: `${SCAN_TARGET}/go.mod`, parser: parseGoMod });
    }

    if (lockfiles.length === 0) {
      logger.info('No dependency files found, skipping package validation');
      return {
        scanner: 'package-validator',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No dependency files found (package.json, requirements.txt, go.mod)',
      };
    }

    // Parse all lockfiles
    for (const { path, parser } of lockfiles) {
      try {
        const content = await readFile(path, 'utf-8');
        const parsed = parser(content, path.replace(`${SCAN_TARGET}/`, ''));
        allPackages.push(...parsed);
      } catch (error) {
        logger.warn({ path, error }, 'Failed to parse lockfile');
      }
    }

    // Deduplicate by name+ecosystem
    const seen = new Set<string>();
    const uniquePackages = allPackages.filter(pkg => {
      const key = `${pkg.ecosystem}:${pkg.name}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    if (uniquePackages.length === 0) {
      logger.info('No packages found in dependency files');
      return {
        scanner: 'package-validator',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No packages found in dependency files',
      };
    }

    logger.info({ packageCount: uniquePackages.length }, 'Validating package existence');

    // Validate all packages against registries
    const results = await validateBatch(uniquePackages);

    const hallucinated = results.filter(r => !r.exists && r.statusCode === 404);
    const validated = results.filter(r => r.exists);
    const errors = results.filter(r => r.error);

    // Create findings for hallucinated packages
    for (const result of hallucinated) {
      findings.push({
        ruleId: 'HALLUCINATED-PKG-001',
        severity: 'critical',
        title: `Hallucinated package: ${result.pkg.name} does not exist in ${result.pkg.ecosystem}`,
        description: `The package "${result.pkg.name}" was declared as a dependency but does not exist in the ${result.pkg.ecosystem} registry. ` +
          `This is a common pattern in AI-generated code where the AI model invents plausible but non-existent package names. ` +
          `This poses a critical supply chain risk: attackers can register these hallucinated names with malicious code (slopsquatting attack).`,
        filePath: result.pkg.source,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: `"${result.pkg.name}": "${result.pkg.version}"`,
        cweId: 'CWE-829',
        owaspCategory: 'A08:2021-Software and Data Integrity Failures',
        fixAvailable: true,
        fixDescription: `Remove "${result.pkg.name}" from your dependencies. If you need this functionality, search the ${result.pkg.ecosystem} registry for a real package that provides it.`,
        metadata: {
          ecosystem: result.pkg.ecosystem,
          registryUrl: getRegistryUrl(result.pkg),
          httpStatus: result.statusCode,
          packageVersion: result.pkg.version,
          attackVector: 'slopsquatting',
        },
      });
    }

    logger.info({
      total: uniquePackages.length,
      validated: validated.length,
      hallucinated: hallucinated.length,
      errors: errors.length,
    }, 'Package validation completed');

    return {
      scanner: 'package-validator',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({
        total: uniquePackages.length,
        validated: validated.length,
        hallucinated: hallucinated.map(r => ({ name: r.pkg.name, ecosystem: r.pkg.ecosystem })),
        errors: errors.length,
      }, null, 2),
      evidence: {
        checksPerformed: [
          'npm registry existence validation',
          'PyPI registry existence validation',
          'Go module proxy existence validation',
          'Slopsquatting risk detection',
          'Hallucinated dependency identification',
        ],
        scanScope: `Validated ${uniquePackages.length} packages across ${lockfiles.length} dependency file(s)`,
        filesAnalyzed: lockfiles.length,
        rulesEvaluated: 1,
        configuration: `Concurrency: ${CONCURRENCY}, Timeout: ${REQUEST_TIMEOUT}ms per request`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Package validation failed');
    return {
      scanner: 'package-validator',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
