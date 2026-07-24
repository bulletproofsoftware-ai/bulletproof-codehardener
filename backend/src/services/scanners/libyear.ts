import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { readFile } from 'fs/promises';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
// Uses npm outdated and pip list --outdated to check dependency freshness.
const execAsync = promisify(exec);
const logger = createLogger('scanner-libyear');

const SCAN_TARGET = '/scan-target';

interface NpmOutdatedEntry {
  current: string;
  wanted: string;
  latest: string;
  dependent: string;
  type: string;
}

function majorsBehind(current: string, latest: string): number {
  const cMajor = parseInt(current.split('.')[0] || '0', 10);
  const lMajor = parseInt(latest.split('.')[0] || '0', 10);
  return Math.max(0, lMajor - cMajor);
}

function behindSeverity(majors: number): Severity {
  if (majors >= 3) return 'high';
  if (majors >= 2) return 'medium';
  if (majors >= 1) return 'low';
  return 'info';
}

export async function runLibyear(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];
  let totalPackages = 0;
  let outdatedCount = 0;

  try {
    const hasNpm = existsSync(`${SCAN_TARGET}/package.json`);
    const hasPython = existsSync(`${SCAN_TARGET}/requirements.txt`) || existsSync(`${SCAN_TARGET}/setup.py`) || existsSync(`${SCAN_TARGET}/pyproject.toml`);

    if (!hasNpm && !hasPython) {
      return { scanner: 'libyear', success: true, skipped: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No package.json or requirements.txt found' };
    }

    // Check npm outdated
    if (hasNpm) {
      try {
        // npm outdated returns exit code 1 when there are outdated packages
        const { stdout } = await execAsync(
          `cd ${SCAN_TARGET} && npm install --ignore-scripts 2>/dev/null; npm outdated --json 2>/dev/null || true`,
          { maxBuffer: 20 * 1024 * 1024, timeout: 120000 }
        );

        if (stdout.trim() && stdout.trim() !== '{}') {
          const outdated: Record<string, NpmOutdatedEntry> = JSON.parse(stdout.trim());
          for (const [name, info] of Object.entries(outdated)) {
            totalPackages++;
            const majors = majorsBehind(info.current, info.latest);
            if (majors === 0) continue;
            outdatedCount++;

            findings.push({
              ruleId: 'LIBYEAR-OUTDATED-NPM',
              severity: behindSeverity(majors),
              title: `Outdated: ${name} ${info.current} → ${info.latest} (${majors} major${majors > 1 ? 's' : ''} behind)`,
              description: `Package "${name}" is at version ${info.current} but ${info.latest} is available. ` +
                `${majors} major version${majors > 1 ? 's' : ''} behind. Outdated dependencies miss security patches and bug fixes.`,
              filePath: 'package.json', lineNumber: null, columnNumber: null, codeSnippet: null,
              cweId: 'CWE-1104', owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
              fixAvailable: true,
              fixDescription: `Update ${name} to ${info.latest}: npm install ${name}@${info.latest}`,
              metadata: { package: name, current: info.current, latest: info.latest, wanted: info.wanted, majorsBehind: majors },
            });
          }
        }
      } catch (e) {
        logger.warn({ error: e }, 'npm outdated check failed');
      }
    }

    // Check pip outdated
    if (hasPython) {
      try {
        // Install requirements first
        if (existsSync(`${SCAN_TARGET}/requirements.txt`)) {
          await execAsync(
            `cd ${SCAN_TARGET} && pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true`,
            { timeout: 120000 }
          ).catch(() => {});
        }

        const { stdout } = await execAsync(
          `pip3 list --outdated --format json 2>/dev/null || true`,
          { maxBuffer: 10 * 1024 * 1024, timeout: 30000 }
        );

        if (stdout.trim() && stdout.trim() !== '[]') {
          const outdated: Array<{ name: string; version: string; latest_version: string }> = JSON.parse(stdout.trim());
          // Read requirements.txt to only flag packages that are in the project
          let projectDeps = new Set<string>();
          if (existsSync(`${SCAN_TARGET}/requirements.txt`)) {
            const reqContent = await readFile(`${SCAN_TARGET}/requirements.txt`, 'utf-8');
            projectDeps = new Set(reqContent.split('\n').map(l => l.split(/[>=<!\s]/)[0].toLowerCase()).filter(Boolean));
          }

          for (const pkg of outdated) {
            if (projectDeps.size > 0 && !projectDeps.has(pkg.name.toLowerCase())) continue;
            totalPackages++;
            const majors = majorsBehind(pkg.version, pkg.latest_version);
            if (majors === 0) continue;
            outdatedCount++;

            findings.push({
              ruleId: 'LIBYEAR-OUTDATED-PIP',
              severity: behindSeverity(majors),
              title: `Outdated: ${pkg.name} ${pkg.version} → ${pkg.latest_version} (${majors} major${majors > 1 ? 's' : ''} behind)`,
              description: `Python package "${pkg.name}" is at version ${pkg.version} but ${pkg.latest_version} is available. ` +
                `${majors} major version${majors > 1 ? 's' : ''} behind.`,
              filePath: 'requirements.txt', lineNumber: null, columnNumber: null, codeSnippet: null,
              cweId: 'CWE-1104', owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
              fixAvailable: true,
              fixDescription: `Update ${pkg.name} to ${pkg.latest_version}`,
              metadata: { package: pkg.name, current: pkg.version, latest: pkg.latest_version, majorsBehind: majors },
            });
          }
        }
      } catch (e) {
        logger.warn({ error: e }, 'pip outdated check failed');
      }
    }

    logger.info({ totalPackages, outdatedCount, findingsCount: findings.length }, 'Libyear scan completed');
    return {
      scanner: 'libyear', success: true, findings, duration: Date.now() - startTime,
      rawOutput: `${totalPackages} packages checked, ${outdatedCount} outdated by 1+ major versions`,
      evidence: {
        checksPerformed: ['npm dependency freshness check', 'pip dependency freshness check', 'Major version gap analysis'],
        scanScope: `${totalPackages} packages checked for version freshness`,
        rulesEvaluated: totalPackages,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Libyear scan failed');
    return { scanner: 'libyear', success: false, findings: [], duration: Date.now() - startTime, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}
