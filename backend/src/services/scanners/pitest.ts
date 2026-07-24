import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-pitest');

const SCAN_TARGET = '/scan-target';

function mutationScoreToSeverity(score: number): Severity {
  if (score < 30) return 'high';
  if (score < 70) return 'medium';
  return 'low';
}

interface PitestMutation {
  detected: boolean;
  status: 'KILLED' | 'SURVIVED' | 'NO_COVERAGE' | 'TIMED_OUT' | 'NON_VIABLE' | 'MEMORY_ERROR' | 'RUN_ERROR';
  numberOfTestsRun: number;
  sourceFile: string;
  mutatedClass: string;
  mutatedMethod: string;
  methodDescription: string;
  lineNumber: number;
  mutator: string;
  indexes: number[];
  block: number;
  killingTest?: string;
  description: string;
}

export async function runPitest(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    const hasMaven = existsSync(`${SCAN_TARGET}/pom.xml`);
    const hasGradle = existsSync(`${SCAN_TARGET}/build.gradle`) || existsSync(`${SCAN_TARGET}/build.gradle.kts`);

    if (!hasMaven && !hasGradle) {
      return {
        scanner: 'pitest',
        success: true,
        skipped: true,
        skipReason: 'no_java_project',
        skipHint: 'No pom.xml or build.gradle found — Pitest requires a Maven or Gradle Java project',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'Not a Java/JVM project (no pom.xml or build.gradle)',
      };
    }

    // Check for test files
    let hasTests = false;
    try {
      const { stdout } = await execAsync(
        `find ${SCAN_TARGET} -maxdepth 5 -path "*/test*/*.java" -not -path "*/build/*" -not -path "*/target/*" 2>/dev/null | head -1`,
        { timeout: 5000 }
      );
      hasTests = stdout.trim().length > 0;
    } catch { /* no tests */ }

    if (!hasTests) {
      findings.push({
        ruleId: 'MUTATION-003',
        severity: 'high',
        title: 'No Java test files found for mutation testing',
        description: 'No Java test files were found in the project. ' +
          'Without tests, mutation testing cannot validate code quality.',
        filePath: hasMaven ? 'pom.xml' : 'build.gradle',
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: 'Add unit tests using JUnit 5 or TestNG.',
        metadata: { mutationScore: 0, reason: 'no-tests' },
      });

      return {
        scanner: 'pitest',
        success: true,
        findings,
        duration: Date.now() - startTime,
        rawOutput: 'No Java test files found',
      };
    }

    // Run pitest via Maven or Gradle
    let cmd: string;
    let reportPath: string;

    if (hasMaven) {
      cmd = `cd ${SCAN_TARGET} && mvn -q org.pitest:pitest-maven:mutationCoverage ` +
        `-DoutputFormats=XML -DtimestampedReports=false ` +
        `-Dthreads=2 -DmutationThreshold=0 ` +
        `2>/dev/null || true`;
      reportPath = `${SCAN_TARGET}/target/pit-reports/mutations.xml`;
    } else {
      cmd = `cd ${SCAN_TARGET} && ./gradlew pitest --no-daemon -q 2>/dev/null || true`;
      reportPath = `${SCAN_TARGET}/build/reports/pitest/mutations.xml`;
    }

    await execAsync(cmd, { maxBuffer: 100 * 1024 * 1024, timeout: 300000 });

    // Parse XML mutations report
    if (!existsSync(reportPath)) {
      logger.warn('pitest produced no report — pitest plugin may not be configured');
      return {
        scanner: 'pitest',
        success: false,
        findings: [],
        duration: Date.now() - startTime,
        error: 'pitest produced no mutations.xml report. Add pitest-maven plugin to pom.xml or gradle-pitest-plugin to build.gradle.',
      };
    }

    const xmlContent = await readFile(reportPath, 'utf-8');

    // Simple XML parser for pitest mutations
    const mutations: PitestMutation[] = [];
    const mutationRegex = /<mutation detected="(true|false)" status="(\w+)" numberOfTestsRun="(\d+)">([\s\S]*?)<\/mutation>/g;
    let match;

    while ((match = mutationRegex.exec(xmlContent)) !== null) {
      const body = match[4];
      const getValue = (tag: string) => {
        const m = body.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
        return m ? m[1] : '';
      };

      mutations.push({
        detected: match[1] === 'true',
        status: match[2] as PitestMutation['status'],
        numberOfTestsRun: parseInt(match[3]),
        sourceFile: getValue('sourceFile'),
        mutatedClass: getValue('mutatedClass'),
        mutatedMethod: getValue('mutatedMethod'),
        methodDescription: getValue('methodDescription'),
        lineNumber: parseInt(getValue('lineNumber')) || 0,
        mutator: getValue('mutator').replace(/^org\.pitest\.mutationtest\.engine\.gregor\.mutators\./, ''),
        indexes: [],
        block: 0,
        killingTest: getValue('killingTest') || undefined,
        description: getValue('description'),
      });
    }

    const totalMutants = mutations.length;
    const killed = mutations.filter(m => m.status === 'KILLED' || m.status === 'TIMED_OUT').length;
    const survived = mutations.filter(m => m.status === 'SURVIVED').length;
    const noCoverage = mutations.filter(m => m.status === 'NO_COVERAGE').length;
    const overallScore = totalMutants > 0 ? Math.round((killed / totalMutants) * 100) : 0;

    // Group survived mutants by class
    const survivedByClass = new Map<string, PitestMutation[]>();
    for (const m of mutations.filter(m => m.status === 'SURVIVED')) {
      const key = m.mutatedClass;
      if (!survivedByClass.has(key)) survivedByClass.set(key, []);
      survivedByClass.get(key)!.push(m);
    }

    // Create findings for survived mutants (up to 20 total)
    let findingCount = 0;
    for (const [className, classMutants] of survivedByClass) {
      if (findingCount >= 20) break;

      for (const mutant of classMutants.slice(0, 3)) {
        if (findingCount >= 20) break;
        findingCount++;

        const filePath = mutant.sourceFile || className.replace(/\./g, '/') + '.java';

        findings.push({
          ruleId: 'MUTATION-003',
          severity: mutationScoreToSeverity(overallScore),
          title: `Survived mutant: ${mutant.mutator} in ${className}:${mutant.lineNumber}`,
          description: `A ${mutant.mutator} mutation in method ${mutant.mutatedMethod}() at line ${mutant.lineNumber} ` +
            `was not detected by any test. ${mutant.description ? `Mutation: ${mutant.description}. ` : ''}` +
            `Overall mutation score: ${overallScore}% (${killed}/${totalMutants} killed).`,
          filePath,
          lineNumber: mutant.lineNumber,
          columnNumber: null,
          codeSnippet: `Class: ${className}\nMethod: ${mutant.mutatedMethod}\nMutator: ${mutant.mutator}`,
          cweId: null,
          owaspCategory: null,
          fixAvailable: true,
          fixDescription: `Add a test for ${className}.${mutant.mutatedMethod}() that validates the logic at line ${mutant.lineNumber}.`,
          metadata: {
            mutator: mutant.mutator,
            mutatedClass: className,
            mutatedMethod: mutant.mutatedMethod,
            overallMutationScore: overallScore,
          },
        });
      }
    }

    logger.info({ overallScore, totalMutants, killed, survived, noCoverage, findingsCount: findings.length }, 'pitest scan completed');

    return {
      scanner: 'pitest',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({ mutationScore: overallScore, totalMutants, killed, survived, noCoverage }),
      evidence: {
        checksPerformed: [
          'Java mutation testing',
          'Test quality validation via mutation score',
          'Survived mutant identification per class/method',
        ],
        scanScope: `Mutation analysis of Java source, ${totalMutants} mutants generated across ${survivedByClass.size} classes`,
        filesAnalyzed: survivedByClass.size,
        rulesEvaluated: totalMutants,
        configuration: `Threads: 2, Build: ${hasMaven ? 'Maven' : 'Gradle'}, Mutation score: ${overallScore}%`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'pitest scan failed');
    return {
      scanner: 'pitest',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
