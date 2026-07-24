import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile, readdir } from 'fs/promises';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-aflpp');

const SCAN_TARGET = '/scan-target';
const AFL_OUTPUT = '/tmp/afl-out';
const AFL_SEEDS = '/tmp/afl-seeds';
const FUZZ_TIMEOUT = 120; // seconds — short run for CI-style scanning

interface AFLStats {
  startTime: number;
  lastUpdate: number;
  cyclesDone: number;
  totalPaths: number;
  uniqueCrashes: number;
  uniqueHangs: number;
  execsPerSec: number;
  stabilityPct: number;
}

function parseAFLStats(content: string): Partial<AFLStats> {
  const stats: Partial<AFLStats> = {};
  const getValue = (key: string): string | undefined => {
    const match = content.match(new RegExp(`${key}\\s*:\\s*(\\S+)`));
    return match?.[1];
  };

  stats.cyclesDone = parseInt(getValue('cycles_done') || '0');
  stats.totalPaths = parseInt(getValue('corpus_count') || getValue('paths_total') || '0');
  stats.uniqueCrashes = parseInt(getValue('saved_crashes') || getValue('unique_crashes') || '0');
  stats.uniqueHangs = parseInt(getValue('saved_hangs') || getValue('unique_hangs') || '0');
  stats.execsPerSec = parseFloat(getValue('execs_per_sec') || '0');
  const stability = getValue('stability');
  stats.stabilityPct = stability ? parseFloat(stability.replace('%', '')) : 0;

  return stats;
}

function findFuzzTarget(): { type: 'makefile' | 'cmake' | 'binary'; path: string } | null {
  // Check for Makefile-based C/C++ projects
  if (existsSync(`${SCAN_TARGET}/Makefile`)) {
    return { type: 'makefile', path: `${SCAN_TARGET}/Makefile` };
  }
  if (existsSync(`${SCAN_TARGET}/CMakeLists.txt`)) {
    return { type: 'cmake', path: `${SCAN_TARGET}/CMakeLists.txt` };
  }
  return null;
}

function hasCSource(dir: string): boolean {
  try {
    const { execFileSync } = require('child_process');
    // execFile with an argument array — no shell interpolation of `dir`.
    const result = execFileSync(
      'find',
      [
        dir, '-maxdepth', '3',
        '(', '-name', '*.c', '-o', '-name', '*.cpp', '-o', '-name', '*.cc', ')',
        '-not', '-path', '*/build/*',
        '-not', '-path', '*/.git/*',
      ],
      { encoding: 'utf-8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    return result.split('\n').some((line: string) => line.trim().length > 0);
  } catch {
    return false;
  }
}

export async function runAFLpp(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check prerequisites
    const target = findFuzzTarget();
    if (!target || !hasCSource(SCAN_TARGET)) {
      return {
        scanner: 'aflpp',
        success: true,
        skipped: true,
        skipReason: 'no_c_project',
        skipHint: 'No C/C++ project detected — AFL++ requires a Makefile or CMakeLists.txt with .c/.cpp source files',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'Not a C/C++ project (no Makefile/CMakeLists.txt with C/C++ source)',
      };
    }

    // Check if afl-fuzz is available
    try {
      await execAsync('which afl-fuzz', { timeout: 5000 });
    } catch {
      return {
        scanner: 'aflpp',
        success: true,
        skipped: true,
        skipReason: 'tool_not_installed',
        skipHint: 'AFL++ binary not available in the scanner image (Alpine package missing)',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'AFL++ not installed in scanner image',
      };
    }

    // Create seed corpus
    await execAsync(`mkdir -p ${AFL_SEEDS} ${AFL_OUTPUT}`, { timeout: 5000 });
    await execAsync(`echo "AAAA" > ${AFL_SEEDS}/seed1`, { timeout: 5000 });
    await execAsync(`echo "" > ${AFL_SEEDS}/seed2`, { timeout: 5000 });
    // Add a seed with some structure
    await execAsync(`printf '\\x00\\x01\\x02\\x03\\xff\\xfe\\xfd' > ${AFL_SEEDS}/seed3`, { timeout: 5000 });

    // Try to build with AFL instrumentation
    let binaryPath: string | null = null;

    if (target.type === 'cmake') {
      try {
        await execAsync(
          `cd ${SCAN_TARGET} && mkdir -p build-afl && cd build-afl && ` +
          `CC=afl-cc CXX=afl-c++ cmake .. -DCMAKE_BUILD_TYPE=Debug 2>/dev/null && ` +
          `make -j2 2>/dev/null`,
          { timeout: 60000, maxBuffer: 50 * 1024 * 1024 }
        );
        // Find the built binary
        const { stdout } = await execAsync(
          `find ${SCAN_TARGET}/build-afl -type f -executable -not -name "*.so" -not -name "*.a" 2>/dev/null | head -1`,
          { timeout: 5000 }
        );
        binaryPath = stdout.trim() || null;
      } catch {
        logger.warn('AFL++ instrumented build failed for cmake project');
      }
    } else if (target.type === 'makefile') {
      try {
        await execAsync(
          `cd ${SCAN_TARGET} && make clean 2>/dev/null; CC=afl-cc CXX=afl-c++ make -j2 2>/dev/null`,
          { timeout: 60000, maxBuffer: 50 * 1024 * 1024 }
        );
        // Find the built binary
        const { stdout } = await execAsync(
          `find ${SCAN_TARGET} -maxdepth 2 -type f -executable -not -name "*.so" -not -name "*.o" -not -name "Makefile" -not -path "*/.git/*" 2>/dev/null | head -1`,
          { timeout: 5000 }
        );
        binaryPath = stdout.trim() || null;
      } catch {
        logger.warn('AFL++ instrumented build failed for makefile project');
      }
    }

    if (!binaryPath) {
      // Fall back to QEMU mode (no instrumentation needed) if we can find any binary
      try {
        const { stdout } = await execAsync(
          `cd ${SCAN_TARGET} && make -j2 2>/dev/null; find . -maxdepth 2 -type f -executable -not -name "*.so" -not -name "*.o" -not -name "Makefile" -not -path "*/.git/*" 2>/dev/null | head -1`,
          { timeout: 60000, maxBuffer: 50 * 1024 * 1024 }
        );
        const fallbackBinary = stdout.trim();
        if (fallbackBinary) {
          binaryPath = `${SCAN_TARGET}/${fallbackBinary.replace('./', '')}`;
        }
      } catch {
        // Can't build at all
      }
    }

    if (!binaryPath) {
      findings.push({
        ruleId: 'FUZZ-001',
        severity: 'medium',
        title: 'C/C++ project could not be built for fuzz testing',
        description: 'The project has C/C++ source files but could not be compiled for fuzz testing. ' +
          'AI-generated C/C++ code without fuzz testing has high risk of memory safety bugs ' +
          '(buffer overflows, use-after-free, integer overflows).',
        filePath: target.path.replace(`${SCAN_TARGET}/`, ''),
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: 'CWE-120',
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: 'Ensure the project builds with standard make/cmake. Add a fuzz harness using AFL++ or libFuzzer.',
        metadata: { buildSystem: target.type, reason: 'build-failed' },
      });

      return {
        scanner: 'aflpp',
        success: true,
        findings,
        duration: Date.now() - startTime,
        rawOutput: 'Build failed — cannot fuzz without a binary',
      };
    }

    // Run AFL++ with timeout
    const useQemu = !binaryPath.includes('build-afl');
    const qemuFlag = useQemu ? '-Q' : '';
    const cmd = `timeout ${FUZZ_TIMEOUT} afl-fuzz ${qemuFlag} ` +
      `-i ${AFL_SEEDS} -o ${AFL_OUTPUT} ` +
      `-m 512 -t 1000 ` +
      `-- ${binaryPath} 2>/dev/null; true`;

    await execAsync(cmd, {
      maxBuffer: 50 * 1024 * 1024,
      timeout: (FUZZ_TIMEOUT + 30) * 1000,
      env: { ...process.env, AFL_SKIP_CPUFREQ: '1', AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: '1' },
    });

    // Parse results
    let stats: Partial<AFLStats> = {};
    const statsPath = `${AFL_OUTPUT}/default/fuzzer_stats`;
    if (existsSync(statsPath)) {
      const statsContent = await readFile(statsPath, 'utf-8');
      stats = parseAFLStats(statsContent);
    }

    // Check for crashes
    const crashDir = `${AFL_OUTPUT}/default/crashes`;
    let crashFiles: string[] = [];
    if (existsSync(crashDir)) {
      crashFiles = (await readdir(crashDir)).filter(f => f !== 'README.txt' && !f.startsWith('.'));
    }

    // Check for hangs
    const hangDir = `${AFL_OUTPUT}/default/hangs`;
    let hangFiles: string[] = [];
    if (existsSync(hangDir)) {
      hangFiles = (await readdir(hangDir)).filter(f => !f.startsWith('.'));
    }

    // Report crashes
    for (const crash of crashFiles.slice(0, 10)) {
      let crashInput: string | null = null;
      try {
        const buf = await readFile(`${crashDir}/${crash}`);
        crashInput = buf.toString('hex').slice(0, 200);
      } catch { /* can't read crash file */ }

      findings.push({
        ruleId: 'FUZZ-001',
        severity: 'critical',
        title: `Crash found by fuzzer: ${crash}`,
        description: `AFL++ found a crash-inducing input after ${stats.cyclesDone || 0} cycles ` +
          `(${stats.execsPerSec || 0} execs/sec). ` +
          'Crashes in C/C++ code typically indicate memory safety vulnerabilities ' +
          '(buffer overflow, use-after-free, null pointer dereference). ' +
          'AI-generated C/C++ code is particularly prone to these issues.',
        filePath: target.path.replace(`${SCAN_TARGET}/`, ''),
        lineNumber: null,
        columnNumber: null,
        codeSnippet: crashInput ? `Crash input (hex): ${crashInput}` : null,
        cweId: 'CWE-120',
        owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
        fixAvailable: true,
        fixDescription: 'Reproduce the crash with the provided input and fix the memory safety issue. ' +
          'Consider using AddressSanitizer (ASAN) to get detailed crash information.',
        metadata: {
          crashFile: crash,
          cyclesDone: stats.cyclesDone,
          execsPerSec: stats.execsPerSec,
          mode: useQemu ? 'QEMU' : 'instrumented',
        },
      });
    }

    // Report hangs
    if (hangFiles.length > 0) {
      findings.push({
        ruleId: 'FUZZ-001',
        severity: 'high',
        title: `${hangFiles.length} hang(s) found by fuzzer`,
        description: `AFL++ found ${hangFiles.length} input(s) that cause the program to hang. ` +
          'Hangs can indicate infinite loops, deadlocks, or algorithmic complexity attacks (ReDoS-style). ' +
          `Fuzzing ran for ${FUZZ_TIMEOUT}s with ${stats.totalPaths || 0} unique paths discovered.`,
        filePath: target.path.replace(`${SCAN_TARGET}/`, ''),
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: 'CWE-835',
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: 'Reproduce the hang with the provided input files and fix the infinite loop or excessive computation.',
        metadata: { hangCount: hangFiles.length, totalPaths: stats.totalPaths },
      });
    }

    // If no crashes/hangs, report summary
    if (crashFiles.length === 0 && hangFiles.length === 0 && (stats.cyclesDone || 0) > 0) {
      logger.info('AFL++ completed with no crashes or hangs');
    }

    logger.info({
      crashes: crashFiles.length,
      hangs: hangFiles.length,
      cyclesDone: stats.cyclesDone,
      totalPaths: stats.totalPaths,
      execsPerSec: stats.execsPerSec,
      findingsCount: findings.length,
    }, 'AFL++ scan completed');

    return {
      scanner: 'aflpp',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({
        crashes: crashFiles.length,
        hangs: hangFiles.length,
        cyclesDone: stats.cyclesDone,
        totalPaths: stats.totalPaths,
        execsPerSec: stats.execsPerSec,
        stabilityPct: stats.stabilityPct,
        mode: useQemu ? 'QEMU' : 'instrumented',
      }),
      evidence: {
        checksPerformed: [
          'Coverage-guided fuzz testing (AFL++)',
          'Crash detection (memory safety violations)',
          'Hang detection (infinite loops, deadlocks)',
          'Input corpus generation',
        ],
        scanScope: `Fuzz testing of ${binaryPath.replace(`${SCAN_TARGET}/`, '')}, ${stats.totalPaths || 0} unique paths, ${FUZZ_TIMEOUT}s runtime`,
        filesAnalyzed: 1,
        rulesEvaluated: stats.totalPaths || 0,
        configuration: `Mode: ${useQemu ? 'QEMU' : 'instrumented'}, Timeout: ${FUZZ_TIMEOUT}s, Memory limit: 512MB`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'AFL++ scan failed');
    return {
      scanner: 'aflpp',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
