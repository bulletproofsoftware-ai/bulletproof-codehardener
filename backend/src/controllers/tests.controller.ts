import type { Request, Response } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { sendSuccess, sendCreated, sendValidationError } from '../utils/apiResponse.js';
import { NotFoundError } from '../middleware/errorHandler.js';
import { createLogger } from '../utils/logger.js';
import { runNpmCommand } from '../utils/execFileNoThrow.js';
import path from 'path';
import { existsSync } from 'fs';

const logger = createLogger('tests-controller');

// In-memory store for test runs (in production, use Redis or database)
interface TestRun {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt: Date;
  completedAt?: Date;
  duration?: number;
  userId: string;
  testType: 'unit' | 'integration' | 'all';
  coverage: boolean;
  results?: {
    total: number;
    passed: number;
    failed: number;
    skipped: number;
    files: TestFile[];
  };
  output: string[];
  error?: string;
}

interface TestFile {
  name: string;
  path: string;
  tests: number;
  passed: number;
  failed: number;
  duration: number;
}

// Store test runs in memory (in production, use persistent storage)
const testRuns = new Map<string, TestRun>();

// Keep last 100 test runs
const MAX_HISTORY = 100;

function cleanupOldRuns() {
  const runs = Array.from(testRuns.entries())
    .sort((a, b) => b[1].startedAt.getTime() - a[1].startedAt.getTime());

  if (runs.length > MAX_HISTORY) {
    const toRemove = runs.slice(MAX_HISTORY);
    for (const [id] of toRemove) {
      testRuns.delete(id);
    }
  }
}

const runTestsSchema = z.object({
  testType: z.enum(['unit', 'integration', 'all']).default('unit'),
  coverage: z.boolean().default(false),
  filter: z.string().optional(),
});

export async function runTests(req: Request, res: Response) {
  const validation = runTestsSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.issues);
  }

  const { testType, coverage, filter } = validation.data;
  const runId = uuidv4();

  // Create test run record
  const testRun: TestRun = {
    id: runId,
    status: 'pending',
    startedAt: new Date(),
    userId: req.user!.id,
    testType,
    coverage,
    output: [],
  };

  testRuns.set(runId, testRun);
  cleanupOldRuns();

  // Start test execution asynchronously
  executeTests(runId, testType, coverage, filter);

  logger.info({ runId, testType, coverage, userId: req.user!.id }, 'Test run initiated');

  return sendCreated(res, {
    runId,
    status: 'pending',
    message: 'Test run initiated',
  });
}

async function executeTests(
  runId: string,
  _testType: string,
  coverage: boolean,
  filter?: string
) {
  const run = testRuns.get(runId);
  if (!run) return;

  run.status = 'running';

  // Build vitest command args
  const args = ['vitest', 'run'];

  if (coverage) {
    args.push('--coverage');
  }

  if (filter) {
    args.push('-t', filter);
  }

  // Get the backend directory — use mounted repo if available, fall back to cwd
  const mountedRepo = '/repos/codehardener/backend';
  const backendDir = existsSync(mountedRepo) ? mountedRepo : path.resolve(process.cwd());

  try {
    // Install platform-native dependencies if using mounted repo
    // (host node_modules may have incompatible native bindings)
    if (backendDir === mountedRepo) {
      run.output.push('Installing dependencies for container platform...\n');
      await runNpmCommand('npm', ['install', '--ignore-scripts=false'], backendDir);
    }

    run.output.push(`Running: npx ${args.join(' ')}\n`);
    run.output.push(`Working directory: ${backendDir}\n`);
    run.output.push('---\n');

    const result = await runNpmCommand('npx', args, backendDir);

    run.completedAt = new Date();
    run.duration = run.completedAt.getTime() - run.startedAt.getTime();

    // Capture all output (stdout, stderr, and error message which contains vitest output)
    if (result.stdout) run.output.push(result.stdout);
    if (result.stderr) run.output.push(result.stderr);
    if (result.error && !result.stdout && !result.stderr) run.output.push(result.error);

    // Parse results from all available output (vitest puts results in stderr on failure)
    const combinedOutput = (result.stdout || '') + (result.stderr || '') + (result.error || '');
    run.results = parseTestOutput(combinedOutput);

    // vitest exits with code 1 when tests fail — that's still "completed" not "failed"
    if (run.results && (run.results.passed > 0 || run.results.failed > 0)) {
      run.status = 'completed';
    } else if (result.status === 'success') {
      run.status = 'completed';
    } else {
      run.status = 'failed';
      run.error = result.error || `Tests exited with code ${result.code}`;
    }

    logger.info(
      { runId, status: run.status, duration: run.duration, results: run.results },
      'Test run completed'
    );
  } catch (error) {
    run.status = 'failed';
    run.error = error instanceof Error ? error.message : 'Unknown error';
    run.completedAt = new Date();
    run.duration = run.completedAt.getTime() - run.startedAt.getTime();

    logger.error({ runId, error }, 'Failed to run tests');
  }
}

function parseTestOutput(rawOutput: string): TestRun['results'] | undefined {
  try {
    // Strip ANSI escape codes before parsing
    // eslint-disable-next-line no-control-regex
    const output = rawOutput.replace(/\x1b\[[0-9;]*m/g, '').replace(/\[\d+m/g, '');

    // Parse the vitest output format
    // Look for patterns like "✓ src/services/auth.service.test.ts (17 tests) 2178ms"
    const filePattern = /[✓✗]\s+([\w/.-]+\.test\.ts)\s+\((\d+)\s+tests?(?:\s*\|\s*(\d+)\s+failed)?\)\s+(\d+)ms/g;
    const summaryPattern = /Tests?\s+(\d+)\s+failed\s*\|\s*(\d+)\s+passed/;
    const altSummaryPattern = /Tests?\s+(\d+)\s+passed/;

    const files: TestFile[] = [];
    let match;

    while ((match = filePattern.exec(output)) !== null) {
      const [, filePath, totalTests, failedTests, duration] = match;
      const failed = parseInt(failedTests || '0');
      const total = parseInt(totalTests);

      files.push({
        name: path.basename(filePath),
        path: filePath,
        tests: total,
        passed: total - failed,
        failed,
        duration: parseInt(duration),
      });
    }

    // Parse summary
    let total = 0;
    let passed = 0;
    let failed = 0;

    const summaryMatch = output.match(summaryPattern);
    if (summaryMatch) {
      failed = parseInt(summaryMatch[1]);
      passed = parseInt(summaryMatch[2]);
      total = passed + failed;
    } else {
      const altMatch = output.match(altSummaryPattern);
      if (altMatch) {
        passed = parseInt(altMatch[1]);
        total = passed;
      } else {
        // Calculate from files
        for (const file of files) {
          total += file.tests;
          passed += file.passed;
          failed += file.failed;
        }
      }
    }

    if (total === 0 && files.length === 0) {
      return undefined;
    }

    return {
      total,
      passed,
      failed,
      skipped: 0,
      files,
    };
  } catch (error) {
    logger.warn({ error }, 'Failed to parse test output');
    return undefined;
  }
}

export async function getTestStatus(req: Request, res: Response) {
  const { runId } = z.object({ runId: z.string().uuid() }).parse(req.params);

  const run = testRuns.get(runId);
  // Ownership is enforced here the same way getTestResults and cancelTestRun
  // already do it. This handler checked only existence, so any authenticated
  // user holding a run id could read another user's run status and output.
  // Answer 404 rather than 403 so the endpoint does not confirm that a run
  // id exists for someone else.
  if (!run || run.userId !== req.user!.id) {
    throw new NotFoundError('Test run not found');
  }

  // Only return recent output lines for status updates
  const recentOutput = run.output.slice(-50);

  return sendSuccess(res, {
    id: run.id,
    status: run.status,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    duration: run.duration,
    testType: run.testType,
    coverage: run.coverage,
    results: run.results,
    recentOutput,
    error: run.error,
  });
}

export async function getTestHistory(req: Request, res: Response) {
  const querySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  }).passthrough();
  const { page, limit } = querySchema.parse(req.query);
  const offset = (page - 1) * limit;

  // Filter runs by user
  const userRuns = Array.from(testRuns.values())
    .filter(run => run.userId === req.user!.id)
    .sort((a, b) => b.startedAt.getTime() - a.startedAt.getTime());

  const total = userRuns.length;
  const paginatedRuns = userRuns.slice(offset, offset + limit);

  const history = paginatedRuns.map(run => ({
    id: run.id,
    status: run.status,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    duration: run.duration,
    testType: run.testType,
    coverage: run.coverage,
    results: run.results ? {
      total: run.results.total,
      passed: run.results.passed,
      failed: run.results.failed,
    } : undefined,
    error: run.error,
  }));

  return sendSuccess(res, history, 200, {
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  });
}

export async function getTestDetails(req: Request, res: Response) {
  const { runId } = z.object({ runId: z.string().uuid() }).parse(req.params);

  const run = testRuns.get(runId);
  if (!run) {
    throw new NotFoundError('Test run not found');
  }

  // Check user owns this run
  if (run.userId !== req.user!.id) {
    throw new NotFoundError('Test run not found');
  }

  return sendSuccess(res, {
    id: run.id,
    status: run.status,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    duration: run.duration,
    testType: run.testType,
    coverage: run.coverage,
    results: run.results,
    output: run.output,
    error: run.error,
  });
}
