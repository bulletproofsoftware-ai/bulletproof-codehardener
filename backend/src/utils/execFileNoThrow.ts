import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export interface ExecResult {
  stdout: string;
  stderr: string;
  status: 'success' | 'error';
  code?: number;
  error?: string;
}

/**
 * Safe command execution utility that uses execFile instead of exec
 * to prevent shell injection vulnerabilities.
 *
 * @param command - The command to execute (no shell interpolation)
 * @param args - Array of arguments (safely escaped)
 * @param options - Optional execution options
 * @returns Promise with structured output
 */
export async function execFileNoThrow(
  command: string,
  args: string[] = [],
  options: {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    timeout?: number;
    maxBuffer?: number;
  } = {}
): Promise<ExecResult> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      timeout: options.timeout || 300000, // 5 minute default
      maxBuffer: options.maxBuffer || 10 * 1024 * 1024, // 10MB default
      shell: process.platform === 'win32', // Only use shell on Windows for compatibility
    });

    return {
      stdout,
      stderr,
      status: 'success',
      code: 0,
    };
  } catch (error: unknown) {
    const execError = error as {
      stdout?: string;
      stderr?: string;
      code?: number;
      message?: string;
    };

    return {
      stdout: execError.stdout || '',
      stderr: execError.stderr || '',
      status: 'error',
      code: execError.code,
      error: execError.message,
    };
  }
}

/**
 * Run npm/npx commands safely
 */
export async function runNpmCommand(
  npmCommand: 'npm' | 'npx',
  args: string[],
  cwd?: string
): Promise<ExecResult> {
  // On Windows, npm/npx needs .cmd extension
  const command = process.platform === 'win32' ? `${npmCommand}.cmd` : npmCommand;

  return execFileNoThrow(command, args, { cwd });
}
