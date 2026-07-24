/**
 * Container Isolation Layer for Scan Execution
 *
 * Spawns ephemeral Docker containers per scan with:
 *   - Read-only root filesystem
 *   - No network for SAST (network allowed for DAST)
 *   - Resource limits (CPU, memory, PIDs)
 *   - Dropped capabilities
 *   - Optional gVisor runtime (runsc) for additional isolation
 *   - Auto-cleanup on completion or timeout
 */

import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import crypto from 'crypto';
import { createLogger } from '../../utils/logger.js';

const execAsync = promisify(exec);
const logger = createLogger('container-isolation');

export type ScanCategory = 'sast' | 'dast' | 'sca' | 'secrets' | 'iac' | 'load' | 'api' | 'browser' | 'supply-chain' | 'policy';

export interface ContainerConfig {
  /** Scanner name (e.g., 'trivy', 'bandit') */
  scanner: string;
  /** Docker image with the scanner installed */
  image: string;
  /** Category determines network/isolation profile */
  category: ScanCategory;
  /** Command to run inside the container */
  command: string[];
  /** Path to the code being scanned (mounted read-only) */
  sourcePath: string;
  /** Optional output directory (mounted read-write) */
  outputPath?: string;
  /** Timeout in milliseconds */
  timeoutMs?: number;
  /** Environment variables */
  env?: Record<string, string>;
  /** Additional volume mounts */
  extraMounts?: Array<{ host: string; container: string; readOnly?: boolean }>;
}

export interface ContainerResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  containerId: string;
  durationMs: number;
  killed: boolean;
}

/** Scanner image registry — maps scanner name to Docker image */
const SCANNER_IMAGES: Record<string, string> = {
  // SAST
  opengrep: 'returntocorp/semgrep:latest',
  bandit: 'codehardener/scanner-bandit:latest',
  gosec: 'securego/gosec:latest',
  'eslint-security': 'codehardener/scanner-eslint:latest',
  pmd: 'codehardener/scanner-pmd:latest',

  // DAST
  nuclei: 'projectdiscovery/nuclei:latest',
  zap: 'zaproxy/zap-stable:latest',

  // SCA
  trivy: 'aquasec/trivy:latest',
  grype: 'anchore/grype:latest',

  // Secrets
  gitleaks: 'zricethezav/gitleaks:latest',

  // IaC
  checkov: 'bridgecrew/checkov:latest',

  // Supply Chain
  syft: 'anchore/syft:latest',
  cosign: 'gcr.io/projectsigstore/cosign:latest',
};

/** Category-based isolation profiles */
const ISOLATION_PROFILES: Record<ScanCategory, {
  network: boolean;
  memoryLimit: string;
  cpuLimit: string;
  pidLimit: number;
  readOnlyRoot: boolean;
  noNewPrivileges: boolean;
}> = {
  sast: {
    network: false,       // SAST never needs network
    memoryLimit: '2g',
    cpuLimit: '1.0',
    pidLimit: 256,
    readOnlyRoot: true,
    noNewPrivileges: true,
  },
  secrets: {
    network: false,
    memoryLimit: '1g',
    cpuLimit: '0.5',
    pidLimit: 128,
    readOnlyRoot: true,
    noNewPrivileges: true,
  },
  sca: {
    network: true,        // SCA may need to fetch vulnerability DBs
    memoryLimit: '2g',
    cpuLimit: '1.0',
    pidLimit: 256,
    readOnlyRoot: true,
    noNewPrivileges: true,
  },
  iac: {
    network: false,
    memoryLimit: '1g',
    cpuLimit: '0.5',
    pidLimit: 128,
    readOnlyRoot: true,
    noNewPrivileges: true,
  },
  dast: {
    network: true,        // DAST requires network access to target
    memoryLimit: '4g',
    cpuLimit: '2.0',
    pidLimit: 512,
    readOnlyRoot: false,  // ZAP needs writable dirs
    noNewPrivileges: true,
  },
  load: {
    network: true,
    memoryLimit: '2g',
    cpuLimit: '1.0',
    pidLimit: 512,
    readOnlyRoot: true,
    noNewPrivileges: true,
  },
  api: {
    network: true,
    memoryLimit: '2g',
    cpuLimit: '1.0',
    pidLimit: 256,
    readOnlyRoot: true,
    noNewPrivileges: true,
  },
  browser: {
    network: true,
    memoryLimit: '4g',
    cpuLimit: '2.0',
    pidLimit: 1024,
    readOnlyRoot: false,  // Browser needs writable dirs
    noNewPrivileges: false, // Chrome sandbox needs capabilities
  },
  'supply-chain': {
    network: true,
    memoryLimit: '1g',
    cpuLimit: '0.5',
    pidLimit: 128,
    readOnlyRoot: true,
    noNewPrivileges: true,
  },
  policy: {
    network: false,
    memoryLimit: '512m',
    cpuLimit: '0.5',
    pidLimit: 64,
    readOnlyRoot: true,
    noNewPrivileges: true,
  },
};

/**
 * Check if Docker is available and gVisor runtime is installed
 */
export async function checkContainerRuntime(): Promise<{
  dockerAvailable: boolean;
  gvisorAvailable: boolean;
}> {
  let dockerAvailable = false;
  let gvisorAvailable = false;

  try {
    await execAsync('docker info --format "{{.ServerVersion}}"');
    dockerAvailable = true;
  } catch {
    logger.warn('Docker not available — container isolation disabled');
  }

  if (dockerAvailable) {
    try {
      const { stdout } = await execAsync('docker info --format "{{.Runtimes}}"');
      gvisorAvailable = stdout.includes('runsc');
    } catch {
      // gVisor not required
    }
  }

  return { dockerAvailable, gvisorAvailable };
}

/**
 * Get the Docker image for a scanner
 */
export function getScannerImage(scanner: string): string | undefined {
  return SCANNER_IMAGES[scanner];
}

/**
 * Run a scanner in an isolated container
 */
export async function runInContainer(config: ContainerConfig): Promise<ContainerResult> {
  const containerId = `ch-scan-${config.scanner}-${crypto.randomBytes(4).toString('hex')}`;
  const profile = ISOLATION_PROFILES[config.category];
  const timeoutMs = config.timeoutMs || 300_000;
  const startTime = Date.now();

  // Build docker run arguments
  const args: string[] = [
    'run',
    '--rm',
    '--name', containerId,

    // Resource limits
    '--memory', profile.memoryLimit,
    '--cpus', profile.cpuLimit,
    '--pids-limit', profile.pidLimit.toString(),

    // Security
    '--security-opt', 'no-new-privileges:true',
    '--cap-drop', 'ALL',
  ];

  // Read-only root filesystem
  if (profile.readOnlyRoot) {
    args.push('--read-only');
    // Scanners need /tmp for temp files
    args.push('--tmpfs', '/tmp:rw,noexec,nosuid,size=512m');
  }

  // Network isolation
  if (!profile.network) {
    args.push('--network', 'none');
  }

  // gVisor runtime for SAST (strongest isolation)
  const useGvisor = config.category === 'sast' && process.env.GVISOR_ENABLED === 'true';
  if (useGvisor) {
    args.push('--runtime', 'runsc');
  }

  // Mount source code read-only
  args.push('-v', `${config.sourcePath}:/scan/source:ro`);

  // Mount output directory if specified
  if (config.outputPath) {
    args.push('-v', `${config.outputPath}:/scan/output:rw`);
  }

  // Extra mounts
  if (config.extraMounts) {
    for (const mount of config.extraMounts) {
      args.push('-v', `${mount.host}:${mount.container}:${mount.readOnly ? 'ro' : 'rw'}`);
    }
  }

  // Environment variables
  if (config.env) {
    for (const [key, value] of Object.entries(config.env)) {
      args.push('-e', `${key}=${value}`);
    }
  }

  // Image and command
  args.push(config.image, ...config.command);

  logger.info({
    containerId,
    scanner: config.scanner,
    category: config.category,
    image: config.image,
    network: profile.network,
    gvisor: useGvisor,
  }, 'Starting isolated scanner container');

  return new Promise<ContainerResult>((resolve) => {
    let stdout = '';
    let stderr = '';
    let killed = false;

    const proc = spawn('docker', args, {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    proc.stdout.on('data', (data: Buffer) => {
      stdout += data.toString();
      // Cap output at 10MB to prevent memory issues
      if (stdout.length > 10_000_000) {
        stdout = stdout.slice(0, 10_000_000) + '\n...output truncated...';
        proc.kill('SIGTERM');
        killed = true;
      }
    });

    proc.stderr.on('data', (data: Buffer) => {
      stderr += data.toString();
      if (stderr.length > 5_000_000) {
        stderr = stderr.slice(0, 5_000_000) + '\n...stderr truncated...';
      }
    });

    // Timeout handler
    const timer = setTimeout(() => {
      killed = true;
      logger.warn({ containerId, timeoutMs }, 'Scanner container timed out, killing');
      // Kill the container directly (more reliable than process.kill)
      exec(`docker kill ${containerId}`, () => {});
      proc.kill('SIGTERM');
    }, timeoutMs);

    proc.on('close', (exitCode) => {
      clearTimeout(timer);
      const durationMs = Date.now() - startTime;

      logger.info({
        containerId,
        scanner: config.scanner,
        exitCode,
        durationMs,
        killed,
        stdoutLen: stdout.length,
        stderrLen: stderr.length,
      }, 'Scanner container completed');

      resolve({
        exitCode: exitCode ?? 1,
        stdout,
        stderr,
        containerId,
        durationMs,
        killed,
      });
    });

    proc.on('error', (error) => {
      clearTimeout(timer);
      const durationMs = Date.now() - startTime;
      logger.error({ error, containerId }, 'Failed to start scanner container');

      resolve({
        exitCode: -1,
        stdout: '',
        stderr: `Failed to start container: ${error.message}`,
        containerId,
        durationMs,
        killed: false,
      });
    });
  });
}

/**
 * Clean up any dangling scan containers (called periodically)
 */
export async function cleanupScanContainers(): Promise<number> {
  try {
    const { stdout } = await execAsync(
      'docker ps -q --filter "name=ch-scan-" --filter "status=running"'
    );

    const containers = stdout.trim().split('\n').filter(Boolean);
    if (containers.length === 0) return 0;

    // Kill containers running longer than 10 minutes
    for (const containerId of containers) {
      try {
        const { stdout: inspectOut } = await execAsync(
          `docker inspect --format '{{.State.StartedAt}}' ${containerId}`
        );
        const startedAt = new Date(inspectOut.trim());
        const runningMs = Date.now() - startedAt.getTime();

        if (runningMs > 600_000) { // 10 minutes
          await execAsync(`docker kill ${containerId}`);
          logger.warn({ containerId, runningMs }, 'Killed stale scan container');
        }
      } catch {
        // Container may have already exited
      }
    }

    return containers.length;
  } catch {
    return 0;
  }
}

/**
 * Map scanner name to its category for isolation profile selection
 */
export function getScannerCategory(scanner: string): ScanCategory {
  const categoryMap: Record<string, ScanCategory> = {
    // SAST
    opengrep: 'sast', semgrep: 'sast', bandit: 'sast',
    gosec: 'sast', 'eslint-security': 'sast', eslint: 'sast', pmd: 'sast',

    // DAST
    nuclei: 'dast', zap: 'dast',

    // SCA
    trivy: 'sca', grype: 'sca', dockle: 'sca',

    // Secrets
    gitleaks: 'secrets',

    // IaC
    checkov: 'iac',

    // Load
    locust: 'load', artillery: 'load', gatling: 'load',

    // API
    newman: 'api', pact: 'api', restler: 'api', wiremock: 'api',

    // Browser
    playwright: 'browser', backstop: 'browser', pa11y: 'browser',

    // Supply Chain
    syft: 'supply-chain', 'in-toto': 'supply-chain', cosign: 'supply-chain',

    // Policy
    opa: 'policy', conftest: 'policy', allure: 'policy',

    // Other
    falco: 'policy', toxiproxy: 'api', flyway: 'sast',
  };

  return categoryMap[scanner] || 'sast';
}
