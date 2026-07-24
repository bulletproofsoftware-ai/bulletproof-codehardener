import { env } from './config/env.js';
import { logger } from './utils/logger.js';
import { checkDbConnection, closeDbConnection } from './db/client.js';
import { createScanWorker } from './services/queue/scan.queue.js';

// Graceful shutdown handler
async function shutdown(signal: string) {
  logger.info({ signal }, 'Received shutdown signal');

  try {
    await closeDbConnection();
    logger.info('Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    logger.error({ error }, 'Error during graceful shutdown');
    process.exit(1);
  }
}

// Handle shutdown signals
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  logger.fatal({ error }, 'Uncaught exception');
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error({ reason }, 'Unhandled rejection');
});

// Start worker
async function start() {
  try {
    logger.info({ env: env.NODE_ENV }, 'Starting scan worker');

    // Check database connection
    const dbConnected = await checkDbConnection();
    if (!dbConnected) {
      logger.fatal('Database connection required for worker');
      process.exit(1);
    }
    logger.info('Database connected successfully');

    // Verify scanner tools are available
    const scannerChecks = await verifyScanners();
    logger.info({ scanners: scannerChecks }, 'Scanner availability check');

    // Create and start worker (worker runs in background, no need to reference it)
    createScanWorker();
    logger.info('Scan worker started and listening for jobs');

    // Keep process alive
    await new Promise(() => {});
  } catch (error) {
    logger.fatal({ error }, 'Failed to start worker');
    process.exit(1);
  }
}

// Verify installed scanners
async function verifyScanners(): Promise<Record<string, boolean>> {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execAsync = promisify(exec);

  const scanners = [
    { name: 'trivy', cmd: 'trivy --version' },
    { name: 'gitleaks', cmd: 'gitleaks version' },
    { name: 'semgrep', cmd: 'semgrep --version' },
    { name: 'checkov', cmd: 'checkov --version' },
    { name: 'nuclei', cmd: 'nuclei -version' },
    { name: 'bandit', cmd: 'bandit --version' },
    { name: 'gosec', cmd: 'gosec --version' },
    { name: 'grype', cmd: 'grype version' },
    { name: 'syft', cmd: 'syft version' },
    // detect-secrets removed: redundant with Gitleaks
  ];

  const results: Record<string, boolean> = {};

  for (const scanner of scanners) {
    try {
      await execAsync(scanner.cmd, { timeout: 10000 });
      results[scanner.name] = true;
    } catch {
      results[scanner.name] = false;
      logger.warn({ scanner: scanner.name }, 'Scanner not available');
    }
  }

  return results;
}

start();
