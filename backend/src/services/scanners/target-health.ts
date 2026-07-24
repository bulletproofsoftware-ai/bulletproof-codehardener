import { createLogger } from '../../utils/logger.js';

const logger = createLogger('target-health');

const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Quick HTTP HEAD check to verify targetUrl is reachable before running DAST scanners.
 * Returns true if the target responds with 2xx or 3xx within the timeout.
 */
export async function checkTargetHealth(
  targetUrl: string,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<boolean> {
  try {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Health check timed out')), timeoutMs);
    });

    const fetchPromise = fetch(targetUrl, {
      method: 'HEAD',
      signal: AbortSignal.timeout(timeoutMs),
      redirect: 'manual', // Don't follow redirects, just check reachability
    });

    const response = await Promise.race([fetchPromise, timeoutPromise]);

    const reachable = response.status < 400;
    logger.info({ targetUrl, status: response.status, reachable }, 'Target health check');
    return reachable;
  } catch (error) {
    logger.warn({ targetUrl, error: (error as Error).message }, 'Target health check failed');
    return false;
  }
}
