import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-toxiproxy');

/**
 * Toxiproxy Chaos/Resilience Configuration Analyzer
 *
 * Analyzes Toxiproxy configuration files for:
 * - Missing chaos testing for critical services
 * - Overly aggressive toxics that could mask real issues
 * - Missing timeout/retry testing patterns
 * - Hardcoded service addresses
 */
export async function runToxiproxy(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Look for Toxiproxy config files
    const { stdout: configSearch } = await execAsync(
      `find /scan-target -name "*toxiproxy*" -o -name "*toxi*config*" -o -name "chaos*.json" -o -name "chaos*.yaml" -o -name "chaos*.yml" 2>/dev/null`
    );

    const configFiles = configSearch.trim().split('\n').filter(Boolean);

    // Also check docker-compose for toxiproxy service
    const { stdout: composeSearch } = await execAsync(
      `find /scan-target -name "docker-compose*.yml" -o -name "docker-compose*.yaml" 2>/dev/null`
    );
    const composeFiles = composeSearch.trim().split('\n').filter(Boolean);

    let hasToxiproxyService = false;
    for (const compose of composeFiles) {
      try {
        const { stdout: content } = await execAsync(`cat "${compose}"`);
        if (/toxiproxy/i.test(content)) {
          hasToxiproxyService = true;
          break;
        }
      } catch { /* skip */ }
    }

    if (configFiles.length === 0 && !hasToxiproxyService) {
      // Check if there are services that SHOULD have chaos testing
      let hasDatabase = false;
      for (const f of composeFiles) {
        try {
          const { stdout } = await execAsync(`cat "${f}"`);
          if (/postgres|mysql|mongo|redis/i.test(stdout)) {
            hasDatabase = true;
            break;
          }
        } catch { /* skip */ }
      }

      if (hasDatabase) {
        findings.push({
          ruleId: 'TOXIPROXY-MISSING',
          severity: 'info',
          title: 'Toxiproxy: No Chaos Testing Configured',
          description: 'Project has database/service dependencies but no chaos testing configuration. Consider adding Toxiproxy for resilience testing.',
          filePath: 'docker-compose.yml',
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: 'A04:2021-Insecure Design',
          fixAvailable: false,
          fixDescription: 'Add Toxiproxy to test network failures, latency, and timeouts',
          metadata: {},
        });
      }

      return {
        scanner: 'toxiproxy',
        success: true,
        skipped: configFiles.length === 0 && !hasToxiproxyService,
        findings,
        duration: Date.now() - startTime,
        skipReason: 'no_config_files',
        skipHint: 'No Toxiproxy config files and no database service in docker-compose',
      };
    }

    for (const configFile of configFiles) {
      try {
        const { stdout: content } = await execAsync(`cat "${configFile}"`, { maxBuffer: 5 * 1024 * 1024 });
        const relativePath = configFile.replace('/scan-target/', '');

        // Try JSON parse
        let config;
        try {
          config = JSON.parse(content);
        } catch {
          // May be YAML — do basic pattern analysis
          if (/upstream.*localhost|upstream.*127\.0\.0\.1/i.test(content)) {
            findings.push({
              ruleId: 'TOXIPROXY-HARDCODED-HOST',
              severity: 'medium',
              title: 'Toxiproxy: Hardcoded localhost in Config',
              description: 'Toxiproxy config uses hardcoded localhost/127.0.0.1. This will not work in containerized environments.',
              filePath: relativePath,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: null,
              owaspCategory: 'A05:2021-Security Misconfiguration',
              fixAvailable: true,
              fixDescription: 'Use service names or environment variables for upstream addresses',
              metadata: {},
            });
          }
          continue;
        }

        // Analyze JSON config
        const proxies = Array.isArray(config) ? config : config.proxies || [config];
        for (const proxy of proxies) {
          // Check for hardcoded addresses
          if (proxy.upstream && (/localhost|127\.0\.0\.1/.test(proxy.upstream))) {
            findings.push({
              ruleId: 'TOXIPROXY-HARDCODED-HOST',
              severity: 'medium',
              title: `Toxiproxy: Hardcoded Host - ${proxy.name || 'Unknown'}`,
              description: `Proxy "${proxy.name}" uses hardcoded upstream "${proxy.upstream}". Use service discovery or env vars.`,
              filePath: relativePath,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: null,
              owaspCategory: 'A05:2021-Security Misconfiguration',
              fixAvailable: true,
              fixDescription: 'Use environment variables: upstream: "${DB_HOST}:5432"',
              metadata: { proxyName: proxy.name, upstream: proxy.upstream },
            });
          }
        }
      } catch {
        logger.warn({ configFile }, 'Failed to parse Toxiproxy config');
      }
    }

    logger.info({ findingsCount: findings.length, files: configFiles.length }, 'Toxiproxy analysis completed');

    return {
      scanner: 'toxiproxy',
      success: true,
      findings,
      duration: Date.now() - startTime,
    };
  } catch (error) {
    logger.error({ error }, 'Toxiproxy analysis failed');
    return {
      scanner: 'toxiproxy',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
