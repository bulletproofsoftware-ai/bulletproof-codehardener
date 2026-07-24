import { apiRequest, printJson, scoreBar } from '../api.js';

interface ScanOptions {
  profile: string;
  scanners?: string[];
  url: string;
  apiKey?: string;
  wait: boolean;
  json?: boolean;
}

export async function scanCommand(opts: ScanOptions): Promise<void> {
  const cwd = process.cwd();
  const projectName = cwd.split('/').pop() || 'Project';

  console.log(`Scanning ${projectName} with ${opts.profile} profile...`);

  try {
    const result = await apiRequest('POST', '/scans', {
      url: opts.url,
      apiKey: opts.apiKey,
    }, {
      projectName,
      repositoryUrl: `file://${cwd}`,
      profile: opts.profile,
      scanners: opts.scanners,
    }) as Record<string, any>;

    const scanId = result.data?.id || result.data?.scanId;

    if (!opts.wait) {
      if (opts.json) {
        printJson(result);
      } else {
        console.log(`Scan queued: ${scanId}`);
        console.log(`Check status: codehardener status ${scanId}`);
      }
      return;
    }

    // Poll for completion
    console.log(`Scan ${scanId} started. Waiting for results...`);
    const maxWait = 300000;
    const pollInterval = 3000;
    const start = Date.now();

    while (Date.now() - start < maxWait) {
      await new Promise(r => setTimeout(r, pollInterval));

      const status = await apiRequest('GET', `/scans/${scanId}`, {
        url: opts.url,
        apiKey: opts.apiKey,
      }) as Record<string, any>;

      const scan = status.data;
      if (!scan) continue;

      if (scan.status === 'completed') {
        if (opts.json) {
          printJson(scan);
        } else {
          console.log('\n' + '='.repeat(50));
          console.log(`Score: ${scoreBar(scan.score || 0)}`);
          console.log(`Risk:  ${scan.riskLevel || 'unknown'}`);
          console.log(`Findings: ${scan.findingsCount || 0}`);
          console.log(`Duration: ${scan.duration || 0}ms`);
          console.log('='.repeat(50));

          if (scan.findingsCount > 0) {
            console.log(`\nView findings: codehardener findings ${scanId}`);
          }
        }
        return;
      }

      if (scan.status === 'failed') {
        console.error('Scan failed.');
        process.exit(1);
      }

      process.stdout.write('.');
    }

    console.log('\nScan timeout. Check status: codehardener status ' + scanId);
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}
