import { apiRequest, printJson } from '../api.js';

interface StatusOptions {
  url: string;
  apiKey?: string;
  json?: boolean;
}

export async function statusCommand(scanId: string, opts: StatusOptions): Promise<void> {
  try {
    const result = await apiRequest('GET', `/scans/${scanId}`, {
      url: opts.url,
      apiKey: opts.apiKey,
    }) as Record<string, any>;

    if (opts.json) {
      printJson(result);
      return;
    }

    const scan = result.data;
    console.log(`Scan:   ${scan.id}`);
    console.log(`Status: ${scan.status}`);
    if (scan.score !== null) console.log(`Score:  ${scan.score}/1000`);
    if (scan.riskLevel) console.log(`Risk:   ${scan.riskLevel}`);
    if (scan.findingsCount) console.log(`Findings: ${scan.findingsCount}`);
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}
