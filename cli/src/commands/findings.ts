import { apiRequest, printJson, colorSeverity } from '../api.js';

interface FindingsOptions {
  severity?: string;
  limit: string;
  url: string;
  apiKey?: string;
  json?: boolean;
}

export async function findingsCommand(scanId: string, opts: FindingsOptions): Promise<void> {
  try {
    const params = new URLSearchParams();
    params.set('limit', opts.limit);
    if (opts.severity) params.set('severity', opts.severity);

    const result = await apiRequest('GET', `/scans/${scanId}/findings?${params}`, {
      url: opts.url,
      apiKey: opts.apiKey,
    }) as Record<string, any>;

    if (opts.json) {
      printJson(result);
      return;
    }

    const findings = result.data?.data || result.data || [];
    if (findings.length === 0) {
      console.log('No findings.');
      return;
    }

    for (const f of findings) {
      const location = f.file_path
        ? `${f.file_path}${f.line_number ? ':' + f.line_number : ''}`
        : '';
      console.log(`${colorSeverity(f.severity)} ${f.title}`);
      if (location) console.log(`  ${location}`);
      if (f.fix_description) console.log(`  Fix: ${f.fix_description}`);
      console.log();
    }

    const meta = result.data?.meta;
    if (meta) {
      console.log(`Showing ${findings.length} of ${meta.total} findings`);
    }
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}
