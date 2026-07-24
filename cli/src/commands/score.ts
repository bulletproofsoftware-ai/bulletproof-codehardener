import { apiRequest, printJson, scoreBar } from '../api.js';

interface ScoreOptions {
  url: string;
  apiKey?: string;
  json?: boolean;
}

export async function scoreCommand(projectId: string | undefined, opts: ScoreOptions): Promise<void> {
  try {
    // If no projectId, get the first project
    let targetProjectId = projectId;

    if (!targetProjectId) {
      const projects = await apiRequest('GET', '/projects', {
        url: opts.url,
        apiKey: opts.apiKey,
      }) as Record<string, any>;

      const projectList = projects.data?.data || projects.data || [];
      if (projectList.length === 0) {
        console.error('No projects found. Run a scan first.');
        process.exit(1);
      }
      targetProjectId = projectList[0].id;
    }

    const result = await apiRequest('GET', `/projects/${targetProjectId}/stats`, {
      url: opts.url,
      apiKey: opts.apiKey,
    }) as Record<string, any>;

    if (opts.json) {
      printJson(result);
      return;
    }

    const stats = result.data;
    console.log(`Project: ${stats.name || targetProjectId}`);
    console.log(`Score:   ${scoreBar(stats.score || 0)}`);
    console.log(`Risk:    ${stats.riskLevel || 'unknown'}`);
    if (stats.findings) {
      console.log(`Open:    ${stats.findings.critical || 0} critical, ${stats.findings.high || 0} high, ${stats.findings.medium || 0} medium, ${stats.findings.low || 0} low`);
    }
    if (stats.lastScanAt) {
      console.log(`Last scan: ${new Date(stats.lastScanAt).toLocaleString()}`);
    }
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}
