/**
 * HTTP client for Code Hardener API
 */

interface ApiOptions {
  url: string;
  apiKey?: string;
}

export async function apiRequest(
  method: string,
  path: string,
  opts: ApiOptions,
  body?: Record<string, unknown>
): Promise<unknown> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (opts.apiKey) {
    headers['Authorization'] = `Bearer ${opts.apiKey}`;
  } else {
    // Dev mode — use header-based auth
    headers['X-User-Id'] = 'dev@codehardener.local';
  }

  const response = await fetch(`${opts.url}/api/v1${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`API error ${response.status}: ${text}`);
  }

  return response.json();
}

export function printJson(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '\x1b[31m',  // red
  high: '\x1b[33m',      // yellow
  medium: '\x1b[36m',    // cyan
  low: '\x1b[37m',       // white
  info: '\x1b[90m',      // gray
};
const RESET = '\x1b[0m';

export function colorSeverity(severity: string): string {
  return `${SEVERITY_COLORS[severity] || ''}${severity.toUpperCase()}${RESET}`;
}

export function scoreBar(score: number): string {
  const width = 20;
  const filled = Math.round((score / 1000) * width);
  const empty = width - filled;
  const color = score >= 750 ? '\x1b[32m' : score >= 500 ? '\x1b[33m' : '\x1b[31m';
  return `${color}${'█'.repeat(filled)}${'░'.repeat(empty)}${RESET} ${score}/1000`;
}
