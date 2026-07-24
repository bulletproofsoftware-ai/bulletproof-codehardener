/**
 * @codehardener/sdk — Official Node.js SDK for Code Hardener
 *
 * Usage:
 *   import { CodeHardener } from '@codehardener/sdk';
 *   const ch = new CodeHardener({ apiKey: 'ch_...' });
 *   const scan = await ch.scans.create({ repositoryUrl: 'https://github.com/...' });
 *   const result = await ch.scans.waitForCompletion(scan.id);
 */

export interface CodeHardenerConfig {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
}

export interface ScanCreateParams {
  repositoryUrl?: string;
  localPath?: string;
  projectId?: string;
  profile?: 'quick' | 'standard' | 'comprehensive' | 'auto';
  branch?: string;
  commitSha?: string;
  triggerType?: string;
  scanners?: string[];
}

export interface Scan {
  id: string;
  projectId: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  profile: string;
  score: number | null;
  riskLevel: string | null;
  findingsCount: number;
  findingsSummary: { critical: number; high: number; medium: number; low: number; info: number };
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

export interface Finding {
  id: string;
  scanId: string;
  projectId: string;
  scanner: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  filePath: string | null;
  line: number | null;
  cweId: string | null;
  cveId: string | null;
  recommendation: string | null;
}

export interface Project {
  id: string;
  name: string;
  repositoryUrl: string | null;
  language: string | null;
  score: number | null;
  riskLevel: string | null;
  lastScanAt: string | null;
  createdAt: string;
}

export interface ProjectScore {
  score: number;
  riskLevel: string;
  breakdown: {
    baseScore: number;
    totalPenalty: number;
    bonusTotal: number;
  };
}

interface ApiResponse<T> {
  success: boolean;
  data: T;
  error?: string;
}

interface PaginatedResponse<T> {
  success: boolean;
  data: T[];
  meta: { total: number; page: number; limit: number; pages: number };
}

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'CodeHardenerApiError';
  }
}

export class CodeHardener {
  private baseUrl: string;
  private apiKey: string;
  private timeout: number;

  public scans: ScansApi;
  public findings: FindingsApi;
  public projects: ProjectsApi;

  constructor(config: CodeHardenerConfig) {
    this.baseUrl = (config.baseUrl || 'https://api.codehardener.com').replace(/\/$/, '');
    this.apiKey = config.apiKey;
    this.timeout = config.timeout || 30_000;

    this.scans = new ScansApi(this);
    this.findings = new FindingsApi(this);
    this.projects = new ProjectsApi(this);
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
          'User-Agent': '@codehardener/sdk-node/0.1.0',
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      const json = await response.json() as ApiResponse<T>;

      if (!response.ok) {
        throw new ApiError(response.status, json.error || `HTTP ${response.status}`);
      }

      return json.data;
    } finally {
      clearTimeout(timer);
    }
  }

  async requestPaginated<T>(path: string, params?: Record<string, string>): Promise<PaginatedResponse<T>> {
    const url = new URL(`${this.baseUrl}${path}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url.toString(), {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'User-Agent': '@codehardener/sdk-node/0.1.0',
        },
        signal: controller.signal,
      });

      return await response.json() as PaginatedResponse<T>;
    } finally {
      clearTimeout(timer);
    }
  }
}

class ScansApi {
  constructor(private client: CodeHardener) {}

  async create(params: ScanCreateParams): Promise<Scan> {
    return this.client.request<Scan>('POST', '/api/v1/scans', params);
  }

  async get(scanId: string): Promise<Scan> {
    return this.client.request<Scan>('GET', `/api/v1/scans/${scanId}`);
  }

  async list(params?: { projectId?: string; page?: number; limit?: number }): Promise<PaginatedResponse<Scan>> {
    const query: Record<string, string> = {};
    if (params?.projectId) query.projectId = params.projectId;
    if (params?.page) query.page = params.page.toString();
    if (params?.limit) query.limit = params.limit.toString();
    return this.client.requestPaginated<Scan>('/api/v1/scans', query);
  }

  async waitForCompletion(scanId: string, opts?: { pollIntervalMs?: number; timeoutMs?: number }): Promise<Scan> {
    const pollInterval = opts?.pollIntervalMs || 3000;
    const timeout = opts?.timeoutMs || 600_000;
    const deadline = Date.now() + timeout;

    while (Date.now() < deadline) {
      const scan = await this.get(scanId);
      if (scan.status === 'completed' || scan.status === 'failed') {
        return scan;
      }
      await new Promise(r => setTimeout(r, pollInterval));
    }

    throw new Error(`Scan ${scanId} timed out after ${timeout}ms`);
  }
}

class FindingsApi {
  constructor(private client: CodeHardener) {}

  async list(params: { scanId?: string; projectId?: string; severity?: string; page?: number; limit?: number }): Promise<PaginatedResponse<Finding>> {
    const query: Record<string, string> = {};
    if (params.scanId) query.scanId = params.scanId;
    if (params.projectId) query.projectId = params.projectId;
    if (params.severity) query.severity = params.severity;
    if (params.page) query.page = params.page.toString();
    if (params.limit) query.limit = params.limit.toString();
    return this.client.requestPaginated<Finding>('/api/v1/findings', query);
  }

  async get(findingId: string): Promise<Finding> {
    return this.client.request<Finding>('GET', `/api/v1/findings/${findingId}`);
  }
}

class ProjectsApi {
  constructor(private client: CodeHardener) {}

  async create(params: { name: string; repositoryUrl?: string }): Promise<Project> {
    return this.client.request<Project>('POST', '/api/v1/projects', params);
  }

  async get(projectId: string): Promise<Project> {
    return this.client.request<Project>('GET', `/api/v1/projects/${projectId}`);
  }

  async list(params?: { page?: number; limit?: number }): Promise<PaginatedResponse<Project>> {
    const query: Record<string, string> = {};
    if (params?.page) query.page = params.page.toString();
    if (params?.limit) query.limit = params.limit.toString();
    return this.client.requestPaginated<Project>('/api/v1/projects', query);
  }

  async score(projectId: string): Promise<ProjectScore> {
    return this.client.request<ProjectScore>('GET', `/api/v1/projects/${projectId}/score`);
  }

  async delete(projectId: string): Promise<void> {
    await this.client.request<void>('DELETE', `/api/v1/projects/${projectId}`);
  }
}

export { ApiError };
