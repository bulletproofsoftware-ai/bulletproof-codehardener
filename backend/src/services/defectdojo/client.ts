import { env } from '../../config/env.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('defectdojo-client');

interface DDProduct {
  id: number;
  name: string;
  description: string;
  prod_type: number;
}

interface DDEngagement {
  id: number;
  name: string;
  product: number;
  target_start: string;
  target_end: string;
  status: string;
  engagement_type: string;
}

interface DDFinding {
  id: number;
  title: string;
  severity: string;
  description: string;
  file_path: string | null;
  line: number | null;
  cwe: number | null;
  active: boolean;
  verified: boolean;
}

interface DDImportResult {
  test: number;
  findings_affected: number;
  test_import: { id: number };
}

interface DDProductMetrics {
  product_id: number;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export class DefectDojoClient {
  private baseUrl: string;
  private apiKey: string;
  private enabled: boolean;

  constructor() {
    this.baseUrl = env.DEFECTDOJO_URL.replace(/\/$/, '');
    this.apiKey = env.DEFECTDOJO_API_KEY || '';
    this.enabled = env.DEFECTDOJO_ENABLED;
  }

  isEnabled(): boolean {
    return this.enabled && !!this.apiKey;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    isFormData?: boolean
  ): Promise<T | null> {
    if (!this.isEnabled()) {
      logger.debug('DefectDojo disabled, skipping request');
      return null;
    }

    const url = `${this.baseUrl}/api/v2${path}`;
    const headers: Record<string, string> = {
      Authorization: `Token ${this.apiKey}`,
    };

    let requestBody: string | FormData | undefined;
    if (body && isFormData) {
      const formData = new FormData();
      for (const [key, value] of Object.entries(body)) {
        if (value instanceof Blob) {
          formData.append(key, value);
        } else if (value !== undefined && value !== null) {
          formData.append(key, String(value));
        }
      }
      requestBody = formData;
    } else if (body) {
      headers['Content-Type'] = 'application/json';
      requestBody = JSON.stringify(body);
    }

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: requestBody,
        signal: AbortSignal.timeout(30000),
      });

      if (!response.ok) {
        const errorText = await response.text();
        logger.error({ status: response.status, path, error: errorText }, 'DefectDojo API error');
        return null;
      }

      if (response.status === 204) return null;
      return (await response.json()) as T;
    } catch (error) {
      logger.error({ error, path }, 'DefectDojo request failed');
      return null;
    }
  }

  async createProduct(name: string, description: string, prodType: number = 1): Promise<DDProduct | null> {
    return this.request<DDProduct>('POST', '/products/', {
      name,
      description,
      prod_type: prodType,
    });
  }

  async getProduct(productId: number): Promise<DDProduct | null> {
    return this.request<DDProduct>('GET', `/products/${productId}/`);
  }

  async createEngagement(
    productId: number,
    name: string,
    opts: { branch?: string; commitSha?: string; scanProfile?: string } = {}
  ): Promise<DDEngagement | null> {
    const today = new Date().toISOString().split('T')[0];
    return this.request<DDEngagement>('POST', '/engagements/', {
      name,
      product: productId,
      target_start: today,
      target_end: today,
      engagement_type: 'CI/CD',
      status: 'In Progress',
      branch_tag: opts.branch || 'main',
      commit_hash: opts.commitSha || '',
      build_id: opts.scanProfile || 'standard',
    });
  }

  async closeEngagement(engagementId: number): Promise<void> {
    await this.request('PATCH', `/engagements/${engagementId}/`, {
      status: 'Completed',
    });
  }

  async importScan(
    engagementId: number,
    scanType: string,
    rawOutput: string,
    opts: { minimumSeverity?: string; active?: boolean; verified?: boolean } = {}
  ): Promise<DDImportResult | null> {
    const file = new Blob([rawOutput], { type: 'application/json' });
    return this.request<DDImportResult>('POST', '/import-scan/', {
      engagement: engagementId,
      scan_type: scanType,
      file,
      minimum_severity: opts.minimumSeverity || 'Info',
      active: opts.active ?? true,
      verified: opts.verified ?? false,
      close_old_findings: false,
    }, true);
  }

  async reimportScan(
    testId: number,
    scanType: string,
    rawOutput: string
  ): Promise<DDImportResult | null> {
    const file = new Blob([rawOutput], { type: 'application/json' });
    return this.request<DDImportResult>('POST', '/reimport-scan/', {
      test: testId,
      scan_type: scanType,
      file,
      minimum_severity: 'Info',
      active: true,
      verified: false,
    }, true);
  }

  async getFindings(
    productId?: number,
    opts: { severity?: string; active?: boolean; limit?: number; offset?: number } = {}
  ): Promise<{ count: number; results: DDFinding[] } | null> {
    const params = new URLSearchParams();
    if (productId) params.set('test__engagement__product', String(productId));
    if (opts.severity) params.set('severity', opts.severity);
    if (opts.active !== undefined) params.set('active', String(opts.active));
    params.set('limit', String(opts.limit || 25));
    params.set('offset', String(opts.offset || 0));

    return this.request<{ count: number; results: DDFinding[] }>(
      'GET',
      `/findings/?${params.toString()}`
    );
  }

  async getProductMetrics(productId: number): Promise<DDProductMetrics | null> {
    const findings = await this.getFindings(productId, { active: true, limit: 0 });
    if (!findings) return null;

    // Get counts by severity
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const sev of ['Critical', 'High', 'Medium', 'Low', 'Info'] as const) {
      const result = await this.getFindings(productId, {
        severity: sev,
        active: true,
        limit: 0,
      });
      const key = sev.toLowerCase() as keyof typeof severityCounts;
      severityCounts[key] = result?.count || 0;
    }

    return {
      product_id: productId,
      total: findings.count,
      ...severityCounts,
    };
  }

  async healthCheck(): Promise<boolean> {
    if (!this.isEnabled()) return false;
    try {
      const result = await this.request<{ user: string }>('GET', '/user_contact_infos/');
      return result !== null;
    } catch {
      return false;
    }
  }
}

// Singleton instance
let client: DefectDojoClient | null = null;

export function getDefectDojoClient(): DefectDojoClient {
  if (!client) {
    client = new DefectDojoClient();
  }
  return client;
}
