// API client for Code Hardener Dashboard

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000/api/v1';

// Convert snake_case keys to camelCase recursively
function snakeToCamel(str: string): string {
  return str.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
}

function transformKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(transformKeys);
  if (obj !== null && typeof obj === 'object' && !(obj instanceof Date)) {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[snakeToCamel(key)] = transformKeys(value);
    }
    return result;
  }
  return obj;
}

// Check if running in dev mode (localhost)
function isDevMode(): boolean {
  if (typeof window === 'undefined') return false;
  return process.env.NEXT_PUBLIC_DEV_MODE === 'true' || window.location.hostname === 'localhost';
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type QueryParams = Record<string, any> | undefined;

interface ApiOptions extends RequestInit {
  params?: QueryParams;
}

class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public data?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function getAuthToken(): Promise<string | null> {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('auth_token');
}

export async function api<T>(endpoint: string, options: ApiOptions = {}): Promise<T> {
  const { params, ...fetchOptions } = options;

  let url = `${API_BASE_URL}${endpoint}`;

  // Add query parameters
  if (params) {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value === undefined) return;
      if (Array.isArray(value)) {
        value.forEach((v) => searchParams.append(key, String(v)));
      } else {
        searchParams.append(key, String(value));
      }
    });
    const queryString = searchParams.toString();
    if (queryString) {
      url += `?${queryString}`;
    }
  }

  // Build auth headers - in dev mode always use X-User-Id header for consistent auth
  const authHeaders: Record<string, string> = {};
  if (isDevMode()) {
    authHeaders['X-User-Id'] = 'dev@codehardener.local';
  } else {
    const token = await getAuthToken();
    if (token) {
      authHeaders['Authorization'] = `Bearer ${token}`;
    }
  }

  const response = await fetch(url, {
    ...fetchOptions,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders,
      ...fetchOptions.headers,
    },
  });

  if (!response.ok) {
    const data = await response.json().catch(() => null);
    // Backend returns errors as { success: false, error: { code, message } }
    const errorMessage = data?.error?.message || data?.message || `HTTP ${response.status}`;
    throw new ApiError(
      errorMessage,
      response.status,
      data
    );
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as T;
  }

  const raw = await response.json();
  const json = transformKeys(raw) as Record<string, unknown>;

  // Unwrap the standard API response format { success: true, data: ..., meta?: ... }
  if (json && typeof json === 'object' && 'success' in json && 'data' in json) {
    // If there's pagination meta, return as PaginatedResponse format
    if ('meta' in json && json.meta) {
      const result: Record<string, unknown> = {
        data: json.data,
        pagination: json.meta,
      };
      // Pass through any extra top-level fields (like summary)
      if ('summary' in json) {
        result.summary = json.summary;
      }
      return result as T;
    }
    return json.data as T;
  }

  return json as T;
}

// Auth response type (unwrapped from { success, data })
interface AuthResponse {
  user: import('@/types').User;
  tokens: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  };
}

// Auth endpoints
export const authApi = {
  login: (email: string, password: string) =>
    api<AuthResponse>(
      '/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      }
    ),

  register: (data: { email: string; password: string; name: string }) =>
    api<AuthResponse>(
      '/auth/register',
      {
        method: 'POST',
        body: JSON.stringify(data),
      }
    ),

  logout: () =>
    api<void>('/auth/logout', { method: 'POST' }),

  me: () =>
    api<{ user: import('@/types').User }>('/auth/me'),

  updateProfile: (data: { name?: string; email?: string }) =>
    api<import('@/types').User>('/auth/me', {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  changePassword: (currentPassword: string, newPassword: string) =>
    api<{ message: string }>('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    }),

  deleteAccount: () =>
    api<{ message: string }>('/auth/me', { method: 'DELETE' }),

  refreshToken: (refreshToken: string) =>
    api<{ accessToken: string; refreshToken: string }>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken }),
    }),
};

// Dashboard endpoints
export const dashboardApi = {
  getSummary: () =>
    api<import('@/types').DashboardSummary>('/dashboard/summary'),
};

// Projects endpoints
export const projectsApi = {
  list: (params?: import('@/types').ProjectsFilters & { page?: number; limit?: number }) =>
    api<import('@/types').PaginatedResponse<import('@/types').Project>>('/projects', { params }),

  get: (id: string) =>
    api<import('@/types').Project>(`/projects/${id}`),

  create: (data: { name: string; description?: string; repositoryUrl?: string }) =>
    api<import('@/types').Project>('/projects', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: Partial<import('@/types').Project>) =>
    api<import('@/types').Project>(`/projects/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    api<void>(`/projects/${id}`, { method: 'DELETE' }),
};

// Scans endpoints
export const scansApi = {
  list: (params?: import('@/types').ScansFilters & { page?: number; limit?: number }) =>
    api<import('@/types').PaginatedResponse<import('@/types').Scan>>('/scans', { params }),

  get: (id: string) =>
    api<import('@/types').Scan>(`/scans/${id}`),

  create: (data: {
    projectId: string;
    scanType?: string;
    branch?: string;
    commit?: string;
    scanners?: string[];
    targetUrlOverride?: string;
    containerImageOverride?: string;
    openapiSpecOverride?: string;
    options?: {
      depth?: 'shallow' | 'full';
      excludePatterns?: string[];
      failThreshold?: string;
      timeout?: number;
      parallel?: boolean;
    };
  }) =>
    api<import('@/types').Scan>('/scans', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  cancel: (id: string) =>
    api<import('@/types').Scan>(`/scans/${id}/cancel`, { method: 'POST' }),

  getFindings: (scanId: string, params?: { severity?: string[]; scanner?: string; status?: string; page?: number; limit?: number }) =>
    api<import('@/types').PaginatedResponse<import('@/types').Finding>>(`/scans/${scanId}/findings`, { params }),

  getAttestation: (scanId: string) =>
    api<{
      id: string;
      scanId: string;
      attestationType: string;
      subjectName: string;
      subjectDigest: string;
      predicate: Record<string, unknown>;
      signature: string | null;
      signatureAlgorithm: string | null;
      certificate: string | null;
      rekorLogId: string | null;
      transparencyLogUrl: string | null;
      createdAt: string;
    }>(`/scans/${scanId}/attestation`),
};

// Findings endpoints
export const findingsApi = {
  list: (params?: import('@/types').FindingsFilters & { page?: number; limit?: number }) =>
    api<import('@/types').PaginatedResponse<import('@/types').Finding> & { summary: { critical: number; high: number; medium: number; low: number; info: number; total: number } }>(
      '/findings',
      { params }
    ),

  get: (id: string) =>
    api<import('@/types').Finding>(`/findings/${id}`),

  updateStatus: (id: string, status: import('@/types').FindingStatus, reason?: string, comment?: string) =>
    api<import('@/types').Finding>(`/findings/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, ...(reason && { reason }), ...(comment && { comment }) }),
    }),

  bulkUpdateStatus: (ids: string[], status: import('@/types').FindingStatus, reason?: string, comment?: string) =>
    api<{ updated: number }>('/findings/bulk-status', {
      method: 'POST',
      body: JSON.stringify({ ids, status, ...(reason && { reason }), ...(comment && { comment }) }),
    }),
};

// Suppression rules endpoints
export const suppressionsApi = {
  list: (params?: { projectId?: string }) =>
    api<Array<{
      id: string;
      projectId: string;
      projectName: string;
      matchType: 'rule_id' | 'scanner' | 'cwe' | 'title_pattern';
      matchValue: string;
      targetStatus: string;
      reason: string | null;
      comment: string | null;
      isActive: boolean;
      createdAt: string;
      updatedAt: string;
    }>>('/suppressions', { params }),

  create: (data: {
    projectId: string;
    matchType: 'rule_id' | 'scanner' | 'cwe' | 'title_pattern';
    matchValue: string;
    targetStatus?: string;
    reason?: string;
    comment?: string;
  }) =>
    api('/suppressions', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: {
    matchValue?: string;
    targetStatus?: string;
    reason?: string;
    comment?: string;
    isActive?: boolean;
  }) =>
    api(`/suppressions/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    api(`/suppressions/${id}`, { method: 'DELETE' }),
};

// Attestations endpoints
export const attestationsApi = {
  list: (params?: { projectId?: string; page?: number; limit?: number }) =>
    api<import('@/types').PaginatedResponse<import('@/types').Attestation>>('/attestations', { params }),

  get: (id: string) =>
    api<import('@/types').Attestation>(`/attestations/${id}`),

  generate: (scanId: string) =>
    api<import('@/types').Attestation>('/attestations', {
      method: 'POST',
      body: JSON.stringify({ scanId }),
    }),

  verify: (id: string) =>
    api<{ valid: boolean; message: string }>(`/attestations/${id}/verify`),
};

// Policies endpoints
export const policiesApi = {
  list: (params?: { page?: number; limit?: number }) =>
    api<import('@/types').PaginatedResponse<import('@/types').Policy>>('/policies', { params }),

  get: (id: string) =>
    api<import('@/types').Policy>(`/policies/${id}`),

  create: (data: Omit<import('@/types').Policy, 'id' | 'createdAt' | 'updatedAt'>) =>
    api<import('@/types').Policy>('/policies', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: Partial<import('@/types').Policy>) =>
    api<import('@/types').Policy>(`/policies/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    api<void>(`/policies/${id}`, { method: 'DELETE' }),

  test: (policyId: string, scanId: string) =>
    api<{ passed: boolean; gates: { name: string; passed: boolean; expected: string; actual: string }[] }>(
      `/policies/${policyId}/test`,
      {
        method: 'POST',
        body: JSON.stringify({ scanId }),
      }
    ),
};

// Reports endpoints
export const reportsApi = {
  list: (params?: { page?: number; limit?: number }) =>
    api<import('@/types').PaginatedResponse<import('@/types').Report>>('/reports', { params }),

  get: (id: string) =>
    api<import('@/types').Report>(`/reports/${id}`),

  generate: (data: { name: string; type: string; projectIds: string[]; dateRange: { start: string; end: string } }) =>
    api<import('@/types').Report>('/reports', {
      method: 'POST',
      body: JSON.stringify({
        title: data.name,
        reportType: data.type,
        format: 'json',
        projectId: data.projectIds.length === 1 ? data.projectIds[0] : undefined,
      }),
    }),

  delete: (id: string) =>
    api<void>(`/reports/${id}`, { method: 'DELETE' }),
};

// API Keys endpoints
export const apiKeysApi = {
  list: () =>
    api<import('@/types').ApiKey[]>('/api-keys'),

  create: (name: string, expiresAt?: string) =>
    api<import('@/types').ApiKey & { key: string }>('/api-keys', {
      method: 'POST',
      body: JSON.stringify({ name, expiresAt }),
    }),

  delete: (id: string) =>
    api<void>(`/api-keys/${id}`, { method: 'DELETE' }),
};

// Team endpoints
export const teamApi = {
  list: () =>
    api<import('@/types').TeamMember[]>('/team/members'),

  invite: (email: string, role: import('@/types').TeamMember['role']) =>
    api<import('@/types').TeamMember>('/team/invite', {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    }),

  updateRole: (id: string, role: import('@/types').TeamMember['role']) =>
    api<import('@/types').TeamMember>(`/team/members/${id}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    }),

  remove: (id: string) =>
    api<void>(`/team/members/${id}`, { method: 'DELETE' }),
};

// Webhooks endpoints
export const webhooksApi = {
  list: () =>
    api<import('@/types').Webhook[]>('/webhooks'),

  create: (data: { url: string; events: string[] }) =>
    api<import('@/types').Webhook>('/webhooks', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: Partial<import('@/types').Webhook>) =>
    api<import('@/types').Webhook>(`/webhooks/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    api<void>(`/webhooks/${id}`, { method: 'DELETE' }),

  test: (id: string) =>
    api<{ success: boolean; statusCode: number }>(`/webhooks/${id}/test`, { method: 'POST' }),
};

// Notifications endpoints
export const notificationsApi = {
  list: () =>
    api<import('@/types').Notification[]>('/notifications'),

  markRead: (id: string) =>
    api<void>(`/notifications/${id}/read`, { method: 'POST' }),

  markAllRead: () =>
    api<void>('/notifications/read-all', { method: 'POST' }),

  getPreferences: () =>
    api<{
      slackConnected: boolean;
      slackChannel: string | null;
      settings: Array<{
        id: string;
        label: string;
        description: string;
        email: boolean;
        slack: boolean;
      }>;
    }>('/notifications/preferences'),

  updatePreferences: (settings: Array<{ id: string; email: boolean; slack: boolean }>) =>
    api<{ message: string }>('/notifications/preferences', {
      method: 'PUT',
      body: JSON.stringify({ settings }),
    }),
};

// Badges endpoints
export const badgesApi = {
  getUrl: (projectId: string) =>
    `${API_BASE_URL}/badges/${projectId}`,

  getMarkdown: (projectId: string) =>
    `[![Security Score](${API_BASE_URL}/badges/${projectId})](${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3001'}/projects/${projectId})`,

  getHtml: (projectId: string, projectName: string) =>
    `<a href="${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3001'}/projects/${projectId}"><img src="${API_BASE_URL}/badges/${projectId}" alt="Security Score - ${projectName}"></a>`,
};

// Billing endpoints
export const billingApi = {
  get: async () => {
    const [subscription, paymentMethods] = await Promise.all([
      api<{
        plan: {
          id: string;
          name: string;
          price: number;
          interval: string;
          features?: string[];
        };
        status: 'active' | 'past_due' | 'canceled' | 'trialing';
        features?: string[];
        currentPeriodStart: string;
        currentPeriodEnd: string;
        cancelAtPeriodEnd: boolean;
      }>('/billing/subscription'),
      api<Array<{
        id: string;
        type: string;
        last4: string;
        expMonth: number;
        expYear: number;
        isDefault: boolean;
      }>>('/billing/payment-methods'),
    ]);
    // Merge features from top-level into plan if needed
    const plan = {
      ...subscription.plan,
      features: subscription.plan.features || subscription.features || [],
    };
    return {
      subscription: { ...subscription, plan },
      paymentMethods,
    };
  },

  getInvoices: (limit?: number) =>
    api<Array<{
      id: string;
      date: string;
      description: string;
      amount: number;
      status: 'paid' | 'pending' | 'failed';
      pdfUrl?: string;
    }>>('/billing/history', { params: { limit } }),

  getPlans: () =>
    api<Array<{
      id: string;
      name: string;
      price: number;
      interval: string;
      features: string[];
    }>>('/billing/plans'),

  subscribe: (planId: string) =>
    api<{ message: string; subscription: unknown }>('/billing/subscribe', {
      method: 'POST',
      body: JSON.stringify({ planId }),
    }),

  cancel: () =>
    api<{ message: string; cancelAt: string }>('/billing/cancel', {
      method: 'POST',
    }),
};

// Tests endpoints
export const testsApi = {
  run: (data?: { testType?: 'unit' | 'integration' | 'all'; coverage?: boolean; filter?: string }) =>
    api<{ runId: string; status: string; message: string }>('/tests/run', {
      method: 'POST',
      body: JSON.stringify(data || {}),
    }),

  getStatus: (runId: string) =>
    api<{
      id: string;
      status: 'pending' | 'running' | 'completed' | 'failed';
      startedAt: string;
      completedAt?: string;
      duration?: number;
      testType: string;
      coverage: boolean;
      results?: {
        total: number;
        passed: number;
        failed: number;
        skipped: number;
        files: Array<{
          name: string;
          path: string;
          tests: number;
          passed: number;
          failed: number;
          duration: number;
        }>;
      };
      recentOutput: string[];
      error?: string;
    }>(`/tests/status/${runId}`),

  getHistory: (params?: { page?: number; limit?: number }) =>
    api<{
      data: Array<{
        id: string;
        status: 'pending' | 'running' | 'completed' | 'failed';
        startedAt: string;
        completedAt?: string;
        duration?: number;
        testType: string;
        coverage: boolean;
        results?: {
          total: number;
          passed: number;
          failed: number;
        };
        error?: string;
      }>;
      pagination: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
      };
    }>('/tests/history', { params }),

  getDetails: (runId: string) =>
    api<{
      id: string;
      status: 'pending' | 'running' | 'completed' | 'failed';
      startedAt: string;
      completedAt?: string;
      duration?: number;
      testType: string;
      coverage: boolean;
      results?: {
        total: number;
        passed: number;
        failed: number;
        skipped: number;
        files: Array<{
          name: string;
          path: string;
          tests: number;
          passed: number;
          failed: number;
          duration: number;
        }>;
      };
      output: string[];
      error?: string;
    }>(`/tests/${runId}`),
};

// Integrations endpoints
export const integrationsApi = {
  list: () =>
    api<Array<{
      id: string;
      provider: string;
      name: string;
      description: string;
      connected: boolean;
      connectedAt?: string;
      details?: string;
    }>>('/integrations'),

  get: (provider: string) =>
    api<{
      id: string;
      provider: string;
      name: string;
      description: string;
      connected: boolean;
      config: Record<string, unknown>;
      connectedAt?: string;
    }>(`/integrations/${provider}`),

  connect: (provider: string, config?: Record<string, unknown>) =>
    api<{ id: string; message: string; oauthUrl?: string }>(`/integrations/${provider}/connect`, {
      method: 'POST',
      body: JSON.stringify({ config }),
    }),

  disconnect: (provider: string) =>
    api<{ message: string }>(`/integrations/${provider}/disconnect`, {
      method: 'POST',
    }),

  update: (provider: string, config: Record<string, unknown>) =>
    api<{ message: string }>(`/integrations/${provider}`, {
      method: 'PUT',
      body: JSON.stringify({ config }),
    }),
};
