import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../../config/env.js', () => ({
  env: {
    DEFECTDOJO_URL: 'http://defectdojo:8080',
    DEFECTDOJO_API_KEY: 'test-api-key',
    DEFECTDOJO_ENABLED: true,
  },
}));

vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

import { DefectDojoClient } from './client.js';

describe('DefectDojoClient', () => {
  let client: DefectDojoClient;
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    client = new DefectDojoClient();
    fetchSpy = vi.spyOn(globalThis, 'fetch');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('isEnabled', () => {
    it('returns true when enabled and API key is set', () => {
      expect(client.isEnabled()).toBe(true);
    });
  });

  describe('createProduct', () => {
    it('sends POST to /api/v2/products/', async () => {
      const mockProduct = { id: 1, name: 'Test', description: 'desc', prod_type: 1 };
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(mockProduct), { status: 200 }));

      const result = await client.createProduct('Test', 'desc');

      expect(fetchSpy).toHaveBeenCalledOnce();
      const [url, opts] = fetchSpy.mock.calls[0];
      expect(url).toBe('http://defectdojo:8080/api/v2/products/');
      expect(opts?.method).toBe('POST');
      expect(opts?.headers).toHaveProperty('Authorization', 'Token test-api-key');
      expect(result).toEqual(mockProduct);
    });

    it('returns null on API error', async () => {
      fetchSpy.mockResolvedValueOnce(new Response('Not Found', { status: 404 }));

      const result = await client.createProduct('Test', 'desc');
      expect(result).toBeNull();
    });

    it('returns null on network error', async () => {
      fetchSpy.mockRejectedValueOnce(new Error('Connection refused'));

      const result = await client.createProduct('Test', 'desc');
      expect(result).toBeNull();
    });
  });

  describe('getProduct', () => {
    it('sends GET to /api/v2/products/:id/', async () => {
      const mockProduct = { id: 42, name: 'My Product', description: '', prod_type: 1 };
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(mockProduct), { status: 200 }));

      const result = await client.getProduct(42);

      const [url, opts] = fetchSpy.mock.calls[0];
      expect(url).toBe('http://defectdojo:8080/api/v2/products/42/');
      expect(opts?.method).toBe('GET');
      expect(result).toEqual(mockProduct);
    });
  });

  describe('createEngagement', () => {
    it('sends POST with engagement details', async () => {
      const mockEngagement = {
        id: 10,
        name: 'Scan',
        product: 1,
        target_start: '2025-01-01',
        target_end: '2025-01-01',
        status: 'In Progress',
        engagement_type: 'CI/CD',
      };
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(mockEngagement), { status: 201 }));

      const result = await client.createEngagement(1, 'Scan', { branch: 'develop' });

      const [url, opts] = fetchSpy.mock.calls[0];
      expect(url).toBe('http://defectdojo:8080/api/v2/engagements/');
      expect(opts?.method).toBe('POST');
      const body = JSON.parse(opts?.body as string);
      expect(body.product).toBe(1);
      expect(body.name).toBe('Scan');
      expect(body.branch_tag).toBe('develop');
      expect(result).toEqual(mockEngagement);
    });
  });

  describe('closeEngagement', () => {
    it('sends PATCH with Completed status', async () => {
      fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

      await client.closeEngagement(10);

      const [url, opts] = fetchSpy.mock.calls[0];
      expect(url).toBe('http://defectdojo:8080/api/v2/engagements/10/');
      expect(opts?.method).toBe('PATCH');
      const body = JSON.parse(opts?.body as string);
      expect(body.status).toBe('Completed');
    });
  });

  describe('importScan', () => {
    it('sends POST with FormData for file upload', async () => {
      const mockResult = { test: 1, findings_affected: 5, test_import: { id: 100 } };
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(mockResult), { status: 201 }));

      const result = await client.importScan(10, 'Trivy Scan', '{"results":[]}');

      const [url, opts] = fetchSpy.mock.calls[0];
      expect(url).toBe('http://defectdojo:8080/api/v2/import-scan/');
      expect(opts?.method).toBe('POST');
      // FormData doesn't set Content-Type header manually
      expect(opts?.headers).not.toHaveProperty('Content-Type');
      expect(result).toEqual(mockResult);
    });
  });

  describe('getFindings', () => {
    it('queries findings with filters', async () => {
      const mockFindings = { count: 3, results: [{ id: 1 }, { id: 2 }, { id: 3 }] };
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(mockFindings), { status: 200 }));

      const result = await client.getFindings(1, { severity: 'High', active: true, limit: 10 });

      const [url] = fetchSpy.mock.calls[0];
      expect(url).toContain('test__engagement__product=1');
      expect(url).toContain('severity=High');
      expect(url).toContain('active=true');
      expect(url).toContain('limit=10');
      expect(result?.count).toBe(3);
    });

    it('works without product filter', async () => {
      const mockFindings = { count: 0, results: [] };
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(mockFindings), { status: 200 }));

      const result = await client.getFindings();

      const [url] = fetchSpy.mock.calls[0];
      expect(url).not.toContain('test__engagement__product');
      expect(result?.count).toBe(0);
    });
  });

  describe('healthCheck', () => {
    it('returns true when API responds', async () => {
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ user: 'admin' }), { status: 200 }));

      const result = await client.healthCheck();
      expect(result).toBe(true);
    });

    it('returns false on error', async () => {
      fetchSpy.mockRejectedValueOnce(new Error('timeout'));

      const result = await client.healthCheck();
      expect(result).toBe(false);
    });
  });
});

describe('DefectDojoClient request handling', () => {
  it('returns null when response is 204 No Content', async () => {
    const client = new DefectDojoClient();
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

    await client.closeEngagement(99);
    // closeEngagement returns void, so no assertion needed — just verifying no throw
    expect(fetchSpy).toHaveBeenCalledOnce();
    vi.restoreAllMocks();
  });

  it('handles concurrent requests without interference', async () => {
    const client = new DefectDojoClient();
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const product1 = { id: 1, name: 'P1', description: '', prod_type: 1 };
    const product2 = { id: 2, name: 'P2', description: '', prod_type: 1 };

    fetchSpy
      .mockResolvedValueOnce(new Response(JSON.stringify(product1), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(product2), { status: 200 }));

    const [r1, r2] = await Promise.all([
      client.getProduct(1),
      client.getProduct(2),
    ]);

    expect(r1).toEqual(product1);
    expect(r2).toEqual(product2);
    vi.restoreAllMocks();
  });
});
