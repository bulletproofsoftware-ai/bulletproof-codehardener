import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkTargetHealth } from './target-health.js';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

beforeEach(() => {
  mockFetch.mockReset();
});

describe('checkTargetHealth', () => {
  it('returns true for 200 response', async () => {
    mockFetch.mockResolvedValue({ ok: true, status: 200 });
    const result = await checkTargetHealth('http://localhost:3000');
    expect(result).toBe(true);
  });

  it('returns true for 301 redirect', async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 301 });
    const result = await checkTargetHealth('http://localhost:3000');
    expect(result).toBe(true);
  });

  it('returns false for connection refused', async () => {
    mockFetch.mockRejectedValue(new Error('fetch failed'));
    const result = await checkTargetHealth('http://localhost:9999');
    expect(result).toBe(false);
  });

  it('returns false for 500 error', async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 500 });
    const result = await checkTargetHealth('http://localhost:3000');
    expect(result).toBe(false);
  });

  it('respects custom timeout', async () => {
    vi.useFakeTimers();
    mockFetch.mockImplementation(() => new Promise(() => {})); // never resolves
    const resultPromise = checkTargetHealth('http://localhost:3000', 100);
    await vi.advanceTimersByTimeAsync(150);
    const result = await resultPromise;
    expect(result).toBe(false);
    vi.useRealTimers();
  });
});
