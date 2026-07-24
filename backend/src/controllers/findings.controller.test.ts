import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ZodError } from 'zod';

vi.mock('../utils/logger.js', () => ({
  createLogger: () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));

const dbExecute = vi.fn();
vi.mock('../db/client.js', () => ({ db: { execute: (...a: unknown[]) => dbExecute(...a) } }));
vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({ strings, values, _tag: 'sql' }),
}));
// quality-score is imported by the controller module; stub to avoid side effects.
vi.mock('../services/assurance/quality-score.js', () => ({
  calculateQualityScore: () => ({ score: 1000, qualityLevel: 'excellent', breakdown: {} }),
}));

import { getFindingPatches } from './findings.controller.js';
import { NotFoundError } from '../middleware/errorHandler.js';

function sqlText(q: { strings: TemplateStringsArray }): string {
  return q.strings.join(' ');
}

function mockRes() {
  const res: any = {};
  res.status = vi.fn(() => res);
  res.json = vi.fn(() => res);
  return res;
}

const OWNER = '11111111-1111-1111-1111-111111111111';
const FINDING = '22222222-2222-2222-2222-222222222222';

beforeEach(() => vi.clearAllMocks());

describe('GET /findings/:id/patches', () => {
  it('returns patch rows (camelCase) for an owned finding', async () => {
    dbExecute.mockImplementation((q: { strings: TemplateStringsArray }) => {
      const t = sqlText(q);
      if (t.includes('SELECT f.id FROM findings f')) {
        return Promise.resolve({ rows: [{ id: FINDING }] });
      }
      if (t.includes('FROM candidate_patches cp')) {
        return Promise.resolve({
          rows: [{
            id: 'p1', finding_id: FINDING, scan_id: 's1',
            patch_diff: '--- a\n+++ b', rationale: 'fix it',
            validation_notes: 'builds: yes', model_used: 'sonnet',
            status: 'proposed', created_at: '2026-06-05T00:00:00Z',
          }],
        });
      }
      return Promise.resolve({ rows: [] });
    });

    const res = mockRes();
    await getFindingPatches({ params: { id: FINDING }, user: { id: OWNER } } as any, res);

    const body = res.json.mock.calls[0][0];
    expect(body.success).toBe(true);
    expect(body.data).toHaveLength(1);
    expect(body.data[0]).toMatchObject({
      id: 'p1', findingId: FINDING, scanId: 's1', patchDiff: '--- a\n+++ b',
      validationNotes: 'builds: yes', modelUsed: 'sonnet', status: 'proposed',
    });
  });

  it('returns [] when an owned finding has no patches', async () => {
    dbExecute.mockImplementation((q: { strings: TemplateStringsArray }) => {
      if (sqlText(q).includes('SELECT f.id FROM findings f')) return Promise.resolve({ rows: [{ id: FINDING }] });
      return Promise.resolve({ rows: [] });
    });
    const res = mockRes();
    await getFindingPatches({ params: { id: FINDING }, user: { id: OWNER } } as any, res);
    const body = res.json.mock.calls[0][0];
    expect(body.data).toEqual([]);
  });

  it('throws NotFoundError (404, no existence oracle) for a cross-tenant finding', async () => {
    // Ownership query returns no rows → not owned (or does not exist).
    dbExecute.mockResolvedValue({ rows: [] });
    const res = mockRes();
    await expect(
      getFindingPatches({ params: { id: FINDING }, user: { id: OWNER } } as any, res),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('rejects a non-uuid :id (validation error before any DB query)', async () => {
    const res = mockRes();
    await expect(
      getFindingPatches({ params: { id: 'not-a-uuid' }, user: { id: OWNER } } as any, res),
    ).rejects.toBeInstanceOf(ZodError);
    expect(dbExecute).not.toHaveBeenCalled();
  });
});
