/**
 * Boot-time parsing of the two SAML environment variables.
 *
 * These exercise the REAL `env.ts` — the module under test here is the schema
 * itself, so mocking it would be circular. Each case re-imports the module with
 * `vi.resetModules()` after setting `process.env`, and `process.exit` is stubbed
 * to throw a sentinel so an aborted boot is observable rather than killing the
 * test runner.
 *
 * Covers:
 *   - AC-11 / KILL-001 companion: SSO_ENABLED must parse the LITERAL string
 *     'false' to boolean false. `z.coerce.boolean()` treats any non-empty string
 *     as true, which would produce a kill-switch that cannot be switched off —
 *     the worst possible failure for a safety control.
 *   - AC-21: SAML_CLOCK_SKEW_MS REJECTS out-of-range values at boot rather than
 *     clamping them. Clamping would map a poisoned `-1` silently to `0` and hide
 *     an operator error in the one setting whose entire purpose is to prevent
 *     that value — `-1` disables ALL node-saml timestamp checks (saml.js:905).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const SAML_KEYS = ['SSO_ENABLED', 'SAML_CLOCK_SKEW_MS'] as const;

class ProcessExitCalled extends Error {
  constructor(public code: number | undefined) {
    super(`process.exit(${String(code)})`);
  }
}

let saved: Partial<Record<(typeof SAML_KEYS)[number], string | undefined>>;

beforeEach(() => {
  saved = {};
  for (const key of SAML_KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  // Keep the production placeholder-secret guard out of play.
  process.env.NODE_ENV = 'test';
  vi.resetModules();
});

afterEach(() => {
  for (const key of SAML_KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
  vi.restoreAllMocks();
  vi.resetModules();
});

/**
 * Import the real env module. Returns the module on success, or the exit code
 * if the schema refused to parse and aborted startup.
 */
async function loadEnv(): Promise<
  { ok: true; mod: typeof import('./env.js') } | { ok: false; code: number | undefined }
> {
  const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new ProcessExitCalled(code);
  }) as never);
  // env.ts prints the formatted zod error before exiting; keep it off the report.
  const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  try {
    const mod = await import('./env.js');
    return { ok: true, mod };
  } catch (error) {
    if (error instanceof ProcessExitCalled) return { ok: false, code: error.code };
    throw error;
  } finally {
    exitSpy.mockRestore();
    errSpy.mockRestore();
  }
}

describe('SSO_ENABLED (REQ-013)', () => {
  it('defaults to false — SSO off unless explicitly enabled', async () => {
    const result = await loadEnv();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.mod.ssoEnabled).toBe(false);
  });

  it("parses the LITERAL string 'false' to boolean false", async () => {
    // The z.coerce.boolean() trap. If this regresses, the kill-switch is on
    // permanently and cannot be turned off.
    process.env.SSO_ENABLED = 'false';
    const result = await loadEnv();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.mod.ssoEnabled).toBe(false);
    expect(result.mod.ssoEnabled).not.toBe('false');
  });

  it("parses the literal string 'true' to boolean true", async () => {
    process.env.SSO_ENABLED = 'true';
    const result = await loadEnv();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.mod.ssoEnabled).toBe(true);
  });

  it('aborts startup on any other value rather than guessing', async () => {
    process.env.SSO_ENABLED = 'yes';
    const result = await loadEnv();
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe(1);
  });
});

describe('SAML_CLOCK_SKEW_MS (REQ-004 / AC-21)', () => {
  it('defaults to 60000', async () => {
    const result = await loadEnv();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.mod.samlClockSkewMs).toBe(60_000);
  });

  it('REJECTS -1 at boot — it does not clamp it to 0', async () => {
    // -1 disables ALL timestamp checks in node-saml, silently reinstating the
    // expired-assertion vulnerability. Clamping would hide the misconfiguration.
    process.env.SAML_CLOCK_SKEW_MS = '-1';
    const result = await loadEnv();
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe(1);
  });

  it('rejects a value above the 300000 ceiling', async () => {
    process.env.SAML_CLOCK_SKEW_MS = '300001';
    const result = await loadEnv();
    expect(result.ok).toBe(false);
  });

  it('rejects a non-integer', async () => {
    process.env.SAML_CLOCK_SKEW_MS = '1.5';
    const result = await loadEnv();
    expect(result.ok).toBe(false);
  });

  it('accepts the in-range boundaries, so the range is a real window not a blanket refusal', async () => {
    process.env.SAML_CLOCK_SKEW_MS = '0';
    const zero = await loadEnv();
    expect(zero.ok).toBe(true);
    if (zero.ok) expect(zero.mod.samlClockSkewMs).toBe(0);

    vi.resetModules();
    process.env.SAML_CLOCK_SKEW_MS = '300000';
    const max = await loadEnv();
    expect(max.ok).toBe(true);
    if (max.ok) expect(max.mod.samlClockSkewMs).toBe(300_000);
  });
});
