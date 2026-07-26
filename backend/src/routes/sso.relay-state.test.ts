/**
 * H-7 — RelayState decides where the minted access token is delivered.
 *
 * `req.body.RelayState` is UNSIGNED attacker-controlled input on the
 * unauthenticated ACS POST. Origin allow-listing alone was not a control: the
 * PATH and QUERY within an allowed origin were entirely attacker-chosen, and the
 * `relay_state` this SP stored when it issued the AuthnRequest — which the SAML
 * hardening work newly collects — was never read back or compared.
 *
 * `resolveRelayTarget` is pure, so the decision is testable without an HTTP
 * server or a new test dependency. The route does nothing with RelayState that
 * is not decided here.
 */

import { describe, it, expect, vi } from 'vitest';

vi.mock('../config/env.js', () => ({
  env: { NODE_ENV: 'test', JWT_SECRET: 'test-only' },
  ssoEnabled: true,
  samlClockSkewMs: 60_000,
  isDev: false,
  isProd: false,
  isTest: true,
  corsOrigins: ['http://localhost:3000'],
}));

vi.mock('../utils/logger.js', () => ({
  createLogger: () => ({ debug: () => {}, info: () => {}, warn: () => {}, error: () => {} }),
}));

vi.mock('../db/client.js', () => ({ db: { execute: async () => ({ rows: [], rowCount: 0 }) } }));
vi.mock('drizzle-orm', () => ({ sql: () => ({ _tag: 'sql' }) }));

import { resolveRelayTarget } from './sso.routes.js';

const ORIGINS = ['http://localhost:3000', 'https://app.example.test'];

describe('H-7 resolveRelayTarget', () => {
  it('redirects to the STORED relay state when the IdP echoes it back unchanged', () => {
    const stored = 'https://app.example.test/dashboard?team=1';
    const decision = resolveRelayTarget(stored, stored, ORIGINS);
    expect(decision.kind).toBe('redirect');
    if (decision.kind !== 'redirect') return;
    expect(decision.url.origin).toBe('https://app.example.test');
    expect(decision.url.pathname).toBe('/dashboard');
  });

  it('rejects a posted RelayState that differs from the stored one', () => {
    // The core of H-7. Both values are inside an ALLOWED origin, so origin
    // checking passes and passes again — only the comparison against the stored
    // value distinguishes them. An attacker who chooses the path within a
    // trusted origin chooses where the access token lands.
    const decision = resolveRelayTarget(
      'https://app.example.test/attacker-controlled-landing',
      'https://app.example.test/dashboard',
      ORIGINS
    );
    expect(decision).toEqual({ kind: 'reject', reason: 'relay_state_mismatch' });
  });

  it('rejects a posted RelayState when the SP stored NONE', () => {
    // SP-initiated is the only supported flow here (validateInResponseTo is
    // `always`), so a RelayState the SP never issued cannot be legitimate.
    const decision = resolveRelayTarget('https://app.example.test/', null, ORIGINS);
    expect(decision).toEqual({ kind: 'reject', reason: 'relay_state_mismatch' });
  });

  it('rejects when the SP stored one and the IdP returned NONE', () => {
    const decision = resolveRelayTarget(undefined, 'https://app.example.test/dashboard', ORIGINS);
    expect(decision).toEqual({ kind: 'reject', reason: 'relay_state_mismatch' });
  });

  it('returns JSON when neither side carries a relay state', () => {
    expect(resolveRelayTarget(undefined, null, ORIGINS)).toEqual({ kind: 'json' });
  });

  it('returns JSON for a matching non-URL relay state rather than redirecting', () => {
    expect(resolveRelayTarget('opaque-token', 'opaque-token', ORIGINS)).toEqual({ kind: 'json' });
  });

  it('rejects an ARRAY RelayState instead of throwing after the tokens are minted', () => {
    // `express.urlencoded({ extended: true })` turns `RelayState[]=a&RelayState[]=b`
    // into an array. The previous bare `relayState.startsWith('http')` raised a
    // TypeError — AFTER `processSAMLResponse` had minted tokens and promoted the
    // session — which surfaces as a 500 on a successful authentication.
    expect(resolveRelayTarget(['https://app.example.test/'], null, ORIGINS)).toEqual({
      kind: 'reject',
      reason: 'relay_state_invalid',
    });
    expect(resolveRelayTarget({ evil: 1 }, null, ORIGINS)).toEqual({
      kind: 'reject',
      reason: 'relay_state_invalid',
    });
  });

  it('still rejects an off-origin relay state, even though it now comes from our own row', () => {
    // Defence in depth: `sso_sessions.relay_state` is written from a query
    // parameter on the login route, so it is operator-facing input too.
    const stored = 'https://evil.test/steal';
    expect(resolveRelayTarget(stored, stored, ORIGINS)).toEqual({
      kind: 'reject',
      reason: 'relay_state_origin',
    });
  });

  it('rejects an unparseable http-prefixed relay state', () => {
    const stored = 'http://';
    expect(resolveRelayTarget(stored, stored, ORIGINS)).toEqual({
      kind: 'reject',
      reason: 'relay_state_invalid',
    });
  });
});
