import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { sendSuccess, sendValidationError } from '../utils/apiResponse.js';
import { authenticate } from '../middleware/auth.js';
import { createLogger } from '../utils/logger.js';
import {
  getSSOConfig,
  upsertSSOConfig,
  toggleSSO,
  initiateSAMLLogin,
  processSAMLResponse,
  generateSPMetadata,
  deleteSSOConfig,
} from '../services/sso/saml.service.js';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { corsOrigins, ssoEnabled } from '../config/env.js';
import { AppError, NotFoundError } from '../middleware/errorHandler.js';

const logger = createLogger('sso-routes');
const router = Router();

/**
 * Kill-switch, router layer (§B.13 layer 2).
 *
 * `app.ts` already refuses to mount this router when SSO_ENABLED is false, so
 * this is defence in depth: the surface stays closed even if the mount is ever
 * made unconditional again. A 404 is returned rather than a 403 so a disabled
 * deployment is indistinguishable from one that never had these routes.
 */
function requireSsoEnabled(_req: Request, _res: Response, next: NextFunction): void {
  if (!ssoEnabled) {
    next(new NotFoundError());
    return;
  }
  next();
}

router.use(requireSsoEnabled);

// Validation schemas
const ssoConfigSchema = z.object({
  idpEntityId: z.string().min(1, 'IdP Entity ID is required'),
  idpSsoUrl: z.string().url('IdP SSO URL must be a valid URL'),
  idpCertificate: z.string().min(1, 'IdP certificate is required'),
  idpMetadataUrl: z.string().url().optional(),
  spEntityId: z.string().min(1, 'SP Entity ID is required'),
  spAcsUrl: z.string().url('SP ACS URL must be a valid URL'),
  attributeMapping: z.record(z.string()).optional(),
  forceAuthn: z.boolean().optional(),
  signAuthnRequest: z.boolean().optional(),
  autoProvisionUsers: z.boolean().optional(),
  defaultRole: z.enum(['member', 'admin']).optional(),
});

/**
 * Helper: get team ID for current user and verify Team/Enterprise tier
 */
async function getTeamForUser(userId: string): Promise<string> {
  const result = await db.execute(
    sql`SELECT tm.team_id, t.name
        FROM team_members tm
        JOIN teams t ON t.id = tm.team_id
        WHERE tm.user_id = ${userId} AND tm.role = 'admin'
        LIMIT 1`
  );

  if (result.rows.length === 0) {
    throw new Error('You must be a team admin to manage SSO');
  }

  return (result.rows[0] as any).team_id;
}

// ============================================================================
// Admin endpoints (require authentication + team admin)
// ============================================================================

// Get SSO configuration for the user's team
router.get('/config', authenticate, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const teamId = await getTeamForUser(req.user!.id);
    const config = await getSSOConfig(teamId);

    if (!config) {
      sendSuccess(res, { configured: false });
      return;
    }

    // Don't expose the full certificate in the response
    sendSuccess(res, {
      configured: true,
      config: {
        ...config,
        idpCertificate: config.idpCertificate ? '***configured***' : null,
      },
    });
  } catch (error) {
    next(error);
  }
});

// Create or update SSO configuration
router.put('/config', authenticate, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const validation = ssoConfigSchema.safeParse(req.body);
    if (!validation.success) {
      sendValidationError(res, validation.error.errors);
      return;
    }

    const teamId = await getTeamForUser(req.user!.id);
    const config = await upsertSSOConfig(teamId, validation.data);

    sendSuccess(res, { config });
  } catch (error) {
    next(error);
  }
});

// Enable/disable SSO
router.patch('/config/toggle', authenticate, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { enabled } = z.object({ enabled: z.boolean() }).parse(req.body);
    const teamId = await getTeamForUser(req.user!.id);
    await toggleSSO(teamId, enabled);
    sendSuccess(res, { enabled });
  } catch (error) {
    next(error);
  }
});

// Delete SSO configuration
router.delete('/config', authenticate, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const teamId = await getTeamForUser(req.user!.id);
    await deleteSSOConfig(teamId);
    sendSuccess(res, { message: 'SSO configuration deleted' });
  } catch (error) {
    next(error);
  }
});

/**
 * Where the ACS response goes, decided from the SP's OWN stored `relay_state`.
 *
 * H-7. `req.body.RelayState` is unsigned attacker-controlled input on an
 * unauthenticated endpoint, and it selects the URL an access token is delivered
 * to. Origin allow-listing alone was not enough: the PATH and QUERY within an
 * allowed origin were entirely attacker-chosen, and the `relay_state` this SP
 * stored when it issued the AuthnRequest was collected and never compared.
 *
 * SAML 2.0 Core §3.4.3 requires the IdP to return RelayState EXACTLY as
 * received, so the posted value has no legitimate reason to differ. It is
 * therefore only ever COMPARED; the redirect is built from `stored`.
 *
 * Pure and exported so this decision is testable without an HTTP server.
 */
export type RelayDecision =
  | { kind: 'json' }
  | { kind: 'redirect'; url: URL }
  | { kind: 'reject'; reason: 'relay_state_invalid' | 'relay_state_mismatch' | 'relay_state_origin' };

export function resolveRelayTarget(
  posted: unknown,
  stored: string | null,
  allowedOrigins: readonly string[]
): RelayDecision {
  // `express.urlencoded({ extended: true })` turns a bracketed or repeated field
  // into an array or object. The previous bare `relayState.startsWith('http')`
  // threw a TypeError on those — AFTER the tokens had been minted and the
  // session promoted.
  const parsed = z.string().optional().safeParse(posted);
  if (!parsed.success) return { kind: 'reject', reason: 'relay_state_invalid' };

  const postedValue = parsed.data ?? null;
  if (postedValue !== stored) return { kind: 'reject', reason: 'relay_state_mismatch' };

  if (stored === null || !stored.startsWith('http')) return { kind: 'json' };

  let url: URL;
  try {
    url = new URL(stored);
  } catch {
    return { kind: 'reject', reason: 'relay_state_invalid' };
  }

  const originAllowed = allowedOrigins.some((o) => {
    try {
      return new URL(o).origin === url.origin;
    } catch {
      return false;
    }
  });
  if (!originAllowed) return { kind: 'reject', reason: 'relay_state_origin' };

  return { kind: 'redirect', url };
}

// ============================================================================
// Public SAML endpoints (no authentication required)
// ============================================================================

// SP metadata endpoint (for IdP to consume)
router.get('/saml/metadata/:teamId', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { teamId } = z.object({ teamId: z.string().uuid() }).parse(req.params);
    const config = await getSSOConfig(teamId);
    if (!config || !config.enabled) {
      res.status(404).send('SSO not configured');
      return;
    }

    const metadata = generateSPMetadata(config);
    res.type('application/xml').send(metadata);
  } catch (error) {
    next(error);
  }
});

// Initiate SSO login (SP-initiated flow)
router.get('/saml/login/:teamId', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { teamId: loginTeamId } = z.object({ teamId: z.string().uuid() }).parse(req.params);
    const { returnTo } = z.object({ returnTo: z.string().optional() }).passthrough().parse(req.query);
    const config = await getSSOConfig(loginTeamId);
    if (!config || !config.enabled) {
      res.status(404).json({ error: 'SSO not configured or disabled' });
      return;
    }

    const { redirectUrl } = await initiateSAMLLogin(
      config,
      returnTo,
      req.ip,
      req.get('user-agent')
    );

    res.redirect(redirectUrl);
  } catch (error) {
    next(error);
  }
});

// SAML ACS (Assertion Consumer Service) - receives POST from IdP
router.post('/saml/acs/:configId', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const samlResponse = req.body.SAMLResponse;
    if (!samlResponse) {
      res.status(400).json({ error: 'Missing SAMLResponse' });
      return;
    }

    const { configId } = z.object({ configId: z.string().uuid() }).parse(req.params);
    const { user, tokens, isNewUser, relayState: storedRelayState } = await processSAMLResponse(
      samlResponse,
      configId
    );

    const decision = resolveRelayTarget(req.body.RelayState, storedRelayState, corsOrigins);
    if (decision.kind === 'reject') {
      // Our own literal, never the posted value: RelayState is attacker-authored.
      logger.warn({ configId, reason: decision.reason }, 'SAML ACS RelayState rejected');
      res.status(400).json({ error: 'Invalid RelayState' });
      return;
    }

    if (decision.kind === 'redirect') {
      // Built from the STORED value, and from a parsed URL object rather than
      // raw string manipulation.
      //
      // Residual, deliberately NOT changed here: the access token still travels
      // as a query parameter, so it reaches browser history, the `Referer` of
      // any subsequent request from the landing page, and intermediate proxy
      // logs. Moving it to an HttpOnly cookie or a one-time exchange code is the
      // right fix and is a dashboard-side change, not a route-side one.
      decision.url.searchParams.set('token', tokens.accessToken);
      decision.url.searchParams.set('new', String(isNewUser));
      res.redirect(decision.url.toString());
      return;
    }

    // Otherwise return JSON
    sendSuccess(res, { user, tokens, isNewUser });
  } catch (error) {
    // The service has already logged the structured rejection reason. The route
    // must add nothing attacker-derived: serialising the error here would put
    // library messages carrying attacker values into the log.
    logger.warn(
      { statusCode: error instanceof AppError ? error.statusCode : 500 },
      'SAML ACS rejected'
    );
    next(error);
  }
});

export { router as ssoRoutes };
