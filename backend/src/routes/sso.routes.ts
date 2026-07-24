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
import { corsOrigins } from '../config/env.js';

const logger = createLogger('sso-routes');
const router = Router();

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
    const { user, tokens, isNewUser } = await processSAMLResponse(
      samlResponse,
      configId
    );

    const relayState = req.body.RelayState;

    // If relay state has a frontend URL, redirect with token (validate origin to prevent open redirect)
    if (relayState && relayState.startsWith('http')) {
      const allowedOrigins = corsOrigins;
      let redirectUrl: URL;
      try {
        redirectUrl = new URL(relayState);
      } catch {
        res.status(400).json({ error: 'Invalid RelayState URL' });
        return;
      }
      const originAllowed = allowedOrigins.some(o => {
        try { return new URL(o).origin === redirectUrl.origin; } catch { return false; }
      });
      if (!originAllowed) {
        res.status(400).json({ error: 'Redirect URL not in allowed origins' });
        return;
      }
      // Use the validated URL object to construct the redirect (prevents open-redirect via raw string manipulation)
      redirectUrl.searchParams.set('token', tokens.accessToken);
      redirectUrl.searchParams.set('new', String(isNewUser));
      res.redirect(redirectUrl.toString());
      return;
    }

    // Otherwise return JSON
    sendSuccess(res, { user, tokens, isNewUser });
  } catch (error) {
    logger.error({ error }, 'SAML ACS error');
    next(error);
  }
});

export { router as ssoRoutes };
