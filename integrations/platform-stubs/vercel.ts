/**
 * Vercel Integration Stub
 *
 * Vercel Marketplace integration that runs Code Hardener scans
 * as part of the deployment pipeline via Vercel Checks API.
 */

export interface VercelIntegrationConfig {
  slug: string;
  name: string;
  description: string;
  checks: Array<{
    name: string;
    path: string;
    blocking: boolean;
  }>;
}

export const vercelConfig: VercelIntegrationConfig = {
  slug: 'codehardener',
  name: 'Code Hardener',
  description: 'Security scanning for Vercel deployments',
  checks: [
    {
      name: 'Security Scan',
      path: '/api/integrations/vercel/check',
      blocking: true,
    },
  ],
};

// Webhook handler for Vercel deployment events
export async function handleVercelWebhook(payload: {
  type: string;
  deployment: { id: string; url: string; meta: { githubRepo?: string } };
  teamId: string;
}): Promise<{ checkId: string }> {
  if (payload.type !== 'deployment.created') {
    return { checkId: '' };
  }

  const apiUrl = process.env.CODEHARDENER_URL || 'https://api.codehardener.com';

  const result = await fetch(`${apiUrl}/api/v1/scans`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.CODEHARDENER_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      repositoryUrl: payload.deployment.meta.githubRepo,
      profile: 'standard',
      triggerType: 'vercel',
      metadata: {
        vercelDeploymentId: payload.deployment.id,
        vercelTeamId: payload.teamId,
      },
    }),
  }).then(r => r.json()) as Record<string, any>;

  return { checkId: result.data?.id || '' };
}
