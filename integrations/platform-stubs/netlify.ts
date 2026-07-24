/**
 * Netlify Build Plugin Stub
 *
 * Runs Code Hardener security scan during Netlify build.
 * Install: npm install netlify-plugin-codehardener
 */

interface NetlifyPluginInputs {
  profile?: string;
  failOn?: string;
  apiKey?: string;
}

interface NetlifyBuildUtils {
  build: { failBuild: (msg: string) => void };
  status: { show: (opts: { summary: string; text: string }) => void };
}

export const onPreBuild = async ({
  inputs,
  utils,
}: {
  inputs: NetlifyPluginInputs;
  utils: NetlifyBuildUtils;
}) => {
  const apiUrl = process.env.CODEHARDENER_URL || 'https://api.codehardener.com';
  const apiKey = inputs.apiKey || process.env.CODEHARDENER_API_KEY;

  if (!apiKey) {
    console.log('CODEHARDENER_API_KEY not set — skipping security scan');
    return;
  }

  const profile = inputs.profile || 'quick';
  const failOn = inputs.failOn || 'critical';

  console.log(`Running Code Hardener ${profile} scan...`);

  try {
    const response = await fetch(`${apiUrl}/api/v1/scans`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        repositoryUrl: process.env.REPOSITORY_URL,
        branch: process.env.BRANCH,
        commitSha: process.env.COMMIT_REF,
        profile,
        triggerType: 'netlify',
      }),
    });

    const result = await response.json() as Record<string, any>;
    const scanId = result.data?.id;

    // Poll for completion
    let score = 0;
    let critical = 0;
    let high = 0;

    for (let i = 0; i < 100; i++) {
      await new Promise(r => setTimeout(r, 3000));
      const status = await fetch(`${apiUrl}/api/v1/scans/${scanId}`, {
        headers: { 'Authorization': `Bearer ${apiKey}` },
      }).then(r => r.json()) as Record<string, any>;

      if (status.data?.status === 'completed') {
        score = status.data.score || 0;
        critical = status.data.findingsSummary?.critical || 0;
        high = status.data.findingsSummary?.high || 0;
        break;
      }
    }

    utils.status.show({
      summary: `Score: ${score}/1000`,
      text: `Critical: ${critical}, High: ${high}`,
    });

    if (failOn === 'critical' && critical > 0) {
      utils.build.failBuild(`Code Hardener: ${critical} critical findings`);
    } else if (failOn === 'high' && (critical + high) > 0) {
      utils.build.failBuild(`Code Hardener: ${critical} critical, ${high} high findings`);
    }
  } catch (error) {
    console.log('Code Hardener scan failed (non-blocking):', error);
  }
};
