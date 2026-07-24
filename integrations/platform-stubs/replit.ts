/**
 * Replit Integration Stub
 *
 * Replit extension that adds a "Security Scan" button to the workspace.
 * Uses Replit Extensions API to register a tool pane.
 */

export interface ReplitExtensionConfig {
  name: string;
  description: string;
  icon: string;
  commands: Array<{
    id: string;
    label: string;
    action: string;
  }>;
}

export const replitExtension: ReplitExtensionConfig = {
  name: 'Code Hardener',
  description: 'Security scanning for your Replit projects',
  icon: 'shield-check',
  commands: [
    {
      id: 'codehardener.scan',
      label: 'Run Security Scan',
      action: 'scan',
    },
    {
      id: 'codehardener.findings',
      label: 'View Findings',
      action: 'findings',
    },
    {
      id: 'codehardener.score',
      label: 'Security Score',
      action: 'score',
    },
  ],
};

// Entry point for Replit extension
export async function handleReplitAction(
  action: string,
  context: { replId: string; language: string; apiKey: string }
): Promise<unknown> {
  const apiUrl = process.env.CODEHARDENER_URL || 'https://api.codehardener.com';

  switch (action) {
    case 'scan':
      return fetch(`${apiUrl}/api/v1/scans`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${context.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repositoryUrl: `replit://${context.replId}`,
          profile: 'auto',
          triggerType: 'replit',
        }),
      }).then(r => r.json());

    default:
      return { error: `Unknown action: ${action}` };
  }
}
