import { Page } from '@playwright/test';

// When running inside Docker, use Docker DNS names
const API = process.env.API_URL || 'http://host.docker.internal:4000/api/v1';
const DASHBOARD = process.env.DASHBOARD_URL || 'http://host.docker.internal:3001';
const TEST_USER = {
  email: 'playwright@test.local',
  password: 'PlaywrightTest123',
};

// Cache token across tests to avoid rate limiting
let cachedToken: string | null = null;

async function getToken(page: Page): Promise<string> {
  if (cachedToken) return cachedToken;

  const response = await page.request.post(`${API}/auth/login`, {
    data: TEST_USER,
  });

  const json = await response.json();

  if (!json.success || !json.data?.tokens?.accessToken) {
    throw new Error(`Login failed: ${JSON.stringify(json)}`);
  }

  cachedToken = json.data.tokens.accessToken;
  return cachedToken;
}

export async function loginAndSetToken(page: Page): Promise<void> {
  const token = await getToken(page);

  await page.goto(DASHBOARD, { waitUntil: 'commit' });
  await page.evaluate((t) => {
    localStorage.setItem('auth_token', t);
  }, token);
}

export { DASHBOARD as D };
