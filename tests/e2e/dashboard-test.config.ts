import { defineConfig } from '@playwright/test';

const baseURL = process.env.DASHBOARD_URL || 'http://host.docker.internal:3001';

export default defineConfig({
  testDir: '.',
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: 'list',
  timeout: 30000,
  use: {
    baseURL,
    trace: 'off',
    screenshot: 'only-on-failure',
    headless: true,
    launchOptions: {
      executablePath: process.env.CHROME_PATH || undefined,
      args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
    },
  },
});
