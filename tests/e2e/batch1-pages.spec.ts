import { test, expect } from '@playwright/test';
import { loginAndSetToken, D } from './auth-setup';

// Batch 1: Core page loads
test.describe.serial('Batch 1: Page Loads', () => {

  test.beforeEach(async ({ page }) => {
    await loginAndSetToken(page);
  });

  test('Overview /', async ({ page }) => {
    await page.goto(D, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(text.length).toBeGreaterThan(10);
    // Should NOT show "Authorization header required"
    expect(text).not.toContain('Authorization header required');
  });

  test('Projects /projects', async ({ page }) => {
    await page.goto(`${D}/projects`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(text).not.toContain('Authorization header required');
  });

  test('Scans /scans', async ({ page }) => {
    await page.goto(`${D}/scans`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(text).not.toContain('Authorization header required');
  });

  test('Findings /findings', async ({ page }) => {
    await page.goto(`${D}/findings`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(text).not.toContain('Authorization header required');
  });

  test('Attestations /attestations', async ({ page }) => {
    await page.goto(`${D}/attestations`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(text).not.toContain('Authorization header required');
  });

  test('Reports /reports', async ({ page }) => {
    await page.goto(`${D}/reports`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(text).not.toContain('Authorization header required');
  });

  test('Policies /policies', async ({ page }) => {
    await page.goto(`${D}/policies`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(text.toLowerCase()).toContain('polic');
  });

  test('Tests /tests', async ({ page }) => {
    await page.goto(`${D}/tests`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(text.toLowerCase()).toContain('test');
  });

  test('Settings /settings', async ({ page }) => {
    await page.goto(`${D}/settings`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(text.toLowerCase()).toContain('setting');
  });

  test('API Keys /settings/api-keys', async ({ page }) => {
    const res = await page.goto(`${D}/settings/api-keys`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    expect(res?.status()).toBeLessThan(500);
  });

  test('Integrations /settings/integrations', async ({ page }) => {
    const res = await page.goto(`${D}/settings/integrations`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    expect(res?.status()).toBeLessThan(500);
  });

  test('Team /settings/team', async ({ page }) => {
    const res = await page.goto(`${D}/settings/team`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    expect(res?.status()).toBeLessThan(500);
  });

  test('Billing /settings/billing', async ({ page }) => {
    const res = await page.goto(`${D}/settings/billing`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    expect(res?.status()).toBeLessThan(500);
  });

  test('Notifications /settings/notifications', async ({ page }) => {
    const res = await page.goto(`${D}/settings/notifications`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    expect(res?.status()).toBeLessThan(500);
  });
});
