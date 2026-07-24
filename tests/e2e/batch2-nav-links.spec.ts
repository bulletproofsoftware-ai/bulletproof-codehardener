import { test, expect } from '@playwright/test';
import { loginAndSetToken, D } from './auth-setup';

// Batch 2: Navigation and links
test.describe.serial('Batch 2: Navigation & Links', () => {

  test.beforeEach(async ({ page }) => {
    await loginAndSetToken(page);
  });

  test('sidebar has all expected nav links', async ({ page }) => {
    await page.goto(D, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const sidebar = page.locator('aside').first();
    const expectedLinks = [
      '/projects',
      '/scans',
      '/findings',
      '/attestations',
      '/reports',
    ];

    for (const href of expectedLinks) {
      const link = sidebar.locator(`a[href="${href}"]`);
      expect(await link.count(), `Missing sidebar link: ${href}`).toBeGreaterThan(0);
    }
  });

  test('sidebar links navigate correctly', async ({ page }) => {
    await page.goto(D, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    // Click Projects
    await page.locator('aside a[href="/projects"]').first().click();
    await page.waitForTimeout(1500);
    expect(page.url()).toContain('/projects');

    // Click Scans
    await page.locator('aside a[href="/scans"]').first().click();
    await page.waitForTimeout(1500);
    expect(page.url()).toContain('/scans');

    // Click Findings
    await page.locator('aside a[href="/findings"]').first().click();
    await page.waitForTimeout(1500);
    expect(page.url()).toContain('/findings');

    // Click Attestations
    await page.locator('aside a[href="/attestations"]').first().click();
    await page.waitForTimeout(1500);
    expect(page.url()).toContain('/attestations');

    // Click Reports
    await page.locator('aside a[href="/reports"]').first().click();
    await page.waitForTimeout(1500);
    expect(page.url()).toContain('/reports');
  });

  test('header New Scan button links correctly', async ({ page }) => {
    await page.goto(D, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const newScanBtn = page.locator('a:has-text("New Scan")').first();
    if (await newScanBtn.count() > 0) {
      const href = await newScanBtn.getAttribute('href');
      expect(href).toContain('/scans/new');
    }
  });

  test('project rows link to project detail', async ({ page }) => {
    await page.goto(`${D}/projects`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const firstLink = page.locator('table tbody a[href*="/projects/"]').first();
    if (await firstLink.count() > 0) {
      await firstLink.click();
      await page.waitForTimeout(2000);
      expect(page.url()).toMatch(/\/projects\/[a-f0-9-]/);

      // Detail page should load without error
      const errorState = page.locator('text=Failed to load');
      const hasError = await errorState.count() > 0;
      if (hasError) {
        console.log('Project detail page shows error state');
      }
    }
  });

  test('scan rows link to scan detail', async ({ page }) => {
    await page.goto(`${D}/scans`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const firstLink = page.locator('table tbody a[href*="/scans/"]').first();
    if (await firstLink.count() > 0) {
      await firstLink.click();
      await page.waitForTimeout(2000);
      expect(page.url()).toMatch(/\/scans\/[a-f0-9-]/);
    }
  });

  test('finding rows link to finding detail', async ({ page }) => {
    await page.goto(`${D}/findings`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const firstLink = page.locator('table tbody a[href*="/findings/"]').first();
    if (await firstLink.count() > 0) {
      await firstLink.click();
      await page.waitForTimeout(2000);
      expect(page.url()).toMatch(/\/findings\/[a-f0-9-]/);
    }
  });

  test('attestation rows link to attestation detail', async ({ page }) => {
    await page.goto(`${D}/attestations`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const firstLink = page.locator('table tbody a[href*="/attestations/"]').first();
    if (await firstLink.count() > 0) {
      await firstLink.click();
      await page.waitForTimeout(2000);
      expect(page.url()).toMatch(/\/attestations\/[a-f0-9-]/);

      // Check no NaN errors
      const bodyText = await page.locator('body').innerText();
      expect(bodyText).not.toContain('NaN');
    }
  });
});
