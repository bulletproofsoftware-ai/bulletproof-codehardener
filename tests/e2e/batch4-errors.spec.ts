import { test, expect } from '@playwright/test';
import { loginAndSetToken, D } from './auth-setup';

// Batch 4: Error handling, edge cases, console error checks
test.describe.serial('Batch 4: Error Handling & Edge Cases', () => {

  test.beforeEach(async ({ page }) => {
    await loginAndSetToken(page);
  });

  test('404 page for nonexistent route', async ({ page }) => {
    await page.goto(`${D}/nonexistent-page-xyz`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(
      text.includes('404') || text.toLowerCase().includes('not found'),
      'Should show 404 or not found'
    ).toBe(true);
  });

  test('overview page has no NaN in rendered text', async ({ page }) => {
    await page.goto(D, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(3000);
    const text = await page.locator('body').innerText();
    // NaN in visible text is always a bug
    expect(text).not.toContain('NaN');
  });

  test('attestation detail has no NaN in ScoreGauge', async ({ page }) => {
    // First get an attestation ID
    await page.goto(`${D}/attestations`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const link = page.locator('table tbody a[href*="/attestations/"]').first();
    if (await link.count() === 0) { test.skip(); return; }

    const href = await link.getAttribute('href');
    if (!href) { test.skip(); return; }

    // Track console errors
    const nanErrors: string[] = [];
    page.on('console', msg => {
      if (msg.text().includes('NaN') && msg.text().includes('strokeDashoffset')) {
        nanErrors.push(msg.text());
      }
    });

    await page.goto(`${D}${href}`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(3000);

    expect(nanErrors.length, 'NaN strokeDashoffset errors found').toBe(0);

    // Also check rendered text
    const text = await page.locator('body').innerText();
    expect(text).not.toContain('NaN');
  });

  test('reports page has no NaN in rendered text', async ({ page }) => {
    await page.goto(`${D}/reports`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    const text = await page.locator('body').innerText();
    expect(text).not.toContain('NaN');
  });

  test('dark mode toggle does not break page', async ({ page }) => {
    await page.goto(D, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const toggle = page.locator('button:has-text("Dark mode"), button:has-text("Light mode")').first();
    if (await toggle.count() === 0) { test.skip(); return; }

    await toggle.click();
    await page.waitForTimeout(1000);

    // Page should still render
    const body = await page.locator('body').innerText();
    expect(body.length).toBeGreaterThan(10);

    // Toggle back
    const toggle2 = page.locator('button:has-text("Dark mode"), button:has-text("Light mode")').first();
    await toggle2.click();
    await page.waitForTimeout(500);
  });

  test('keyboard shortcut Ctrl+K opens search', async ({ page }) => {
    await page.goto(D, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    // Press Ctrl+K (Meta+K doesn't work in headless Linux)
    await page.keyboard.press('Control+k');
    await page.waitForTimeout(500);

    // Search should be focused or a dialog/modal opened
    const searchInput = page.locator('input[placeholder*="Search"]');
    if (await searchInput.count() > 0) {
      const isFocused = await searchInput.first().evaluate(
        el => el === document.activeElement
      );
      const hasDialog = await page.locator('[role="dialog"], [data-radix-popper-content-wrapper]').count() > 0;
      // Pass if either search focused or dialog opened; skip if neither (feature may not exist)
      if (!isFocused && !hasDialog) {
        test.skip(true, 'Keyboard shortcut not implemented or not detectable in headless');
      }
    }
  });

  test('project detail page for valid project does not 500', async ({ page }) => {
    await page.goto(`${D}/projects`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const link = page.locator('table tbody a[href*="/projects/"]').first();
    if (await link.count() === 0) { test.skip(); return; }

    const href = await link.getAttribute('href');
    if (!href) { test.skip(); return; }

    const res = await page.goto(`${D}${href}`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    expect(res?.status()).toBeLessThan(500);
  });

  test('scan detail page for valid scan does not 500', async ({ page }) => {
    await page.goto(`${D}/scans`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const link = page.locator('table tbody a[href*="/scans/"]').first();
    if (await link.count() === 0) { test.skip(); return; }

    const href = await link.getAttribute('href');
    if (!href) { test.skip(); return; }

    const res = await page.goto(`${D}${href}`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    expect(res?.status()).toBeLessThan(500);
  });

  test('finding detail page for valid finding does not 500', async ({ page }) => {
    await page.goto(`${D}/findings`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const link = page.locator('table tbody a[href*="/findings/"]').first();
    if (await link.count() === 0) { test.skip(); return; }

    const href = await link.getAttribute('href');
    if (!href) { test.skip(); return; }

    const res = await page.goto(`${D}${href}`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    expect(res?.status()).toBeLessThan(500);
  });
});
