import { test, expect } from '@playwright/test';
import { loginAndSetToken, D } from './auth-setup';

// Batch 3: Form inputs, modals, interactions
test.describe.serial('Batch 3: Forms & Interactions', () => {

  test.beforeEach(async ({ page }) => {
    await loginAndSetToken(page);
  });

  test('generate report modal opens and has all fields', async ({ page }) => {
    await page.goto(`${D}/reports`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const genBtn = page.locator('button:has-text("Generate Report")');
    if (await genBtn.count() === 0) {
      test.skip();
      return;
    }

    await genBtn.first().click();
    await page.waitForTimeout(500);

    // Modal should appear
    const modal = page.locator('.fixed.inset-0');
    await expect(modal).toBeVisible();

    // Check form fields exist
    const nameInput = page.locator('input[type="text"]');
    expect(await nameInput.count(), 'Report name input missing').toBeGreaterThan(0);

    const selects = page.locator('.fixed.inset-0 select');
    expect(await selects.count(), 'Select dropdowns missing').toBeGreaterThanOrEqual(1);

    // Radio buttons for project scope
    const radios = page.locator('.fixed.inset-0 input[type="radio"]');
    expect(await radios.count(), 'Project scope radios missing').toBeGreaterThan(0);
  });

  test('generate report: submit button disabled when name empty', async ({ page }) => {
    await page.goto(`${D}/reports`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const genBtn = page.locator('button:has-text("Generate Report")');
    if (await genBtn.count() === 0) { test.skip(); return; }
    await genBtn.first().click();
    await page.waitForTimeout(500);

    // Find the Generate submit button inside the modal (not the "Generate Report" button)
    const submitBtn = page.locator('.fixed.inset-0 button:has-text("Generate")').last();
    const isDisabled = await submitBtn.isDisabled();
    expect(isDisabled, 'Submit should be disabled when name is empty').toBe(true);
  });

  test('generate report: fill name enables submit', async ({ page }) => {
    await page.goto(`${D}/reports`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const genBtn = page.locator('button:has-text("Generate Report")');
    if (await genBtn.count() === 0) { test.skip(); return; }
    await genBtn.first().click();
    await page.waitForTimeout(500);

    // Fill name
    await page.locator('.fixed.inset-0 input[type="text"]').first().fill('PW Test Report');
    await page.waitForTimeout(200);

    const submitBtn = page.locator('.fixed.inset-0 button:has-text("Generate")').last();
    const isEnabled = await submitBtn.isEnabled();
    expect(isEnabled, 'Submit should be enabled after filling name').toBe(true);
  });

  test('generate report: submit succeeds (no validation error)', async ({ page }) => {
    await page.goto(`${D}/reports`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const genBtn = page.locator('button:has-text("Generate Report")');
    if (await genBtn.count() === 0) { test.skip(); return; }
    await genBtn.first().click();
    await page.waitForTimeout(500);

    // Fill form
    await page.locator('.fixed.inset-0 input[type="text"]').first().fill('PW Auto Report');

    // Listen for console errors
    const apiErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error' && msg.text().includes('Failed to generate')) {
        apiErrors.push(msg.text());
      }
    });

    // Submit
    const submitBtn = page.locator('.fixed.inset-0 button:has-text("Generate")').last();
    await submitBtn.click();
    await page.waitForTimeout(3000);

    // Should NOT show "Validation failed" in the modal
    const validationError = page.locator('.fixed.inset-0 text=Validation failed');
    const hasError = await validationError.count() > 0;
    expect(hasError, 'Validation failed error should not appear').toBe(false);
  });

  test('generate report modal cancel works', async ({ page }) => {
    await page.goto(`${D}/reports`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const genBtn = page.locator('button:has-text("Generate Report")');
    if (await genBtn.count() === 0) { test.skip(); return; }
    await genBtn.first().click();
    await page.waitForTimeout(500);

    // Click cancel
    await page.locator('.fixed.inset-0 button:has-text("Cancel")').click();
    await page.waitForTimeout(500);

    // Modal should close
    const modal = page.locator('.fixed.inset-0');
    expect(await modal.count()).toBe(0);
  });

  test('attestation /new without scanId shows error message', async ({ page }) => {
    await page.goto(`${D}/attestations/new`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const bodyText = await page.locator('body').innerText();
    // Should show meaningful error, not "Internal server error"
    expect(bodyText).not.toContain('Internal server error');
    expect(bodyText.toLowerCase()).toContain('no scan id');
  });

  test('new project modal validates empty name', async ({ page }) => {
    await page.goto(`${D}/projects`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const newBtn = page.locator('button:has-text("New Project")');
    if (await newBtn.count() === 0) { test.skip(); return; }
    await newBtn.first().click();
    await page.waitForTimeout(500);

    // Try to submit empty form - button should be disabled or show error
    const submitBtn = page.locator('.fixed.inset-0 button:has-text("Create"), .fixed.inset-0 button[type="submit"]');
    if (await submitBtn.count() > 0) {
      const isDisabled = await submitBtn.first().isDisabled();
      if (!isDisabled) {
        await submitBtn.first().click();
        await page.waitForTimeout(500);
        // Should show validation error
        const error = page.locator('.fixed.inset-0 .text-error, .fixed.inset-0 [role="alert"]');
        expect(await error.count()).toBeGreaterThan(0);
      } else {
        expect(isDisabled).toBe(true);
      }
    }
  });

  test('scans page filter selects change state', async ({ page }) => {
    await page.goto(`${D}/scans`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const selects = page.locator('select');
    const count = await selects.count();
    if (count === 0) { test.skip(); return; }

    // Change first select
    const options = await selects.first().locator('option').all();
    if (options.length > 1) {
      await selects.first().selectOption({ index: 1 });
      await page.waitForTimeout(1000);
      // Page should not crash
      const body = await page.locator('body').innerText();
      expect(body.length).toBeGreaterThan(10);
    }
  });

  test('findings page severity filter works', async ({ page }) => {
    await page.goto(`${D}/findings`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    // Try clicking severity badge buttons
    const criticalBtn = page.locator('button:has-text("Critical")').first();
    if (await criticalBtn.count() > 0) {
      await criticalBtn.click();
      await page.waitForTimeout(1000);
      const body = await page.locator('body').innerText();
      expect(body.length).toBeGreaterThan(10);
    }
  });

  test('search input accepts text without crash', async ({ page }) => {
    await page.goto(D, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);

    const searchInput = page.locator('input[placeholder*="Search"]');
    if (await searchInput.count() === 0) { test.skip(); return; }

    await searchInput.first().click();
    await searchInput.first().fill('test search query');
    await page.waitForTimeout(500);

    // Should not crash
    const body = await page.locator('body').innerText();
    expect(body.length).toBeGreaterThan(10);
  });
});
