import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const docsPages = [
  { path: '/docs', name: 'Documentation Home' },
  { path: '/docs/quickstart', name: 'Quickstart Guide' },
  { path: '/docs/api', name: 'API Reference' },
  { path: '/docs/cli', name: 'CLI Reference' },
  { path: '/docs/mcp', name: 'MCP Integration' },
  { path: '/docs/integrations', name: 'Integrations Overview' },
  { path: '/docs/integrations/github-actions', name: 'GitHub Actions' },
  { path: '/docs/integrations/gitlab-ci', name: 'GitLab CI' },
  { path: '/docs/integrations/vscode', name: 'VS Code Extension' },
  { path: '/docs/integrations/cursor', name: 'Cursor Integration' },
];

test.describe('Documentation Portal Accessibility', () => {
  for (const page of docsPages) {
    test(`${page.name} (${page.path}) should have no accessibility violations`, async ({ page: browserPage }) => {
      await browserPage.goto(`http://localhost:3000${page.path}`, { waitUntil: 'domcontentloaded' });

      // Run axe accessibility scan
      const accessibilityScanResults = await new AxeBuilder({ page: browserPage })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
        .analyze();

      // Log any violations for debugging
      if (accessibilityScanResults.violations.length > 0) {
        console.log(`Violations on ${page.path}:`, JSON.stringify(accessibilityScanResults.violations, null, 2));
      }

      expect(accessibilityScanResults.violations).toEqual([]);
    });
  }
});

test.describe('Documentation Portal Structure', () => {
  test('Documentation home should have proper heading hierarchy', async ({ page }) => {
    await page.goto('http://localhost:3000/docs', { waitUntil: 'domcontentloaded' });

    // Check for h1
    const h1 = await page.locator('h1').first();
    await expect(h1).toBeVisible();

    // Check for main landmark
    const main = await page.locator('main, [role="main"]').first();
    await expect(main).toBeVisible();

    // Check for navigation
    const nav = await page.locator('nav, [role="navigation"]').first();
    await expect(nav).toBeVisible();
  });

  test('Documentation navigation should be keyboard accessible', async ({ page }) => {
    await page.goto('http://localhost:3000/docs', { waitUntil: 'domcontentloaded' });

    // Tab through the page and check focus is visible
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100); // Allow focus to settle

    // Check if any element has focus using a different approach
    const hasFocusedElement = await page.locator('a:focus, button:focus, input:focus, [tabindex]:focus').count();
    expect(hasFocusedElement).toBeGreaterThan(0);
  });

  test('Documentation links should have descriptive text', async ({ page }) => {
    await page.goto('http://localhost:3000/docs', { waitUntil: 'domcontentloaded' });

    // Check for links with generic text that should be avoided
    const clickHereLinks = await page.locator('a:text-is("click here")').count();
    const hereLinks = await page.locator('a:text-is("here")').count();

    expect(clickHereLinks).toBe(0);
    expect(hereLinks).toBe(0);
  });

  test('All images should have alt text', async ({ page }) => {
    await page.goto('http://localhost:3000/docs', { waitUntil: 'domcontentloaded' });

    // Find images without alt attribute
    const imagesWithoutAlt = await page.locator('img:not([alt])').count();
    expect(imagesWithoutAlt).toBe(0);
  });

  test('Form inputs should have associated labels', async ({ page }) => {
    await page.goto('http://localhost:3000/docs', { waitUntil: 'domcontentloaded' });

    // Find visible inputs (excluding hidden, submit, button types)
    const inputs = page.locator('input:visible:not([type="hidden"]):not([type="submit"]):not([type="button"])');
    const inputCount = await inputs.count();

    // Each visible input should have a label or aria-label
    for (let i = 0; i < inputCount; i++) {
      const input = inputs.nth(i);
      const hasLabel = await input.getAttribute('aria-label') || await input.getAttribute('aria-labelledby');
      const id = await input.getAttribute('id');

      if (!hasLabel && id) {
        const labelForInput = await page.locator(`label[for="${id}"]`).count();
        expect(labelForInput).toBeGreaterThan(0);
      }
    }
  });
});
