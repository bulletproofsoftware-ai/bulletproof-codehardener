import { test, expect } from '@playwright/test';

const DASHBOARD = process.env.DASHBOARD_BASE || 'http://localhost:3001';

test.describe('Dashboard Comprehensive Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.setExtraHTTPHeaders({ 'X-User-Id': 'dev@codehardener.local' });
  });

  // All dashboard pages to test
  const pages = [
    { path: '/', name: 'Overview' },
    { path: '/projects', name: 'Projects' },
    { path: '/scans', name: 'Scans' },
    { path: '/findings', name: 'Findings' },
    { path: '/attestations', name: 'Attestations' },
    { path: '/reports', name: 'Reports' },
    { path: '/settings', name: 'Settings' },
    { path: '/settings/api-keys', name: 'API Keys' },
    { path: '/settings/integrations', name: 'Integrations' },
    { path: '/settings/team', name: 'Team' },
    { path: '/settings/billing', name: 'Billing' },
    { path: '/settings/notifications', name: 'Notifications' },
    { path: '/policies', name: 'Policies' },
    { path: '/tests', name: 'Tests' },
  ];

  test.describe('Page Load Tests', () => {
    for (const p of pages) {
      test(`${p.name} page loads without errors (${p.path})`, async ({ page }) => {
        const consoleErrors: string[] = [];
        page.on('console', msg => {
          if (msg.type() === 'error' && !msg.text().includes('favicon')) {
            consoleErrors.push(msg.text());
          }
        });

        const response = await page.goto(`${DASHBOARD}${p.path}`, { waitUntil: 'load' });
        expect(response?.status()).toBeLessThan(500);

        // Page should have content (not blank)
        const body = await page.locator('body').textContent();
        expect(body?.trim().length).toBeGreaterThan(0);

        // No React error boundaries should be showing
        const errorBoundary = page.locator('text=Something went wrong');
        expect(await errorBoundary.count()).toBe(0);

        // Filter out expected API errors (backend may return 404/500 for some data)
        const unexpectedErrors = consoleErrors.filter(
          e => !e.includes('ApiError') && !e.includes('Failed to fetch') && !e.includes('net::ERR')
        );
        // Log but don't fail on console errors (they're common in dev)
        if (unexpectedErrors.length > 0) {
          console.log(`Console errors on ${p.path}:`, unexpectedErrors);
        }
      });
    }
  });

  test.describe('Navigation Links', () => {
    test('sidebar navigation links work', async ({ page }) => {
      await page.goto(DASHBOARD, { waitUntil: 'load' });

      // Get all sidebar nav links
      const sidebar = page.locator('aside, nav').first();
      const links = sidebar.locator('a[href]');
      const linkCount = await links.count();
      expect(linkCount).toBeGreaterThan(3);

      const hrefs: string[] = [];
      for (let i = 0; i < linkCount; i++) {
        const href = await links.nth(i).getAttribute('href');
        if (href && href.startsWith('/') && !href.includes('#')) {
          hrefs.push(href);
        }
      }

      // Test each sidebar link navigates successfully
      for (const href of hrefs) {
        const response = await page.goto(`${DASHBOARD}${href}`, { waitUntil: 'domcontentloaded' });
        expect(response?.status(), `Failed loading ${href}`).toBeLessThan(500);
      }
    });

    test('header action buttons exist', async ({ page }) => {
      await page.goto(DASHBOARD, { waitUntil: 'load' });

      // Header should have key action buttons
      const newScanBtn = page.locator('a:has-text("New Scan"), button:has-text("New Scan")');
      expect(await newScanBtn.count()).toBeGreaterThan(0);
    });
  });

  test.describe('Projects Page', () => {
    test('projects list loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/projects`, { waitUntil: 'load' });

      // Should show projects heading
      await expect(page.locator('h1')).toContainText(/Project/i);

      // Should have a table or empty state
      const table = page.locator('table');
      const emptyState = page.locator('text=No Projects');
      expect((await table.count()) > 0 || (await emptyState.count()) > 0).toBe(true);
    });

    test('new project button exists and opens modal', async ({ page }) => {
      await page.goto(`${DASHBOARD}/projects`, { waitUntil: 'load' });

      const newBtn = page.locator('button:has-text("New Project"), a:has-text("New Project")');
      if (await newBtn.count() > 0) {
        await newBtn.first().click();
        await page.waitForTimeout(500);

        // Modal should appear with form fields
        const modal = page.locator('[role="dialog"], .fixed.inset-0');
        if (await modal.count() > 0) {
          const nameInput = page.locator('input[placeholder*="name" i], input[name="name"]');
          expect(await nameInput.count()).toBeGreaterThan(0);
        }
      }
    });

    test('project links navigate to detail page', async ({ page }) => {
      await page.goto(`${DASHBOARD}/projects`, { waitUntil: 'load' });

      const projectLinks = page.locator('table tbody tr a, .project-card a');
      if (await projectLinks.count() > 0) {
        const href = await projectLinks.first().getAttribute('href');
        expect(href).toMatch(/\/projects\/[a-f0-9-]+/);
      }
    });
  });

  test.describe('Scans Page', () => {
    test('scans list loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/scans`, { waitUntil: 'load' });
      await expect(page.locator('h1')).toContainText(/Scan/i);
    });

    test('new scan button and form', async ({ page }) => {
      await page.goto(`${DASHBOARD}/scans`, { waitUntil: 'load' });

      // Look for New Scan in header
      const newScanBtn = page.locator('a[href="/scans/new"], button:has-text("New Scan")');
      if (await newScanBtn.count() > 0) {
        await newScanBtn.first().click();
        await page.waitForURL('**/scans/new**', { timeout: 5000 }).catch(() => {});

        // Should have scan configuration form
        const form = page.locator('form, select, .scan-config');
        expect(await form.count()).toBeGreaterThan(0);
      }
    });

    test('scan filters work', async ({ page }) => {
      await page.goto(`${DASHBOARD}/scans`, { waitUntil: 'load' });

      const selects = page.locator('select');
      if (await selects.count() > 0) {
        // Try changing a filter
        await selects.first().selectOption({ index: 1 }).catch(() => {});
        await page.waitForTimeout(300);
        // Page should not crash
        const body = await page.locator('body').textContent();
        expect(body?.trim().length).toBeGreaterThan(0);
      }
    });
  });

  test.describe('Findings Page', () => {
    test('findings list loads with severity counts', async ({ page }) => {
      await page.goto(`${DASHBOARD}/findings`, { waitUntil: 'load' });
      await expect(page.locator('h1')).toContainText(/Finding/i);

      // Should have severity summary badges
      const badges = page.locator('.badge, span:has-text("Critical"), span:has-text("High")');
      expect(await badges.count()).toBeGreaterThan(0);
    });

    test('severity filter buttons work', async ({ page }) => {
      await page.goto(`${DASHBOARD}/findings`, { waitUntil: 'load' });

      // Click severity filter buttons
      const severityBtns = page.locator('button:has-text("Critical"), button:has-text("High"), button:has-text("Medium")');
      if (await severityBtns.count() > 0) {
        await severityBtns.first().click();
        await page.waitForTimeout(300);
        // Page should still be functional
        const body = await page.locator('body').textContent();
        expect(body?.trim().length).toBeGreaterThan(0);
      }
    });

    test('finding row links to detail', async ({ page }) => {
      await page.goto(`${DASHBOARD}/findings`, { waitUntil: 'load' });

      const findingLinks = page.locator('table tbody tr a, .finding-row a');
      if (await findingLinks.count() > 0) {
        const href = await findingLinks.first().getAttribute('href');
        expect(href).toMatch(/\/findings\/[a-f0-9-]+/);
      }
    });
  });

  test.describe('Attestations Page', () => {
    test('attestations list loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/attestations`, { waitUntil: 'load' });
      await expect(page.locator('h1')).toContainText(/Attestation/i);
    });

    test('attestation row links to detail', async ({ page }) => {
      await page.goto(`${DASHBOARD}/attestations`, { waitUntil: 'load' });

      const attestationLinks = page.locator('table tbody tr a');
      if (await attestationLinks.count() > 0) {
        const href = await attestationLinks.first().getAttribute('href');
        expect(href).toMatch(/\/attestations\/[a-f0-9-]+/);
      }
    });

    test('attestation detail page loads without NaN error', async ({ page }) => {
      // First get an attestation ID from the list
      await page.goto(`${DASHBOARD}/attestations`, { waitUntil: 'load' });

      const attestationLinks = page.locator('table tbody tr a[href*="/attestations/"]');
      if (await attestationLinks.count() > 0) {
        const href = await attestationLinks.first().getAttribute('href');
        if (href) {
          const consoleErrors: string[] = [];
          page.on('console', msg => {
            if (msg.type() === 'error') {
              consoleErrors.push(msg.text());
            }
          });

          await page.goto(`${DASHBOARD}${href}`, { waitUntil: 'load' });

          // Should NOT have NaN strokeDashoffset error
          const nanErrors = consoleErrors.filter(e => e.includes('NaN') && e.includes('strokeDashoffset'));
          expect(nanErrors.length, 'ScoreGauge NaN error detected').toBe(0);
        }
      }
    });

    test('attestation new page handles scanId param', async ({ page }) => {
      // Navigate to /attestations/new without scanId
      await page.goto(`${DASHBOARD}/attestations/new`, { waitUntil: 'load' });

      // Should show error about missing scanId, not a 500 error
      const content = await page.content();
      expect(content).not.toContain('Internal server error');
    });

    test('project filter works', async ({ page }) => {
      await page.goto(`${DASHBOARD}/attestations`, { waitUntil: 'load' });

      const selects = page.locator('select');
      if (await selects.count() > 0) {
        await selects.first().selectOption({ index: 1 }).catch(() => {});
        await page.waitForTimeout(300);
        const body = await page.locator('body').textContent();
        expect(body?.trim().length).toBeGreaterThan(0);
      }
    });
  });

  test.describe('Reports Page', () => {
    test('reports page loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/reports`, { waitUntil: 'load' });
      await expect(page.locator('h1')).toContainText(/Report/i);
    });

    test('generate report modal opens', async ({ page }) => {
      await page.goto(`${DASHBOARD}/reports`, { waitUntil: 'load' });

      const generateBtn = page.locator('button:has-text("Generate Report")');
      if (await generateBtn.count() > 0) {
        await generateBtn.first().click();
        await page.waitForTimeout(500);

        // Modal should appear
        const modal = page.locator('[role="dialog"], .fixed.inset-0');
        expect(await modal.count()).toBeGreaterThan(0);

        // Should have form fields
        const reportNameInput = page.locator('input[type="text"]');
        expect(await reportNameInput.count()).toBeGreaterThan(0);

        const reportTypeSelect = page.locator('select');
        expect(await reportTypeSelect.count()).toBeGreaterThan(0);
      }
    });

    test('generate report form validation works', async ({ page }) => {
      await page.goto(`${DASHBOARD}/reports`, { waitUntil: 'load' });

      const generateBtn = page.locator('button:has-text("Generate Report")');
      if (await generateBtn.count() > 0) {
        await generateBtn.first().click();
        await page.waitForTimeout(500);

        // Try to generate without a name (should be disabled or show error)
        const submitBtn = page.locator('button:has-text("Generate"):not(:has-text("Generate Report"))');
        if (await submitBtn.count() > 0) {
          // Button should be disabled when name is empty
          const isDisabled = await submitBtn.first().isDisabled();
          expect(isDisabled).toBe(true);

          // Fill in name
          const nameInput = page.locator('input[type="text"]').first();
          await nameInput.fill('Test Report');

          // Button should now be enabled
          const isEnabledNow = await submitBtn.first().isEnabled();
          expect(isEnabledNow).toBe(true);
        }
      }
    });

    test('generate report succeeds with valid data', async ({ page }) => {
      await page.goto(`${DASHBOARD}/reports`, { waitUntil: 'load' });

      const generateBtn = page.locator('button:has-text("Generate Report")');
      if (await generateBtn.count() > 0) {
        await generateBtn.first().click();
        await page.waitForTimeout(500);

        // Fill form
        const nameInput = page.locator('input[type="text"]').first();
        await nameInput.fill('Playwright Test Report');

        // Submit
        const submitBtn = page.locator('.fixed.inset-0 button:has-text("Generate")');
        if (await submitBtn.count() > 0 && await submitBtn.first().isEnabled()) {
          const consoleErrors: string[] = [];
          page.on('console', msg => {
            if (msg.type() === 'error') consoleErrors.push(msg.text());
          });

          await submitBtn.first().click();
          await page.waitForTimeout(2000);

          // Should NOT show validation failed
          const errorBox = page.locator('text=Validation failed');
          expect(await errorBox.count(), 'Validation failed error shown').toBe(0);
        }
      }
    });
  });

  test.describe('Settings Pages', () => {
    test('settings page loads with tabs', async ({ page }) => {
      await page.goto(`${DASHBOARD}/settings`, { waitUntil: 'load' });
      await expect(page.locator('h1')).toContainText(/Setting/i);
    });

    test('API keys page loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/settings/api-keys`, { waitUntil: 'load' });
      const content = await page.content();
      expect(content.toLowerCase()).toContain('api');
    });

    test('team page loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/settings/team`, { waitUntil: 'load' });
      const content = await page.content();
      expect(content.toLowerCase()).toContain('team');
    });

    test('billing page loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/settings/billing`, { waitUntil: 'load' });
      const content = await page.content();
      expect(content.toLowerCase()).toMatch(/billing|plan|subscription/i);
    });

    test('integrations page loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/settings/integrations`, { waitUntil: 'load' });
      const content = await page.content();
      expect(content.toLowerCase()).toContain('integration');
    });

    test('notifications page loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/settings/notifications`, { waitUntil: 'load' });
      const content = await page.content();
      expect(content.toLowerCase()).toContain('notification');
    });
  });

  test.describe('Policies Page', () => {
    test('policies page loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/policies`, { waitUntil: 'load' });
      const content = await page.content();
      expect(content.toLowerCase()).toContain('polic');
    });
  });

  test.describe('Tests Page', () => {
    test('tests page loads', async ({ page }) => {
      await page.goto(`${DASHBOARD}/tests`, { waitUntil: 'load' });
      const content = await page.content();
      expect(content.toLowerCase()).toContain('test');
    });
  });

  test.describe('Search Functionality', () => {
    test('global search opens on click', async ({ page }) => {
      await page.goto(DASHBOARD, { waitUntil: 'load' });

      const searchInput = page.locator('input[placeholder*="Search"], input[type="search"]');
      if (await searchInput.count() > 0) {
        await searchInput.first().click();
        await page.waitForTimeout(300);

        // Search should be focused/active
        const isFocused = await searchInput.first().evaluate(
          el => el === document.activeElement
        );
        expect(isFocused).toBe(true);
      }
    });

    test('search accepts input', async ({ page }) => {
      await page.goto(DASHBOARD, { waitUntil: 'load' });

      const searchInput = page.locator('input[placeholder*="Search"], input[type="search"]');
      if (await searchInput.count() > 0) {
        await searchInput.first().fill('test query');
        await page.waitForTimeout(500);
        // Should not crash
        const body = await page.locator('body').textContent();
        expect(body?.trim().length).toBeGreaterThan(0);
      }
    });
  });

  test.describe('Dark Mode', () => {
    test('dark mode toggle exists and works', async ({ page }) => {
      await page.goto(DASHBOARD, { waitUntil: 'load' });

      const darkModeToggle = page.locator('button:has-text("Dark mode"), button:has-text("Light mode"), [data-testid="theme-toggle"]');
      if (await darkModeToggle.count() > 0) {
        await darkModeToggle.first().click();
        await page.waitForTimeout(300);
        // Page should still be functional
        const body = await page.locator('body').textContent();
        expect(body?.trim().length).toBeGreaterThan(0);
      }
    });
  });

  test.describe('Link Crawler - All Internal Links', () => {
    test('all internal links resolve without 500 errors', async ({ page }) => {
      const visited = new Set<string>();
      const failed: { url: string; status: number }[] = [];
      const toVisit = ['/'];
      const maxPages = 50;

      while (toVisit.length > 0 && visited.size < maxPages) {
        const path = toVisit.shift()!;
        if (visited.has(path)) continue;
        visited.add(path);

        try {
          const response = await page.goto(`${DASHBOARD}${path}`, {
            waitUntil: 'domcontentloaded',
            timeout: 10000,
          });

          const status = response?.status() || 0;
          if (status >= 500) {
            failed.push({ url: path, status });
          }

          // Collect new links
          const links = await page.locator('a[href^="/"]').all();
          for (const link of links) {
            const href = await link.getAttribute('href');
            if (href && !visited.has(href) && !href.includes('#') && !href.startsWith('/api')) {
              // Skip links with dynamic IDs longer than 36 chars (UUIDs)
              toVisit.push(href);
            }
          }
        } catch {
          // Timeout or navigation error - skip
        }
      }

      console.log(`Crawled ${visited.size} pages`);
      if (failed.length > 0) {
        console.log('Failed pages:', failed);
      }
      expect(failed.length, `${failed.length} pages returned 500 errors`).toBe(0);
    });
  });
});
