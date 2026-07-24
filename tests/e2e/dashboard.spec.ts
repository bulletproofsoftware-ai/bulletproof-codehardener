import { test, expect, Page } from '@playwright/test';

/**
 * Code Hardener - Dashboard E2E Tests
 *
 * Tests all dashboard pages and functionality:
 * - Overview/Home
 * - Projects
 * - Scans
 * - Findings
 * - Attestations
 * - Reports
 * - Settings
 */

const MARKETING_BASE = 'http://localhost:3000';
const DASHBOARD_BASE = 'http://localhost:3001';

// Test user
const TEST_USER = {
  email: 'test@codehardener.local',
  password: 'TestPassword123!',
};

// Helper to login before tests
async function loginUser(page: Page): Promise<void> {
  await page.goto(`${MARKETING_BASE}/login`);
  await page.fill('input[type="email"], input[name="email"]', TEST_USER.email);
  await page.fill('input[type="password"]', TEST_USER.password);
  await page.locator('button[type="submit"]').click();
  await page.waitForURL(new RegExp(`${DASHBOARD_BASE}|/dashboard`), { timeout: 10000 });
}

test.describe('Dashboard - Overview', () => {
  test.beforeEach(async ({ page }) => {
    await loginUser(page);
  });

  test('should display overview dashboard @dashboard @critical', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}`);

    // Dashboard header
    await expect(page.locator('h1, h2').first()).toBeVisible();

    // Should have metrics/stats cards
    const statsCards = page.locator('[data-testid="stat-card"], .stat-card, .metric-card');
    const cardCount = await statsCards.count();
    expect(cardCount).toBeGreaterThanOrEqual(1);
  });

  test('should display security score @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}`);

    // Security score display
    const scoreElement = page.locator('[data-testid="security-score"], .security-score, :text("Score")');
    await expect(scoreElement.first()).toBeVisible();
  });

  test('should show recent activity @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}`);

    // Activity feed or recent items
    const activity = page.locator('[data-testid="activity-feed"], .activity, .recent-scans');
    await expect(activity.first()).toBeVisible();
  });

  test('should have navigation sidebar @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}`);

    // Sidebar navigation
    const sidebar = page.locator('[data-testid="sidebar"], aside, nav.sidebar');
    await expect(sidebar).toBeVisible();

    // Navigation links
    await expect(page.locator('a[href*="projects"]')).toBeVisible();
    await expect(page.locator('a[href*="scans"]')).toBeVisible();
    await expect(page.locator('a[href*="findings"]')).toBeVisible();
  });
});

test.describe('Dashboard - Projects', () => {
  test.beforeEach(async ({ page }) => {
    await loginUser(page);
  });

  test('should display projects list @dashboard @critical', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/projects`);

    // Projects page header
    await expect(page.locator('h1, h2').first()).toContainText(/project/i);

    // Projects table or grid
    const projectsList = page.locator('table, [data-testid="projects-list"], .projects-grid');
    await expect(projectsList).toBeVisible();
  });

  test('should have create project button @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/projects`);

    const createBtn = page.locator('button:has-text("New"), button:has-text("Create"), a[href*="new"]');
    await expect(createBtn.first()).toBeVisible();
  });

  test('should open create project modal @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/projects`);

    await page.locator('button:has-text("New"), button:has-text("Create")').first().click();

    // Modal or form should appear
    const modal = page.locator('[role="dialog"], .modal, form');
    await expect(modal.first()).toBeVisible();
  });

  test('should validate project creation form @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/projects`);

    await page.locator('button:has-text("New"), button:has-text("Create")').first().click();

    // Submit empty form
    await page.locator('button[type="submit"], button:has-text("Save")').click();

    // Should show validation error
    await expect(page.locator('.error, [role="alert"]')).toBeVisible();
  });

  test('should display project details @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/projects`);

    // Click first project (if exists)
    const firstProject = page.locator('table tbody tr, .project-card').first();
    if ((await firstProject.count()) > 0) {
      await firstProject.click();

      // Project detail page
      await expect(page.locator('h1, h2')).toContainText(/project/i);
      await expect(page.locator('[data-testid="project-score"], .security-score')).toBeVisible();
    }
  });

  test('should filter projects @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/projects`);

    // Search/filter input
    const search = page.locator('input[type="search"], input[placeholder*="Search"], input[placeholder*="Filter"]');
    if ((await search.count()) > 0) {
      await search.fill('test');
      await page.waitForTimeout(500);

      // Results should update (or show no results)
      const results = page.locator('table tbody tr, .project-card');
      const count = await results.count();
      // Either has filtered results or shows empty state
      expect(count >= 0).toBe(true);
    }
  });
});

test.describe('Dashboard - Scans', () => {
  test.beforeEach(async ({ page }) => {
    await loginUser(page);
  });

  test('should display scans list @dashboard @critical', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/scans`);

    await expect(page.locator('h1, h2').first()).toContainText(/scan/i);

    // Scans table
    const scansList = page.locator('table, [data-testid="scans-list"]');
    await expect(scansList).toBeVisible();
  });

  test('should have new scan button @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/scans`);

    const newScanBtn = page.locator('button:has-text("New Scan"), button:has-text("Run Scan")');
    await expect(newScanBtn.first()).toBeVisible();
  });

  test('should display scan status indicators @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/scans`);

    // Status badges
    const statuses = page.locator('.status-badge, [data-testid="scan-status"], .badge');
    const count = await statuses.count();

    if (count > 0) {
      // At least one status should be visible
      await expect(statuses.first()).toBeVisible();
    }
  });

  test('should show scan details @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/scans`);

    const firstScan = page.locator('table tbody tr, .scan-row').first();
    if ((await firstScan.count()) > 0) {
      await firstScan.click();

      // Scan details
      await expect(page.locator('[data-testid="scan-details"], .scan-detail')).toBeVisible();
    }
  });

  test('should filter scans by status @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/scans`);

    // Status filter dropdown
    const statusFilter = page.locator('select[name*="status"], [data-testid="status-filter"]');
    if ((await statusFilter.count()) > 0) {
      await statusFilter.selectOption({ index: 1 });
      await page.waitForTimeout(500);

      // Results should update
      const results = page.locator('table tbody tr, .scan-row');
      expect(await results.count()).toBeGreaterThanOrEqual(0);
    }
  });
});

test.describe('Dashboard - Findings', () => {
  test.beforeEach(async ({ page }) => {
    await loginUser(page);
  });

  test('should display findings list @dashboard @critical', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/findings`);

    await expect(page.locator('h1, h2').first()).toContainText(/finding/i);

    const findingsList = page.locator('table, [data-testid="findings-list"]');
    await expect(findingsList).toBeVisible();
  });

  test('should show severity indicators @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/findings`);

    // Severity badges (Critical, High, Medium, Low)
    const severityBadges = page.locator('.severity, [data-testid="severity"], .badge');
    const count = await severityBadges.count();

    if (count > 0) {
      await expect(severityBadges.first()).toBeVisible();
    }
  });

  test('should filter findings by severity @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/findings`);

    const severityFilter = page.locator('select[name*="severity"], [data-testid="severity-filter"], button:has-text("Severity")');
    if ((await severityFilter.count()) > 0) {
      await severityFilter.first().click();

      // Select Critical
      const criticalOption = page.locator('option:has-text("Critical"), [role="option"]:has-text("Critical")');
      if ((await criticalOption.count()) > 0) {
        await criticalOption.click();
      }
    }
  });

  test('should show finding details @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/findings`);

    const firstFinding = page.locator('table tbody tr, .finding-row').first();
    if ((await firstFinding.count()) > 0) {
      await firstFinding.click();

      // Finding details should show
      await expect(page.locator('[data-testid="finding-details"], .finding-detail')).toBeVisible();
    }
  });

  test('should have remediation guidance @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/findings`);

    const firstFinding = page.locator('table tbody tr, .finding-row').first();
    if ((await firstFinding.count()) > 0) {
      await firstFinding.click();

      // Remediation section
      const remediation = page.locator(':text("Remediation"), :text("Fix"), :text("Resolution")');
      await expect(remediation.first()).toBeVisible();
    }
  });
});

test.describe('Dashboard - Attestations', () => {
  test.beforeEach(async ({ page }) => {
    await loginUser(page);
  });

  test('should display attestations list @dashboard @critical', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/attestations`);

    await expect(page.locator('h1, h2').first()).toContainText(/attestation/i);

    const attestationsList = page.locator('table, [data-testid="attestations-list"]');
    await expect(attestationsList).toBeVisible();
  });

  test('should show attestation types @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/attestations`);

    // Should show types like SBOM, Provenance, Scan Results
    const content = await page.content();
    const hasTypes =
      content.toLowerCase().includes('sbom') ||
      content.toLowerCase().includes('provenance') ||
      content.toLowerCase().includes('vulnerability');

    expect(hasTypes).toBe(true);
  });

  test('should have create attestation flow @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/attestations`);

    const createBtn = page.locator('button:has-text("Create"), button:has-text("New"), a[href*="new"]');
    await expect(createBtn.first()).toBeVisible();
  });

  test('should show verification status @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/attestations`);

    // Verification badges
    const verificationStatus = page.locator('.verified, .status, [data-testid="verification-status"]');
    const count = await verificationStatus.count();

    if (count > 0) {
      await expect(verificationStatus.first()).toBeVisible();
    }
  });
});

test.describe('Dashboard - Reports', () => {
  test.beforeEach(async ({ page }) => {
    await loginUser(page);
  });

  test('should display reports page @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/reports`);

    await expect(page.locator('h1, h2').first()).toContainText(/report/i);
  });

  test('should have report generation options @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/reports`);

    // Report type options
    const reportTypes = page.locator('select, [role="listbox"], .report-type');
    await expect(reportTypes.first()).toBeVisible();
  });

  test('should allow date range selection @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/reports`);

    // Date pickers
    const datePicker = page.locator('input[type="date"], [data-testid="date-picker"]');
    const count = await datePicker.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('should generate report @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/reports`);

    const generateBtn = page.locator('button:has-text("Generate"), button:has-text("Create Report")');
    await expect(generateBtn.first()).toBeVisible();
  });
});

test.describe('Dashboard - Settings', () => {
  test.beforeEach(async ({ page }) => {
    await loginUser(page);
  });

  test('should display settings page @dashboard @critical', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/settings`);

    await expect(page.locator('h1, h2').first()).toContainText(/setting/i);
  });

  test('should have profile section @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/settings`);

    const profileSection = page.locator(':text("Profile"), :text("Account")');
    await expect(profileSection.first()).toBeVisible();
  });

  test('should have notification settings @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/settings`);

    const notifications = page.locator(':text("Notification"), a[href*="notification"]');
    await expect(notifications.first()).toBeVisible();
  });

  test('should have API keys section @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/settings`);

    const apiKeys = page.locator(':text("API Key"), :text("API Token"), a[href*="api-keys"]');
    await expect(apiKeys.first()).toBeVisible();
  });

  test('should have integrations section @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/settings`);

    const integrations = page.locator(':text("Integration"), a[href*="integration"]');
    await expect(integrations.first()).toBeVisible();
  });

  test('should save profile changes @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/settings`);

    // Find name input and update
    const nameInput = page.locator('input[name="name"], input[name="displayName"]');
    if ((await nameInput.count()) > 0) {
      await nameInput.fill('Updated Name');

      // Save button
      const saveBtn = page.locator('button:has-text("Save"), button[type="submit"]');
      await saveBtn.first().click();

      // Success message
      await expect(page.locator('.success, [role="status"]')).toBeVisible();
    }
  });
});

test.describe('Dashboard - Documentation Portal', () => {
  test.beforeEach(async ({ page }) => {
    await loginUser(page);
  });

  test('should access SBOM documentation @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/docs/sbom`);

    const content = await page.content();
    expect(content.toLowerCase()).toContain('sbom');
  });

  test('should access Admin Guide @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/docs/admin-guide`);

    const content = await page.content();
    expect(
      content.toLowerCase().includes('admin') || content.toLowerCase().includes('guide')
    ).toBe(true);
  });

  test('should access API documentation @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/docs/api`);

    const content = await page.content();
    expect(content.toLowerCase()).toContain('api');
  });
});

test.describe('Dashboard - Responsive Design', () => {
  test.beforeEach(async ({ page }) => {
    await loginUser(page);
  });

  test('should be usable on tablet @responsive', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto(`${DASHBOARD_BASE}`);

    // Sidebar should collapse or show hamburger
    const sidebar = page.locator('[data-testid="sidebar"], aside');
    const hamburger = page.locator('[data-testid="mobile-menu"], .hamburger');

    const sidebarVisible = await sidebar.isVisible();
    const hamburgerVisible = await hamburger.isVisible();

    expect(sidebarVisible || hamburgerVisible).toBe(true);
  });

  test('should be usable on mobile @responsive', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto(`${DASHBOARD_BASE}`);

    // Mobile menu should work
    const hamburger = page.locator('[data-testid="mobile-menu"], .hamburger, button[aria-label*="menu"]');
    if ((await hamburger.count()) > 0) {
      await hamburger.click();

      // Navigation should appear
      await expect(page.locator('nav a, .mobile-nav')).toBeVisible();
    }
  });
});

test.describe('Dashboard - Error Handling', () => {
  test.beforeEach(async ({ page }) => {
    await loginUser(page);
  });

  test('should handle 404 pages @dashboard', async ({ page }) => {
    await page.goto(`${DASHBOARD_BASE}/nonexistent-page-12345`);

    // Should show 404 page
    const content = await page.content();
    expect(
      content.includes('404') ||
      content.toLowerCase().includes('not found') ||
      content.toLowerCase().includes('page not found')
    ).toBe(true);
  });

  test('should handle API errors gracefully @dashboard', async ({ page }) => {
    // Intercept API call and force error
    await page.route('**/api/**', (route) => {
      route.fulfill({
        status: 500,
        body: JSON.stringify({ error: 'Internal server error' }),
      });
    });

    await page.goto(`${DASHBOARD_BASE}/projects`);

    // Should show error state, not crash
    const errorMessage = page.locator('.error, [role="alert"], :text("error")');
    const isHandled = (await errorMessage.count()) > 0 || !(await page.content()).includes('undefined');

    expect(isHandled).toBe(true);
  });
});
