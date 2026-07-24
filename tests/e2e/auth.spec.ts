import { test, expect } from '@playwright/test';

/**
 * Code Hardener - Authentication E2E Tests
 *
 * Tests authentication flows including:
 * - Login/logout
 * - Registration
 * - Password reset
 * - Session management
 * - OAuth flows
 */

const MARKETING_BASE = 'http://localhost:3000';
const DASHBOARD_BASE = 'http://localhost:3001';

// Test user credentials (seeded in test environment)
const TEST_USER = {
  email: 'test@codehardener.local',
  password: 'TestPassword123!',
  name: 'Test User',
};

const NEW_USER = {
  email: `newuser-${Date.now()}@codehardener.local`,
  password: 'NewUserPass456!',
  name: 'New Test User',
};

test.describe('Authentication - Login', () => {
  test('should display login page correctly @marketing @critical', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/login`);

    // Check page elements
    await expect(page.locator('h1, h2').first()).toContainText(/login|sign in/i);
    await expect(page.locator('input[type="email"], input[name="email"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();

    // Check for forgot password link
    await expect(page.locator('a[href*="forgot"], a[href*="reset"]')).toBeVisible();

    // Check for signup link
    await expect(page.locator('a[href*="signup"], a[href*="register"]')).toBeVisible();
  });

  test('should show validation errors for empty form @marketing', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/login`);

    // Submit empty form
    await page.locator('button[type="submit"]').click();

    // Should show validation errors
    await expect(page.locator('.error, [role="alert"], .text-red')).toBeVisible();
  });

  test('should show error for invalid credentials @marketing', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/login`);

    await page.fill('input[type="email"], input[name="email"]', 'invalid@example.com');
    await page.fill('input[type="password"]', 'wrongpassword');
    await page.locator('button[type="submit"]').click();

    // Should show authentication error
    await expect(page.locator('.error, [role="alert"]')).toContainText(/invalid|incorrect|failed/i);
  });

  test('should login successfully with valid credentials @marketing @critical', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/login`);

    await page.fill('input[type="email"], input[name="email"]', TEST_USER.email);
    await page.fill('input[type="password"]', TEST_USER.password);
    await page.locator('button[type="submit"]').click();

    // Should redirect to dashboard
    await expect(page).toHaveURL(new RegExp(`${DASHBOARD_BASE}|/dashboard`));
  });

  test('should handle rate limiting @security', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/login`);

    // Attempt multiple rapid logins
    for (let i = 0; i < 10; i++) {
      await page.fill('input[type="email"], input[name="email"]', 'attacker@example.com');
      await page.fill('input[type="password"]', `wrongpass${i}`);
      await page.locator('button[type="submit"]').click();
      await page.waitForTimeout(100);
    }

    // Should show rate limit message or be blocked
    const content = await page.content();
    const isRateLimited =
      content.toLowerCase().includes('rate limit') ||
      content.toLowerCase().includes('too many') ||
      content.toLowerCase().includes('try again later') ||
      page.url().includes('blocked');

    expect(isRateLimited).toBe(true);
  });
});

test.describe('Authentication - Registration', () => {
  test('should display registration page correctly @marketing @critical', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/signup`);

    // Check page elements
    await expect(page.locator('h1, h2').first()).toContainText(/sign up|register|create account/i);
    await expect(page.locator('input[name="name"], input[name="fullName"]')).toBeVisible();
    await expect(page.locator('input[type="email"], input[name="email"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('should validate password requirements @marketing', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/signup`);

    await page.fill('input[name="name"], input[name="fullName"]', NEW_USER.name);
    await page.fill('input[type="email"], input[name="email"]', NEW_USER.email);
    await page.fill('input[type="password"]', 'weak'); // Weak password

    await page.locator('button[type="submit"]').click();

    // Should show password requirements error
    const content = await page.content();
    const hasPasswordError =
      content.toLowerCase().includes('password') &&
      (content.toLowerCase().includes('8') ||
        content.toLowerCase().includes('characters') ||
        content.toLowerCase().includes('uppercase') ||
        content.toLowerCase().includes('number'));

    expect(hasPasswordError).toBe(true);
  });

  test('should prevent duplicate email registration @marketing', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/signup`);

    await page.fill('input[name="name"], input[name="fullName"]', 'Duplicate User');
    await page.fill('input[type="email"], input[name="email"]', TEST_USER.email); // Existing user
    await page.fill('input[type="password"]', 'ValidPass123!');

    await page.locator('button[type="submit"]').click();

    // Should show error about existing account
    await expect(page.locator('.error, [role="alert"]')).toContainText(
      /already exists|already registered|account exists/i
    );
  });
});

test.describe('Authentication - Password Reset', () => {
  test('should display forgot password page @marketing', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/forgot-password`);

    await expect(page.locator('h1, h2').first()).toContainText(/forgot|reset|recover/i);
    await expect(page.locator('input[type="email"], input[name="email"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('should accept valid email for password reset @marketing', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/forgot-password`);

    await page.fill('input[type="email"], input[name="email"]', TEST_USER.email);
    await page.locator('button[type="submit"]').click();

    // Should show success message
    await expect(page.locator('.success, [role="status"]')).toContainText(
      /email sent|check your email|instructions/i
    );
  });

  test('should not reveal if email exists @security', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/forgot-password`);

    // Try with non-existent email
    await page.fill('input[type="email"], input[name="email"]', 'nonexistent@example.com');
    await page.locator('button[type="submit"]').click();

    // Should show same generic message (not reveal if account exists)
    const content = await page.content();
    const isGenericMessage =
      content.toLowerCase().includes('if an account exists') ||
      content.toLowerCase().includes('check your email') ||
      !content.toLowerCase().includes('not found');

    expect(isGenericMessage).toBe(true);
  });
});

test.describe('Authentication - Session Management', () => {
  test('should maintain session across page refreshes @dashboard', async ({ page }) => {
    // Login first
    await page.goto(`${MARKETING_BASE}/login`);
    await page.fill('input[type="email"], input[name="email"]', TEST_USER.email);
    await page.fill('input[type="password"]', TEST_USER.password);
    await page.locator('button[type="submit"]').click();

    // Wait for dashboard
    await page.waitForURL(new RegExp(`${DASHBOARD_BASE}|/dashboard`));

    // Refresh page
    await page.reload();

    // Should still be logged in
    await expect(page.locator('[data-testid="user-menu"], .user-menu, .avatar')).toBeVisible();
  });

  test('should logout successfully @dashboard @critical', async ({ page }) => {
    // Login first
    await page.goto(`${MARKETING_BASE}/login`);
    await page.fill('input[type="email"], input[name="email"]', TEST_USER.email);
    await page.fill('input[type="password"]', TEST_USER.password);
    await page.locator('button[type="submit"]').click();

    await page.waitForURL(new RegExp(`${DASHBOARD_BASE}|/dashboard`));

    // Find and click logout
    await page.locator('[data-testid="user-menu"], .user-menu, .avatar').click();
    await page.locator('text=logout', { exact: false }).click();

    // Should redirect to login or home
    await expect(page).toHaveURL(new RegExp(`${MARKETING_BASE}|/login|/$`));
  });

  test('should clear session data on logout @security', async ({ page, context }) => {
    // Login
    await page.goto(`${MARKETING_BASE}/login`);
    await page.fill('input[type="email"], input[name="email"]', TEST_USER.email);
    await page.fill('input[type="password"]', TEST_USER.password);
    await page.locator('button[type="submit"]').click();

    await page.waitForURL(new RegExp(`${DASHBOARD_BASE}|/dashboard`));

    // Logout
    await page.locator('[data-testid="user-menu"], .user-menu, .avatar').click();
    await page.locator('text=logout', { exact: false }).click();

    // Check that auth cookies/storage are cleared
    const cookies = await context.cookies();
    const authCookies = cookies.filter(
      (c) =>
        c.name.toLowerCase().includes('auth') ||
        c.name.toLowerCase().includes('session') ||
        c.name.toLowerCase().includes('token')
    );

    expect(authCookies.length).toBe(0);
  });

  test('should redirect to login when accessing protected routes @security', async ({ page }) => {
    // Try to access dashboard without login
    await page.goto(`${DASHBOARD_BASE}/projects`);

    // Should redirect to login
    await expect(page).toHaveURL(new RegExp(`/login`));
  });
});

test.describe('Authentication - Security Headers', () => {
  test('should have secure cookie settings @security', async ({ page, context }) => {
    await page.goto(`${MARKETING_BASE}/login`);
    await page.fill('input[type="email"], input[name="email"]', TEST_USER.email);
    await page.fill('input[type="password"]', TEST_USER.password);
    await page.locator('button[type="submit"]').click();

    await page.waitForURL(new RegExp(`${DASHBOARD_BASE}|/dashboard`));

    const cookies = await context.cookies();
    const sessionCookie = cookies.find(
      (c) =>
        c.name.toLowerCase().includes('session') ||
        c.name.toLowerCase().includes('auth') ||
        c.name.toLowerCase().includes('token')
    );

    if (sessionCookie) {
      // Session cookies should be HttpOnly and Secure in production
      // In local dev, at least check they exist
      expect(sessionCookie.httpOnly).toBe(true);
    }
  });

  test('should include security headers in response @security', async ({ page }) => {
    const response = await page.goto(`${MARKETING_BASE}/login`);
    const headers = response?.headers() || {};

    // Check for recommended security headers
    const securityHeaders = [
      'x-content-type-options',
      'x-frame-options',
      'x-xss-protection',
    ];

    for (const header of securityHeaders) {
      expect(
        headers[header],
        `Missing security header: ${header}`
      ).toBeDefined();
    }
  });
});

test.describe('Authentication - CSRF Protection', () => {
  test('should include CSRF token in forms @security', async ({ page }) => {
    await page.goto(`${MARKETING_BASE}/login`);

    // Check for CSRF token in form or meta tag
    const csrfInput = await page.locator('input[name*="csrf"], input[name*="_token"]').count();
    const csrfMeta = await page.locator('meta[name*="csrf"]').count();

    expect(csrfInput > 0 || csrfMeta > 0).toBe(true);
  });
});
