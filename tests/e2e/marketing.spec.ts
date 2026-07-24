import { test, expect } from '@playwright/test';

/**
 * Code Hardener - Marketing Site E2E Tests
 *
 * Tests all marketing site pages and functionality:
 * - Home page
 * - Features page
 * - Pricing page
 * - Documentation
 * - About/Contact
 * - Blog
 */

const BASE_URL = 'http://localhost:3000';

test.describe('Marketing - Home Page', () => {
  test('should load home page successfully @marketing @critical', async ({ page }) => {
    const response = await page.goto(BASE_URL);
    expect(response?.status()).toBe(200);
  });

  test('should display hero section @marketing', async ({ page }) => {
    await page.goto(BASE_URL);

    // Hero should have headline and CTA
    await expect(page.locator('h1').first()).toBeVisible();
    await expect(page.locator('a[href*="signup"], a[href*="demo"], button').first()).toBeVisible();
  });

  test('should display navigation @marketing', async ({ page }) => {
    await page.goto(BASE_URL);

    // Navigation links
    await expect(page.locator('nav')).toBeVisible();
    await expect(page.locator('a[href="/features"], a:has-text("Features")')).toBeVisible();
    await expect(page.locator('a[href="/pricing"], a:has-text("Pricing")')).toBeVisible();
    await expect(page.locator('a[href="/docs"], a:has-text("Docs")')).toBeVisible();
  });

  test('should display footer with legal links @marketing', async ({ page }) => {
    await page.goto(BASE_URL);

    await expect(page.locator('footer')).toBeVisible();
    await expect(page.locator('a[href*="privacy"]')).toBeVisible();
    await expect(page.locator('a[href*="terms"]')).toBeVisible();
  });

  test('should have proper page title and meta @seo', async ({ page }) => {
    await page.goto(BASE_URL);

    const title = await page.title();
    expect(title).toContain('Code Hardener');

    // Check meta description
    const metaDesc = await page.locator('meta[name="description"]').getAttribute('content');
    expect(metaDesc).toBeTruthy();
    expect(metaDesc?.length).toBeGreaterThan(50);
  });

  test('should be responsive on mobile @responsive', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto(BASE_URL);

    // Mobile menu should be present
    await expect(page.locator('[data-testid="mobile-menu"], .hamburger, button[aria-label*="menu"]')).toBeVisible();

    // Content should not overflow
    const body = page.locator('body');
    const bodyWidth = await body.evaluate((el) => el.scrollWidth);
    expect(bodyWidth).toBeLessThanOrEqual(375);
  });
});

test.describe('Marketing - Features Page', () => {
  test('should load features page @marketing @critical', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/features`);
    expect(response?.status()).toBe(200);
  });

  test('should display all feature categories @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/features`);

    // Check for main feature sections
    const features = [
      /security scan/i,
      /attestation/i,
      /sbom/i,
      /dashboard/i,
    ];

    for (const feature of features) {
      const element = page.locator(`text=${feature.source.replace(/[/\\^$*+?.()|[\]{}]/g, '')}`);
      await expect(element.first()).toBeVisible();
    }
  });

  test('should have working CTA buttons @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/features`);

    // Find CTA and verify it links to signup/demo
    const cta = page.locator('a[href*="signup"], a[href*="demo"]').first();
    await expect(cta).toBeVisible();

    const href = await cta.getAttribute('href');
    expect(href).toMatch(/signup|demo|trial/);
  });
});

test.describe('Marketing - Pricing Page', () => {
  test('should load pricing page @marketing @critical', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/pricing`);
    expect(response?.status()).toBe(200);
  });

  test('should display pricing tiers @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/pricing`);

    // Should have multiple pricing cards
    const pricingCards = page.locator('[data-testid="pricing-card"], .pricing-card, .plan-card');
    const cardCount = await pricingCards.count();

    // At least 2 tiers (Free + Paid)
    expect(cardCount).toBeGreaterThanOrEqual(2);
  });

  test('should display prices @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/pricing`);

    // Should have price displays
    const prices = page.locator('text=/\\$\\d+|Free|Custom/');
    const priceCount = await prices.count();

    expect(priceCount).toBeGreaterThanOrEqual(2);
  });

  test('should have comparison table @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/pricing`);

    // Look for feature comparison
    const table = page.locator('table, [role="table"], .comparison');
    await expect(table).toBeVisible();
  });

  test('should have FAQ section @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/pricing`);

    // FAQ accordion or section
    const faq = page.locator('[data-testid="faq"], .faq, :text("FAQ"), :text("Questions")');
    await expect(faq.first()).toBeVisible();
  });
});

test.describe('Marketing - Documentation', () => {
  test('should load docs landing page @marketing @critical', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/docs`);
    expect(response?.status()).toBe(200);
  });

  test('should have documentation navigation @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/docs`);

    // Sidebar or navigation
    const nav = page.locator('[data-testid="docs-nav"], .docs-sidebar, aside nav');
    await expect(nav).toBeVisible();
  });

  test('should have search functionality @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/docs`);

    // Search input
    const search = page.locator('input[type="search"], input[placeholder*="Search"]');
    await expect(search).toBeVisible();
  });

  test('should have getting started guide @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/docs`);

    // Quick start or getting started link
    const quickStart = page.locator('a[href*="getting-started"], a[href*="quickstart"], :text("Getting Started")');
    await expect(quickStart.first()).toBeVisible();
  });

  test('should have API documentation link @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/docs`);

    const apiDocs = page.locator('a[href*="api"], :text("API Reference")');
    await expect(apiDocs.first()).toBeVisible();
  });
});

test.describe('Marketing - About Page', () => {
  test('should load about page @marketing', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/about`);
    expect(response?.status()).toBe(200);
  });

  test('should display company mission @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/about`);

    // Mission or about content
    const content = await page.content();
    const hasMission =
      content.toLowerCase().includes('mission') ||
      content.toLowerCase().includes('about') ||
      content.toLowerCase().includes('story');

    expect(hasMission).toBe(true);
  });
});

test.describe('Marketing - Contact Page', () => {
  test('should load contact page @marketing', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/contact`);
    expect(response?.status()).toBe(200);
  });

  test('should display contact form @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/contact`);

    // Contact form elements
    await expect(page.locator('input[type="email"], input[name="email"]')).toBeVisible();
    await expect(page.locator('textarea, input[name="message"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('should validate contact form @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/contact`);

    // Submit empty form
    await page.locator('button[type="submit"]').click();

    // Should show validation errors
    await expect(page.locator('.error, [role="alert"], :text("required")')).toBeVisible();
  });
});

test.describe('Marketing - Blog', () => {
  test('should load blog page @marketing', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/blog`);
    expect(response?.status()).toBe(200);
  });

  test('should display blog posts @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/blog`);

    // Blog post cards
    const posts = page.locator('article, [data-testid="blog-post"], .blog-card');
    const postCount = await posts.count();

    expect(postCount).toBeGreaterThanOrEqual(1);
  });

  test('should have working blog post links @marketing', async ({ page }) => {
    await page.goto(`${BASE_URL}/blog`);

    // Click first blog post
    const firstPost = page.locator('article a, [data-testid="blog-post"] a').first();
    const href = await firstPost.getAttribute('href');

    await firstPost.click();

    // Should navigate to post
    expect(page.url()).toContain(href || '/blog/');
  });
});

test.describe('Marketing - Legal Pages', () => {
  test('should load privacy policy @marketing @critical', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/privacy`);
    expect(response?.status()).toBe(200);

    // Should have privacy content
    const content = await page.content();
    expect(content.toLowerCase()).toContain('privacy');
  });

  test('should load terms of service @marketing @critical', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/terms`);
    expect(response?.status()).toBe(200);

    // Should have terms content
    const content = await page.content();
    expect(content.toLowerCase()).toContain('terms');
  });

  test('should load cookie policy @marketing', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/cookies`);
    expect(response?.status()).toBe(200);
  });
});

test.describe('Marketing - Performance', () => {
  test('should load home page within 3 seconds @performance', async ({ page }) => {
    const startTime = Date.now();
    await page.goto(BASE_URL, { waitUntil: 'domcontentloaded' });
    const loadTime = Date.now() - startTime;

    expect(loadTime).toBeLessThan(3000);
  });

  test('should have no console errors @quality', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    await page.goto(BASE_URL);
    await page.waitForTimeout(1000);

    // Filter out known acceptable errors
    const criticalErrors = errors.filter(
      (e) =>
        !e.includes('favicon') &&
        !e.includes('analytics') &&
        !e.includes('tracking')
    );

    expect(criticalErrors).toHaveLength(0);
  });
});

test.describe('Marketing - Accessibility Quick Check', () => {
  test('should have proper heading hierarchy @a11y', async ({ page }) => {
    await page.goto(BASE_URL);

    // Should have exactly one h1
    const h1Count = await page.locator('h1').count();
    expect(h1Count).toBe(1);

    // Check for h2s following h1
    const h2Count = await page.locator('h2').count();
    expect(h2Count).toBeGreaterThan(0);
  });

  test('should have alt text on images @a11y', async ({ page }) => {
    await page.goto(BASE_URL);

    const images = page.locator('img');
    const count = await images.count();

    for (let i = 0; i < count; i++) {
      const img = images.nth(i);
      const alt = await img.getAttribute('alt');
      const role = await img.getAttribute('role');

      // Image should have alt or be decorative (role=presentation)
      expect(alt !== null || role === 'presentation').toBe(true);
    }
  });

  test('should have proper link text @a11y', async ({ page }) => {
    await page.goto(BASE_URL);

    const links = page.locator('a');
    const count = await links.count();

    for (let i = 0; i < Math.min(count, 20); i++) {
      const link = links.nth(i);
      const text = await link.textContent();
      const ariaLabel = await link.getAttribute('aria-label');

      // Link should have meaningful text or aria-label
      const hasContent = (text && text.trim().length > 0) || ariaLabel;
      expect(hasContent).toBeTruthy();

      // Avoid generic link text
      if (text) {
        expect(text.toLowerCase()).not.toMatch(/^(click here|read more|here)$/);
      }
    }
  });
});
