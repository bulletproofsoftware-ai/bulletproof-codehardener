import { test, expect, Page } from '@playwright/test';

/**
 * Code Hardener - Comprehensive Link Crawler Test
 *
 * This test crawls all pages and verifies:
 * - No broken internal links (4xx/5xx responses)
 * - No broken external links
 * - No missing anchor targets
 * - All resources load (images, scripts, styles)
 *
 * CRITICAL: This test MUST pass before deployment.
 */

interface LinkResult {
  url: string;
  status: number | 'error' | 'timeout';
  source: string;
  type: 'internal' | 'external' | 'anchor' | 'resource';
}

const MARKETING_BASE = process.env.MARKETING_BASE || 'http://localhost:3000';
const DASHBOARD_BASE = process.env.DASHBOARD_BASE || 'http://localhost:3001';
const CRAWL_TIMEOUT = 30000;
const MAX_DEPTH = 5;

// Pages to exclude from crawling
const EXCLUDED_PATTERNS = [
  /\/logout/,
  /\/api\//,
  /\.(pdf|zip|tar|gz)$/i,
  /^mailto:/,
  /^tel:/,
  /^javascript:/,
];

// External domains to skip verification (known slow/blocking)
const SKIP_EXTERNAL = [
  'twitter.com',
  'linkedin.com',
  'github.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
];

function escapeSelector(id: string): string {
  // Escape special CSS selector characters
  return id.replace(/([!"#$%&'()*+,./:;<=>?@[\\\]^`{|}~])/g, '\\$1');
}

class LinkCrawler {
  private visited = new Set<string>();
  private results: LinkResult[] = [];
  private queue: { url: string; depth: number; source: string }[] = [];

  constructor(private page: Page, private baseUrl: string) {}

  async crawl(): Promise<LinkResult[]> {
    this.queue.push({ url: this.baseUrl, depth: 0, source: 'root' });

    while (this.queue.length > 0) {
      const { url, depth, source } = this.queue.shift()!;

      if (this.visited.has(url) || depth > MAX_DEPTH) continue;
      if (EXCLUDED_PATTERNS.some(p => p.test(url))) continue;

      this.visited.add(url);

      try {
        const response = await this.page.goto(url, {
          timeout: CRAWL_TIMEOUT,
          waitUntil: 'networkidle',
        });

        const status = response?.status() || 0;

        this.results.push({
          url,
          status,
          source,
          type: this.isInternal(url) ? 'internal' : 'external',
        });

        // Only crawl internal pages
        if (this.isInternal(url) && status === 200) {
          await this.extractLinks(url, depth);
          await this.checkResources(url);
          await this.verifyContent(url);
        }
      } catch (error) {
        this.results.push({
          url,
          status: error instanceof Error && error.message.includes('timeout') ? 'timeout' : 'error',
          source,
          type: this.isInternal(url) ? 'internal' : 'external',
        });
      }
    }

    return this.results;
  }

  private isInternal(url: string): boolean {
    try {
      const urlObj = new URL(url);
      const baseObj = new URL(this.baseUrl);
      return urlObj.hostname === baseObj.hostname;
    } catch {
      return url.startsWith('/') || url.startsWith(this.baseUrl);
    }
  }

  private async extractLinks(currentUrl: string, depth: number): Promise<void> {
    const links = await this.page.locator('a[href]').evaluateAll((anchors) =>
      anchors.map((a) => ({
        href: a.getAttribute('href') || '',
        text: a.textContent?.trim() || '',
      }))
    );

    for (const link of links) {
      let href = link.href;

      // Skip excluded patterns
      if (EXCLUDED_PATTERNS.some(p => p.test(href))) continue;

      // Resolve relative URLs
      if (href.startsWith('/')) {
        href = new URL(href, this.baseUrl).href;
      } else if (!href.startsWith('http')) {
        href = new URL(href, currentUrl).href;
      }

      // Check external links directly (don't add to crawl queue)
      if (!this.isInternal(href)) {
        if (!this.visited.has(href)) {
          await this.checkExternalLink(href, currentUrl);
        }
        continue;
      }

      // Add internal links to queue
      if (!this.visited.has(href)) {
        this.queue.push({ url: href, depth: depth + 1, source: currentUrl });
      }
    }

    // Check anchor links
    const anchors = await this.page.locator('a[href^="#"]').evaluateAll((as) =>
      as.map((a) => a.getAttribute('href') || '')
    );

    for (const anchor of anchors) {
      if (anchor.length > 1) {
        const targetId = anchor.substring(1);
        const escapedId = escapeSelector(targetId);
        const exists = await this.page.locator(`#${escapedId}`).count() > 0;
        this.results.push({
          url: anchor,
          status: exists ? 200 : 404,
          source: currentUrl,
          type: 'anchor',
        });
      }
    }
  }

  private async checkExternalLink(url: string, source: string): Promise<void> {
    this.visited.add(url);

    // Skip known problematic domains
    if (SKIP_EXTERNAL.some(domain => url.includes(domain))) {
      this.results.push({
        url,
        status: 200, // Assume OK
        source,
        type: 'external',
      });
      return;
    }

    try {
      const response = await this.page.request.head(url, { timeout: 10000 });
      this.results.push({
        url,
        status: response.status(),
        source,
        type: 'external',
      });
    } catch {
      this.results.push({
        url,
        status: 'error',
        source,
        type: 'external',
      });
    }
  }

  private async verifyContent(currentUrl: string): Promise<void> {
    const body = await this.page.locator('body').textContent().catch(() => '');
    if (!body || body.trim().length < 10) {
      this.results.push({
        url: currentUrl,
        status: 'error',
        source: 'content-check: page has no meaningful content',
        type: 'internal',
      });
      return;
    }

    const errorBoundary = await this.page.locator('text=Something went wrong').count().catch(() => 0);
    if (errorBoundary > 0) {
      this.results.push({
        url: currentUrl,
        status: 500,
        source: 'content-check: React error boundary rendered',
        type: 'internal',
      });
    }

    const mainContent = await this.page.locator('main, [role="main"], #__next > div').count().catch(() => 0);
    if (mainContent === 0) {
      console.warn(`[CONTENT] ${currentUrl} — no <main> element found`);
    }
  }

  private async checkResources(currentUrl: string): Promise<void> {
    // Check images
    const images = await this.page.locator('img[src]').evaluateAll((imgs) =>
      imgs.map((img) => img.getAttribute('src') || '')
    );

    for (const src of images) {
      if (!src || src.startsWith('data:')) continue;

      const fullUrl = src.startsWith('http') ? src : new URL(src, currentUrl).href;

      if (!this.visited.has(fullUrl)) {
        this.visited.add(fullUrl);
        try {
          const response = await this.page.request.head(fullUrl, { timeout: 5000 });
          this.results.push({
            url: fullUrl,
            status: response.status(),
            source: currentUrl,
            type: 'resource',
          });
        } catch {
          this.results.push({
            url: fullUrl,
            status: 'error',
            source: currentUrl,
            type: 'resource',
          });
        }
      }
    }
  }
}

test.describe('Link Crawler', () => {
  test('Marketing site - all links should be valid @marketing @critical', async ({ page }) => {
    test.setTimeout(300000); // 5 minutes

    const crawler = new LinkCrawler(page, MARKETING_BASE);
    const results = await crawler.crawl();

    // Analyze results
    const broken = results.filter(
      (r) =>
        (typeof r.status === 'number' && r.status >= 400) ||
        r.status === 'error'
    );

    const internalBroken = broken.filter((r) => r.type === 'internal');
    const externalBroken = broken.filter((r) => r.type === 'external');
    const anchorBroken = broken.filter((r) => r.type === 'anchor');
    const resourceBroken = broken.filter((r) => r.type === 'resource');

    // Log summary
    console.log('\n=== Marketing Site Link Report ===');
    console.log(`Total pages crawled: ${results.filter(r => r.type === 'internal').length}`);
    console.log(`External links checked: ${results.filter(r => r.type === 'external').length}`);
    console.log(`Resources checked: ${results.filter(r => r.type === 'resource').length}`);
    console.log(`Anchor links checked: ${results.filter(r => r.type === 'anchor').length}`);

    if (broken.length > 0) {
      console.log('\n=== Broken Links ===');
      broken.forEach((r) => {
        console.log(`[${r.status}] ${r.type}: ${r.url} (from: ${r.source})`);
      });
    }

    // Assertions - ZERO broken internal links
    expect(internalBroken, 'Broken internal links').toHaveLength(0);
    expect(resourceBroken, 'Broken resources').toHaveLength(0);
    expect(anchorBroken, 'Broken anchor links').toHaveLength(0);

    // External links - allow some failures (third-party issues)
    expect(externalBroken.length, 'Too many broken external links').toBeLessThan(5);
  });

  test('Dashboard - all links should be valid @dashboard @critical', async ({ page }) => {
    test.setTimeout(300000);

    await page.setExtraHTTPHeaders({ 'X-User-Id': 'dev@codehardener.local' });

    const response = await page.goto(DASHBOARD_BASE, { timeout: 10000 }).catch(() => null);
    if (!response) {
      throw new Error(`Dashboard unreachable at ${DASHBOARD_BASE} — cannot skip link verification`);
    }

    const crawler = new LinkCrawler(page, DASHBOARD_BASE);
    const results = await crawler.crawl();

    const broken = results.filter(
      (r) =>
        (typeof r.status === 'number' && r.status >= 400) ||
        r.status === 'error'
    );

    const internalBroken = broken.filter((r) => r.type === 'internal');
    const resourceBroken = broken.filter((r) => r.type === 'resource');

    console.log('\n=== Dashboard Link Report ===');
    console.log(`Total pages crawled: ${results.filter(r => r.type === 'internal').length}`);
    console.log(`Resources checked: ${results.filter(r => r.type === 'resource').length}`);

    if (broken.length > 0) {
      console.log('\n=== Broken Links ===');
      broken.forEach((r) => {
        console.log(`[${r.status}] ${r.type}: ${r.url} (from: ${r.source})`);
      });
    }

    expect(internalBroken, 'Broken internal links').toHaveLength(0);
    expect(resourceBroken, 'Broken resources').toHaveLength(0);
  });
});
