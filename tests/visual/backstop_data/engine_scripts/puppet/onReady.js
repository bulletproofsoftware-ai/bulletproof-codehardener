/**
 * BackstopJS - onReady script
 * Runs after page loads and before screenshot
 */

module.exports = async (page, _scenario, _vp) => {
  // Wait for page to be fully loaded
  await page.waitForSelector('body');

  // Wait for fonts to load
  await page.evaluate(async () => {
    if (document.fonts && document.fonts.ready) {
      await document.fonts.ready;
    }
  });

  // Wait for images to load
  await page.evaluate(async () => {
    const images = document.querySelectorAll('img');
    await Promise.all(
      Array.from(images).map((img) => {
        if (img.complete) return Promise.resolve();
        return new Promise((resolve) => {
          img.addEventListener('load', resolve);
          img.addEventListener('error', resolve);
        });
      })
    );
  });

  // Hide dynamic content that changes between runs
  await page.evaluate(() => {
    // Hide elements with dynamic content
    const selectorsToHide = [
      '[data-testid="timestamp"]',
      '.timestamp',
      '.date-time',
      '.relative-time',
      '.live-indicator',
      '.notification-count',
      '.cookie-banner',
      '.cookie-consent',
    ];

    selectorsToHide.forEach((selector) => {
      const elements = document.querySelectorAll(selector);
      elements.forEach((el) => {
        el.style.visibility = 'hidden';
      });
    });

    // Replace dynamic text
    const dynamicTextElements = document.querySelectorAll('[data-dynamic]');
    dynamicTextElements.forEach((el) => {
      el.textContent = '[DYNAMIC]';
    });
  });

  // Scroll to trigger lazy loading if needed
  await page.evaluate(async () => {
    await new Promise((resolve) => {
      let totalHeight = 0;
      const distance = 100;
      const timer = setInterval(() => {
        const scrollHeight = document.body.scrollHeight;
        window.scrollBy(0, distance);
        totalHeight += distance;

        if (totalHeight >= scrollHeight) {
          clearInterval(timer);
          window.scrollTo(0, 0);
          resolve();
        }
      }, 100);
    });
  });

  // Final wait for any lazy-loaded content
  await new Promise((resolve) => setTimeout(resolve, 500));

  // Scroll back to top
  await page.evaluate(() => window.scrollTo(0, 0));

  // Additional wait for scroll to settle
  await new Promise((resolve) => setTimeout(resolve, 200));
};
