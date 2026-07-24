/**
 * BackstopJS - onBefore script
 * Runs before each scenario
 */

module.exports = async (page, _scenario, vp, _isReference, _browserContext) => {
  // Set default timeout
  await page.setDefaultTimeout(30000);

  // Set viewport
  await page.setViewport({
    width: vp.width,
    height: vp.height,
  });

  // Block unnecessary resources for faster loading
  await page.setRequestInterception(true);
  page.on('request', (request) => {
    const resourceType = request.resourceType();
    const url = request.url();

    // Block analytics, ads, and other non-essential resources
    if (
      resourceType === 'media' ||
      url.includes('google-analytics') ||
      url.includes('googletagmanager') ||
      url.includes('facebook') ||
      url.includes('hotjar') ||
      url.includes('intercom')
    ) {
      request.abort();
    } else {
      request.continue();
    }
  });

  // Disable animations for consistent screenshots
  await page.evaluateOnNewDocument(() => {
    // Create style element using safe DOM methods
    const style = document.createElement('style');
    style.type = 'text/css';

    // Use textContent instead of innerHTML for safety
    style.textContent = [
      '*, *::before, *::after {',
      '  animation-duration: 0s !important;',
      '  animation-delay: 0s !important;',
      '  transition-duration: 0s !important;',
      '  transition-delay: 0s !important;',
      '}'
    ].join('\n');

    document.head.appendChild(style);
  });
};
