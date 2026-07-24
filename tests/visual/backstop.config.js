/**
 * Code Hardener - BackstopJS Visual Regression Configuration
 *
 * Captures and compares screenshots across viewports.
 * Run with: backstop test --config=backstop.config.js
 */

module.exports = {
  id: 'codehardener',
  viewports: [
    {
      label: 'phone',
      width: 375,
      height: 667,
    },
    {
      label: 'tablet',
      width: 768,
      height: 1024,
    },
    {
      label: 'desktop',
      width: 1440,
      height: 900,
    },
  ],
  onBeforeScript: 'puppet/onBefore.js',
  onReadyScript: 'puppet/onReady.js',
  scenarios: [
    // Dashboard Scenarios
    {
      label: 'Dashboard - Overview',
      url: 'http://localhost:3001',
      delay: 1000,
    },
    {
      label: 'Dashboard - Sidebar',
      url: 'http://localhost:3001',
      selectors: ['[data-testid="sidebar"], aside, .sidebar'],
      delay: 500,
    },
    {
      label: 'Dashboard - Projects List',
      url: 'http://localhost:3001/projects',
      delay: 1000,
    },
    {
      label: 'Dashboard - Scans List',
      url: 'http://localhost:3001/scans',
      delay: 1000,
    },
    {
      label: 'Dashboard - Findings',
      url: 'http://localhost:3001/findings',
      delay: 1000,
    },
    {
      label: 'Dashboard - Attestations',
      url: 'http://localhost:3001/attestations',
      delay: 1000,
    },
    {
      label: 'Dashboard - Settings',
      url: 'http://localhost:3001/settings',
      delay: 1000,
    },

    // Interactive State Scenarios
    {
      label: 'Dashboard - Dropdown Open',
      url: 'http://localhost:3001',
      clickSelector: '[data-testid="user-menu"], .user-menu, .avatar',
      postInteractionWait: 500,
    },

    // Form State Scenarios
    {
      label: 'Login - Form Focus',
      url: 'http://localhost:3001/login',
      clickSelector: 'input[type="email"]',
      postInteractionWait: 300,
    },
    {
      label: 'Login - Form Error',
      url: 'http://localhost:3001/login',
      onReadyScript: 'puppet/loginError.js',
      delay: 1000,
    },
  ],
  paths: {
    bitmaps_reference: 'backstop_data/bitmaps_reference',
    bitmaps_test: 'backstop_data/bitmaps_test',
    engine_scripts: 'backstop_data/engine_scripts',
    html_report: 'backstop_data/html_report',
    ci_report: 'backstop_data/ci_report',
  },
  report: ['browser', 'CI'],
  engine: 'puppeteer',
  engineOptions: {
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  },
  asyncCaptureLimit: 5,
  asyncCompareLimit: 50,
  debug: false,
  debugWindow: false,
  resembleOutputOptions: {
    errorColor: {
      red: 255,
      green: 0,
      blue: 255,
    },
    errorType: 'movement',
    transparency: 0.3,
    largeImageThreshold: 1200,
  },
};
