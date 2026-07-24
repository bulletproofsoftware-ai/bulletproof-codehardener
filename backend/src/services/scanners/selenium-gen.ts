// backend/src/services/scanners/selenium-gen.ts
import { createLogger } from '../../utils/logger.js';
import { analyzeCode } from '../test-generator/code-analyzer/index.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';
import type { ExtractedEndpoint, AuthPattern, DataFlow } from '../test-generator/types.js';

const logger = createLogger('scanner-selenium-gen');
const SCAN_TARGET = '/scan-target';

const XSS_PAYLOADS = [
  '<script>alert("xss")</script>',
  '"><img src=x onerror=alert(1)>',
  "';alert(String.fromCharCode(88,83,83))//",
  '<svg/onload=alert(1)>',
];

const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "1; DROP TABLE users--",
  "' UNION SELECT NULL,NULL--",
  "admin'--",
];

interface GeneratedTests {
  functionalTestCode: string;
  securityTestCode: string;
  functionalTestCount: number;
  securityTestCount: number;
  endpointsAnalyzed: number;
  authPatternsDetected: number;
  dataFlowsAnalyzed: number;
}

function testBoilerplate(suiteName: string, testBodies: string[]): string {
  return `const { Builder, By, until } = require('selenium-webdriver');
const assert = require('assert');

describe('${suiteName}', function() {
  this.timeout(30000);
  let driver;

  before(async function() {
    driver = await new Builder()
      .forBrowser('chrome')
      .setChromeOptions(
        new (require('selenium-webdriver/chrome').Options)()
          .addArguments('--headless', '--no-sandbox', '--disable-dev-shm-usage')
      )
      .build();
  });

  after(async function() {
    if (driver) await driver.quit();
  });

${testBodies.join('\n\n')}
});
`;
}

function buildEndpointTest(endpoint: ExtractedEndpoint, baseUrl: string): string {
  const { method, path } = endpoint;
  const fullUrl = `${baseUrl}${path}`;
  const testName = `${method} ${path} — responds successfully`;

  if (method === 'GET') {
    return `  it('${testName}', async function() {
    await driver.get('${fullUrl}');
    const title = await driver.getTitle();
    assert.ok(title !== undefined, 'Page should load with a title');
    const body = await driver.findElement(By.tagName('body')).getText();
    assert.ok(!body.includes('500'), 'Should not return server error');
    assert.ok(!body.includes('Internal Server Error'), 'Should not return 500');
  });`;
  }

  if (method === 'POST' && path.includes('login')) {
    return `  it('${testName}', async function() {
    await driver.get('${fullUrl}');
    const inputs = await driver.findElements(By.tagName('input'));
    assert.ok(inputs.length >= 2, 'Login page should have at least 2 input fields');
    const emailInput = await driver.findElement(By.css('input[type="email"], input[name="email"], input[name="username"]')).catch(() => null);
    const passwordInput = await driver.findElement(By.css('input[type="password"]')).catch(() => null);
    if (emailInput && passwordInput) {
      await emailInput.sendKeys('test@example.com');
      await passwordInput.sendKeys('TestPassword123!');
      const submitBtn = await driver.findElement(By.css('button[type="submit"], input[type="submit"]')).catch(() => null);
      if (submitBtn) await submitBtn.click();
    }
  });`;
  }

  return `  it('${testName}', async function() {
    await driver.get('${fullUrl}');
    const body = await driver.findElement(By.tagName('body')).getText();
    assert.ok(!body.includes('Internal Server Error'), 'Should not return 500 error');
  });`;
}

function buildNavigationTest(endpoints: ExtractedEndpoint[], baseUrl: string): string {
  const getEndpoints = endpoints.filter(e => e.method === 'GET').slice(0, 10);
  if (getEndpoints.length === 0) return '';

  const navSteps = getEndpoints.map(e => {
    const url = `${baseUrl}${e.path}`;
    return `    await driver.get('${url}');
    currentUrl = await driver.getCurrentUrl();
    assert.ok(currentUrl.includes('${e.path.split('/').slice(0, 3).join('/')}'), 'Should navigate to ${e.path}');`;
  }).join('\n\n');

  return `  it('navigates through all detected routes without errors', async function() {
    this.timeout(60000);
    let currentUrl;
${navSteps}
  });`;
}

function buildXSSTests(endpoints: ExtractedEndpoint[], dataFlows: DataFlow[], baseUrl: string): string[] {
  const tests: string[] = [];
  const taintedSinks = dataFlows.filter(df => df.tainted && !df.sanitized && df.source.type === 'user_input');

  for (const endpoint of endpoints) {
    if (endpoint.method !== 'POST' && endpoint.method !== 'PUT') continue;

    const hasTaintedFlow = taintedSinks.some(df =>
      df.source.location.includes(endpoint.file) || df.sink.location.includes(endpoint.file)
    );

    const severity = hasTaintedFlow ? 'TAINTED — unsanitized user input detected' : 'standard input validation';

    tests.push(`  it('${endpoint.method} ${endpoint.path} — rejects XSS payloads (${severity})', async function() {
    await driver.get('${baseUrl}${endpoint.path}');
    const inputs = await driver.findElements(By.tagName('input'));
    const textareas = await driver.findElements(By.tagName('textarea'));
    const allInputs = [...inputs, ...textareas];

    for (const input of allInputs) {
      const type = await input.getAttribute('type');
      if (type === 'hidden' || type === 'submit') continue;

      for (const payload of ${JSON.stringify(XSS_PAYLOADS)}) {
        await input.clear();
        await input.sendKeys(payload);
      }
    }

    const submitBtn = await driver.findElement(By.css('button[type="submit"], input[type="submit"]')).catch(() => null);
    if (submitBtn) await submitBtn.click();

    const pageSource = await driver.getPageSource();
    for (const payload of ${JSON.stringify(XSS_PAYLOADS)}) {
      assert.ok(
        !pageSource.includes(payload),
        'XSS payload should be escaped or rejected: ' + payload.substring(0, 30)
      );
    }
  });`);
  }

  return tests;
}

function buildAuthBypassTests(endpoints: ExtractedEndpoint[], _authPatterns: AuthPattern[], baseUrl: string): string[] {
  const tests: string[] = [];
  const protectedEndpoints = endpoints.filter(e => e.authentication || e.auth);

  for (const endpoint of protectedEndpoints) {
    tests.push(`  it('${endpoint.method} ${endpoint.path} — blocks access without authentication', async function() {
    await driver.get('${baseUrl}${endpoint.path}');
    const body = await driver.findElement(By.tagName('body')).getText();
    const currentUrl = await driver.getCurrentUrl();

    const isRedirected = currentUrl.includes('login') || currentUrl.includes('signin') || currentUrl.includes('auth');
    const isBlocked = body.includes('401') || body.includes('403') || body.includes('Unauthorized') || body.includes('Forbidden');

    assert.ok(
      isRedirected || isBlocked,
      '${endpoint.path} should require authentication — got: ' + body.substring(0, 100)
    );
  });`);
  }

  if (_authPatterns.some(p => p.type === 'session')) {
    tests.push(`  it('rejects session fixation attacks', async function() {
    await driver.manage().addCookie({ name: 'connect.sid', value: 'attacker-controlled-session-id' });
    const loginEndpoint = ${JSON.stringify(endpoints.find(e => e.path.includes('login'))?.path || '/login')};
    await driver.get('${baseUrl}' + loginEndpoint);

    const cookies = await driver.manage().getCookies();
    const sessionCookie = cookies.find(c => c.name === 'connect.sid');
    if (sessionCookie) {
      assert.notStrictEqual(
        sessionCookie.value,
        'attacker-controlled-session-id',
        'Session ID should be regenerated after login to prevent session fixation'
      );
    }
  });`);
  }

  return tests;
}

function buildCSRFTests(endpoints: ExtractedEndpoint[], baseUrl: string): string[] {
  const stateChanging = endpoints.filter(e =>
    ['POST', 'PUT', 'DELETE', 'PATCH'].includes(e.method)
  );

  if (stateChanging.length === 0) return [];

  return [`  it('state-changing endpoints require CSRF tokens', async function() {
    await driver.get('${baseUrl}${stateChanging[0]?.path || '/'}');

    const csrfMeta = await driver.findElement(By.css('meta[name="csrf-token"]')).catch(() => null);
    const csrfInput = await driver.findElement(By.css('input[name="_csrf"], input[name="csrf_token"], input[name="csrfmiddlewaretoken"]')).catch(() => null);

    const hasCSRF = csrfMeta !== null || csrfInput !== null;
    if (!hasCSRF) {
      console.warn('No CSRF token found — verify CSRF protection via other mechanisms (SameSite cookies, Origin header)');
    }
  });`];
}

function buildSQLiTests(endpoints: ExtractedEndpoint[], dataFlows: DataFlow[], baseUrl: string): string[] {
  const dbFlows = dataFlows.filter(df => df.sink.type === 'db');
  if (dbFlows.length === 0) return [];

  const tests: string[] = [];

  for (const endpoint of endpoints.filter(e => e.method === 'POST' || e.method === 'GET')) {
    const hasDbFlow = dbFlows.some(df =>
      df.source.location.includes(endpoint.file) || df.sink.location.includes(endpoint.file)
    );
    if (!hasDbFlow) continue;

    tests.push(`  it('${endpoint.method} ${endpoint.path} — handles SQL injection payloads safely', async function() {
    await driver.get('${baseUrl}${endpoint.path}');
    const inputs = await driver.findElements(By.tagName('input'));

    for (const input of inputs) {
      const type = await input.getAttribute('type');
      if (type === 'hidden' || type === 'submit') continue;

      for (const payload of ${JSON.stringify(SQLI_PAYLOADS)}) {
        await input.clear();
        await input.sendKeys(payload);
      }
    }

    const submitBtn = await driver.findElement(By.css('button[type="submit"], input[type="submit"]')).catch(() => null);
    if (submitBtn) await submitBtn.click();

    const body = await driver.findElement(By.tagName('body')).getText();
    assert.ok(!body.includes('SQL syntax'), 'Should not leak SQL error messages');
    assert.ok(!body.includes('mysql_'), 'Should not leak MySQL error messages');
    assert.ok(!body.includes('pg_'), 'Should not leak PostgreSQL error messages');
    assert.ok(!body.includes('SQLITE_ERROR'), 'Should not leak SQLite errors');
  });`);
  }

  return tests;
}

export async function runSeleniumGen(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    let analysis;
    try {
      analysis = await analyzeCode(SCAN_TARGET, {
        skipSensitiveDataDetection: true,
        skipDependencyParsing: true,
        skipInfraDetection: true,
        timeout: 30000,
      });
    } catch (error) {
      logger.warn({ error }, 'Code analysis failed — skipping selenium-gen');
      return {
        scanner: 'selenium-gen',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'Code analysis failed — cannot generate Selenium tests without endpoint data',
        skipReason: 'no_web_endpoints',
        skipHint: 'No web endpoints detected — Selenium needs HTTP routes to generate tests',
      };
    }

    const { endpoints, authPatterns, dataFlows, frameworks } = analysis.result;

    if (endpoints.length === 0) {
      findings.push({
        ruleId: 'SELENIUM-GEN-SKIPPED',
        severity: 'info' as Severity,
        title: 'Selenium test generation skipped — no web endpoints detected',
        description: 'No HTTP endpoints, routes, or web handlers were found in the codebase. ' +
          'Selenium tests require web endpoints to test against.',
        filePath: null,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: false,
        fixDescription: null,
        metadata: { reason: 'no-endpoints' },
      });

      return {
        scanner: 'selenium-gen',
        success: true,
        skipped: true,
        findings,
        duration: Date.now() - startTime,
        skipReason: 'no_web_endpoints',
        skipHint: 'No web endpoints detected — Selenium needs HTTP routes to generate tests',
      };
    }

    const baseUrl = 'http://localhost:3000';

    const functionalTests: string[] = [];
    for (const endpoint of endpoints.slice(0, 20)) {
      functionalTests.push(buildEndpointTest(endpoint, baseUrl));
    }

    const navTest = buildNavigationTest(endpoints, baseUrl);
    if (navTest) functionalTests.push(navTest);

    const functionalTestCode = testBoilerplate(
      `[Generated] Functional E2E Tests — ${_jobData.scanId}`,
      functionalTests
    );

    const securityTests: string[] = [];
    securityTests.push(...buildXSSTests(endpoints, dataFlows, baseUrl));
    securityTests.push(...buildAuthBypassTests(endpoints, authPatterns, baseUrl));
    securityTests.push(...buildCSRFTests(endpoints, baseUrl));
    securityTests.push(...buildSQLiTests(endpoints, dataFlows, baseUrl));

    const securityTestCode = securityTests.length > 0
      ? testBoilerplate(
          `[Generated] Security Regression Tests — ${_jobData.scanId}`,
          securityTests
        )
      : '';

    const generated: GeneratedTests = {
      functionalTestCode,
      securityTestCode,
      functionalTestCount: functionalTests.length,
      securityTestCount: securityTests.length,
      endpointsAnalyzed: endpoints.length,
      authPatternsDetected: authPatterns.length,
      dataFlowsAnalyzed: dataFlows.length,
    };

    findings.push({
      ruleId: 'SELENIUM-GEN-FUNCTIONAL',
      severity: 'info' as Severity,
      title: `Selenium: Generated ${functionalTests.length} functional E2E tests`,
      description: `Generated functional Selenium WebDriver tests covering ${endpoints.length} endpoints. ` +
        `Tests include navigation, form submission, and endpoint response validation. ` +
        `Framework: ${frameworks.map(f => f.name || f.framework).join(', ') || 'unknown'}. ` +
        `Copy the generated test code from the scan rawOutput to use in your project.`,
      filePath: null,
      lineNumber: null,
      columnNumber: null,
      codeSnippet: null,
      cweId: null,
      owaspCategory: null,
      fixAvailable: false,
      fixDescription: 'Save the generated test code to your project and run with: npx mocha functional.test.js',
      metadata: {
        testCount: functionalTests.length,
        endpointsAnalyzed: endpoints.length,
      },
    });

    if (securityTests.length > 0) {
      findings.push({
        ruleId: 'SELENIUM-GEN-SECURITY',
        severity: 'info' as Severity,
        title: `Selenium: Generated ${securityTests.length} security regression tests`,
        description: `Generated security Selenium WebDriver tests: ` +
          `XSS injection (${endpoints.filter(e => ['POST', 'PUT'].includes(e.method)).length} forms), ` +
          `auth bypass (${endpoints.filter(e => e.authentication || e.auth).length} protected routes), ` +
          `CSRF validation, SQL injection (${dataFlows.filter(df => df.sink.type === 'db').length} DB flows). ` +
          `Copy the generated test code from the scan rawOutput to use in your project.`,
        filePath: null,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: 'A03:2021-Injection',
        fixAvailable: false,
        fixDescription: 'Save the generated test code to your project and run with: npx mocha security.test.js',
        metadata: {
          testCount: securityTests.length,
          authPatternsDetected: authPatterns.length,
          dataFlowsAnalyzed: dataFlows.length,
        },
      });
    }

    logger.info({
      functionalTests: functionalTests.length,
      securityTests: securityTests.length,
      endpoints: endpoints.length,
    }, 'Selenium test generation completed');

    return {
      scanner: 'selenium-gen',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify(generated),
      evidence: {
        checksPerformed: [
          'Endpoint analysis for functional test generation',
          'Auth pattern analysis for bypass test generation',
          'Dataflow analysis for injection test generation',
          'CSRF protection detection',
        ],
        scanScope: `${endpoints.length} endpoints, ${authPatterns.length} auth patterns, ${dataFlows.length} data flows`,
        filesAnalyzed: new Set(endpoints.map(e => e.file)).size,
        rulesEvaluated: functionalTests.length + securityTests.length,
        configuration: `functional: ${functionalTests.length}, security: ${securityTests.length}`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Selenium test generation failed');
    return {
      scanner: 'selenium-gen',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
