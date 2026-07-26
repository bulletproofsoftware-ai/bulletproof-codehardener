import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { readFile, writeFile, mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';
import type { Severity } from '../../types/index.js';

const execAsync = promisify(exec);

/**
 * Quote a value for safe interpolation into a /bin/sh command line.
 *
 * These scans run through promisify(exec), which is `sh -c`. The previous code
 * escaped only the double quote, but inside a double-quoted shell word `$(...)`
 * and backticks are still evaluated — so a project whose configured username
 * was `x$(id > /tmp/pwned)` executed that command on the scanner host. Wrapping
 * in single quotes disables every form of expansion; the only character that
 * needs handling is the single quote itself, closed and reopened around an
 * escaped one (CodeQL js/indirect-command-line-injection).
 */
function shQuote(value: string): string {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

const logger = createLogger('scanner-zap');

const ZAP_HOME = '/app/tools/ZAP_2.16.0';
const ZAP_PORT = 8090;

interface ZAPAlert {
  pluginid: string;
  alertRef: string;
  alert: string;
  name: string;
  riskcode: string;
  confidence: string;
  riskdesc: string;
  desc: string;
  instances: Array<{
    uri: string;
    method: string;
    param?: string;
    attack?: string;
    evidence?: string;
  }>;
  count: string;
  solution: string;
  otherinfo?: string;
  reference?: string;
  cweid: string;
  wascid: string;
  sourceid: string;
}

interface ZAPSite {
  '@name': string;
  '@host': string;
  '@port': string;
  '@ssl': string;
  alerts: ZAPAlert[];
}

interface ZAPResult {
  '@version': string;
  '@generated': string;
  site: ZAPSite[];
}

function mapSeverity(riskcode: string): Severity {
  const map: Record<string, Severity> = {
    '3': 'critical',
    '2': 'high',
    '1': 'medium',
    '0': 'low',
  };
  return map[riskcode] || 'info';
}

function parseAlerts(stdout: string): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  if (!stdout.trim() || stdout.trim() === '{}') return findings;

  const result: ZAPResult = JSON.parse(stdout);

  for (const site of result.site || []) {
    for (const alert of site.alerts || []) {
      for (const instance of alert.instances || []) {
        findings.push({
          ruleId: alert.pluginid,
          severity: mapSeverity(alert.riskcode),
          title: `ZAP: ${alert.name}`,
          description: alert.desc,
          filePath: instance.uri,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: instance.attack
            ? `Attack: ${instance.attack}\nEvidence: ${instance.evidence || 'N/A'}`
            : null,
          cweId: alert.cweid ? `CWE-${alert.cweid}` : null,
          owaspCategory: getOWASPFromZAP(alert.cweid, alert.wascid),
          fixAvailable: true,
          fixDescription: alert.solution,
          metadata: {
            confidence: alert.confidence,
            method: instance.method,
            param: instance.param,
            attack: instance.attack,
            evidence: instance.evidence,
            reference: alert.reference,
            riskDescription: alert.riskdesc,
          },
        });
      }
    }
  }

  return findings;
}

export async function runZAP(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];
  const targetUrl = jobData.targetUrl || process.env.ZAP_TARGET_URL;
  // Declared out here so the finally block below can remove it on every path.
  let authContextDir: string | null = null;

  if (!targetUrl || !targetUrl.startsWith('http')) {
    logger.info('No HTTP target URL available for ZAP DAST scan');
    return {
      scanner: 'zap',
      success: true,
      skipped: true,
      skipReason: 'no_target_url',
      skipHint: 'Add Application URL in Project Settings to enable DAST scanning',
      findings: [],
      duration: Date.now() - startTime,
      rawOutput: 'No HTTP target URL specified (ZAP requires a running web application)',
    };
  }

  try {
    const outputFile = `/tmp/zap-report-${Date.now()}.json`;
    let scanMode = 'baseline';
    const authConfig = jobData.authConfig;
    const hasAuth = !!(authConfig?.loginUrl && authConfig?.username && authConfig?.password);

    // Check if zap-baseline.py exists (present in ZAP crossplatform package)
    const baselineScript = `${ZAP_HOME}/zap-baseline.py`;
    const fullScanScript = `${ZAP_HOME}/zap-full-scan.py`;
    const apiScanScript = `${ZAP_HOME}/zap-api-scan.py`;
    const hasBaseline = existsSync(baselineScript);
    const hasFullScan = existsSync(fullScanScript);
    const hasApiScan = existsSync(apiScanScript);

    // Build ZAP form-handler auth flags when auth config is available
    let authZFlags = '';
    if (hasAuth) {
      // Only the double quote is escaped here because these values sit inside
      // ZAP's own -config "value" syntax; the whole -z argument is shQuote'd
      // before it reaches the shell, so shell metacharacters cannot escape.
      const usernameField = authConfig.usernameField.replace(/"/g, '\\"');
      const passwordField = authConfig.passwordField.replace(/"/g, '\\"');
      const username = authConfig.username.replace(/"/g, '\\"');
      const password = authConfig.password.replace(/"/g, '\\"');
      authZFlags = [
        `-config formhandler.fields.field(0).fieldName="${usernameField}"`,
        `-config formhandler.fields.field(0).value="${username}"`,
        `-config formhandler.fields.field(0).enabled=true`,
        `-config formhandler.fields.field(1).fieldName="${passwordField}"`,
        `-config formhandler.fields.field(1).value="${password}"`,
        `-config formhandler.fields.field(1).enabled=true`,
      ].join(' ');
      logger.info({ loginUrl: authConfig.loginUrl }, 'ZAP: auth config provided, enabling form-handler auto-fill');
    }

    // Build the -z flags string (always includes api.disablekey, plus optional auth)
    const zFlags = shQuote(
      authZFlags
        ? `-config api.disablekey=true ${authZFlags}`
        : '-config api.disablekey=true'
    );

    // When auth is configured, write a ZAP context XML for authenticated scanning
    let contextFileArg = '';
    if (hasAuth) {
      const contextXml = buildZapAuthContext(authConfig, targetUrl);
      // This file contains the target's authentication configuration —
      // credentials included. `/tmp/zap-auth-context-<Date.now()>.context` is
      // guessable to the millisecond, so another local user could pre-create
      // the path as a symlink and capture them, or read the file once written.
      // mkdtemp gives a 0700 directory with a random suffix, created
      // atomically (CodeQL js/insecure-temporary-file).
      authContextDir = await mkdtemp(join(tmpdir(), 'zap-auth-'));
      const contextPath = join(authContextDir, 'auth.context');
      await writeFile(contextPath, contextXml, 'utf-8');
      contextFileArg = `-n ${shQuote(contextPath)}`;
    }

    // Use user-configured spec, auto-detected spec, or env var
    const openApiSpec = jobData.openapiSpecPath
      || jobData.detectedSpecs?.openapi?.[0]
      || process.env.ZAP_OPENAPI_SPEC;

    if (hasApiScan && openApiSpec) {
      // API scan mode — validates OpenAPI/Swagger spec endpoints
      scanMode = 'api-scan';
      logger.info({ targetUrl, spec: openApiSpec, authenticated: hasAuth }, 'Running ZAP API scan');
      await execAsync(
        `timeout 300 python3 ${shQuote(apiScanScript)} -t ${shQuote(targetUrl)} -f openapi -J ${shQuote(outputFile)} -z ${zFlags} ${contextFileArg} 2>/dev/null; true`,
        { maxBuffer: 50 * 1024 * 1024, timeout: 330000 }
      );
    } else if (hasAuth && hasFullScan) {
      // Authenticated full scan — active + passive scanning with form auto-fill
      scanMode = 'full-authenticated';
      logger.info({ targetUrl }, 'Running ZAP full authenticated scan');
      await execAsync(
        `timeout 300 python3 ${shQuote(fullScanScript)} -t ${shQuote(targetUrl)} -J ${shQuote(outputFile)} -a -z ${zFlags} ${contextFileArg} 2>/dev/null; true`,
        { maxBuffer: 50 * 1024 * 1024, timeout: 330000 }
      );
    } else if (hasBaseline) {
      // Baseline scan — passive scanning + spider + optional ajax spider
      scanMode = hasAuth ? 'baseline-authenticated' : 'baseline';
      logger.info({ targetUrl, authenticated: hasAuth }, 'Running ZAP baseline scan');
      await execAsync(
        `timeout 300 python3 ${shQuote(baselineScript)} -t ${shQuote(targetUrl)} -J ${shQuote(outputFile)} -a -z ${zFlags} ${contextFileArg} 2>/dev/null; true`,
        { maxBuffer: 50 * 1024 * 1024, timeout: 330000 }
      );
    } else {
      // Fallback: use ZAP daemon mode with API for active + passive scanning
      scanMode = 'daemon-active';
      logger.info({ targetUrl }, 'Running ZAP active scan via daemon mode');

      // Start ZAP daemon
      void execAsync(
        `${ZAP_HOME}/zap.sh -daemon -port ${ZAP_PORT} -config api.disablekey=true -config spider.maxDuration=2 -config scanner.maxScanDurationInMins=3 2>/dev/null &`,
        { timeout: 30000 }
      ).catch(() => {});

      // Wait for ZAP to start
      let zapReady = false;
      for (let i = 0; i < 30; i++) {
        try {
          await execAsync(`curl -sf http://localhost:${ZAP_PORT}/JSON/core/view/version/ 2>/dev/null`, { timeout: 3000 });
          zapReady = true;
          break;
        } catch {
          await new Promise(resolve => setTimeout(resolve, 2000));
        }
      }

      if (!zapReady) {
        // Fall back to quick scan if daemon won't start
        scanMode = 'quick-fallback';
        logger.warn('ZAP daemon failed to start, falling back to quick scan');
        await execAsync(
          `timeout 300 ${ZAP_HOME}/zap.sh -cmd -quickurl ${targetUrl} -quickout ${outputFile} -quickprogress -config api.disablekey=true 2>/dev/null; true`,
          { maxBuffer: 50 * 1024 * 1024, timeout: 330000 }
        );
      } else {
        try {
          // Spider the target
          logger.info('ZAP: Spidering target');
          await execAsync(
            `curl -sf "http://localhost:${ZAP_PORT}/JSON/spider/action/scan/?url=${encodeURIComponent(targetUrl)}&maxChildren=20&recurse=true" 2>/dev/null`,
            { timeout: 10000 }
          );

          // Wait for spider to finish (max 60s)
          for (let i = 0; i < 30; i++) {
            const { stdout: status } = await execAsync(
              `curl -sf "http://localhost:${ZAP_PORT}/JSON/spider/view/status/" 2>/dev/null || echo '{"status":"100"}'`,
              { timeout: 5000 }
            );
            if (JSON.parse(status).status === '100') break;
            await new Promise(resolve => setTimeout(resolve, 2000));
          }

          // Run active scan
          logger.info('ZAP: Running active scan');
          await execAsync(
            `curl -sf "http://localhost:${ZAP_PORT}/JSON/ascan/action/scan/?url=${encodeURIComponent(targetUrl)}&recurse=true" 2>/dev/null`,
            { timeout: 10000 }
          );

          // Wait for active scan (max 180s)
          for (let i = 0; i < 90; i++) {
            const { stdout: status } = await execAsync(
              `curl -sf "http://localhost:${ZAP_PORT}/JSON/ascan/view/status/" 2>/dev/null || echo '{"status":"100"}'`,
              { timeout: 5000 }
            );
            if (JSON.parse(status).status === '100') break;
            await new Promise(resolve => setTimeout(resolve, 2000));
          }

          // Export results
          await execAsync(
            `curl -sf "http://localhost:${ZAP_PORT}/OTHER/core/other/jsonreport/" > ${outputFile} 2>/dev/null`,
            { timeout: 10000, maxBuffer: 50 * 1024 * 1024 }
          );
        } finally {
          // Shutdown ZAP daemon
          await execAsync(
            `curl -sf "http://localhost:${ZAP_PORT}/JSON/core/action/shutdown/" 2>/dev/null; true`,
            { timeout: 5000 }
          ).catch(() => {});
        }
      }
    }

    // Parse results
    let stdout = '';
    try {
      stdout = await readFile(outputFile, 'utf-8');
    } catch {
      stdout = '{}';
    }

    findings.push(...parseAlerts(stdout));

    logger.info({ findingsCount: findings.length, scanMode, authenticated: hasAuth }, 'ZAP scan completed');

    const baseChecks = scanMode === 'api-scan'
      ? ['OpenAPI endpoint validation', 'Passive security scanning', 'API-specific vulnerability detection', 'Authentication testing']
      : scanMode === 'daemon-active'
      ? ['Spider/crawl discovery', 'Active vulnerability scanning', 'Passive security scanning', 'SQL injection testing', 'XSS detection', 'CSRF testing', 'Path traversal testing']
      : scanMode.includes('full')
      ? ['Spider/crawl discovery', 'Active vulnerability scanning', 'Passive security scanning', 'SQL injection testing', 'XSS detection', 'CSRF testing', 'Path traversal testing', 'Alpha passive rules']
      : ['Passive security scanning', 'Spider/crawl discovery', 'Alpha passive rules', 'Security header analysis', 'Cookie security', 'Information disclosure'];
    if (hasAuth) {
      baseChecks.push('Form-based authentication auto-fill', 'Authenticated endpoint discovery');
    }

    return {
      scanner: 'zap',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: baseChecks,
        scanScope: `DAST scan of ${targetUrl} using ${scanMode} mode`,
        configuration: `ZAP 2.16.0, mode: ${scanMode}, target: ${targetUrl}${hasAuth ? ', authenticated via form handler' : ''}`,
        authenticationStatus: hasAuth ? 'authenticated' : 'unauthenticated',
      },
    };
  } catch (error) {
    logger.error({ error }, 'ZAP scan failed');
    return {
      scanner: 'zap',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  } finally {
    // The context file holds the target's credentials, so it must not outlive
    // the scan on either the success or the failure path.
    if (authContextDir) {
      await rm(authContextDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}

/** Build a ZAP context XML file for form-based authentication */
function buildZapAuthContext(
  auth: NonNullable<ScanJobData['authConfig']>,
  targetUrl: string,
): string {
  // Escape XML special characters in user-provided values
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const loginUrl = esc(auth.loginUrl);
  const usernameField = esc(auth.usernameField);
  const passwordField = esc(auth.passwordField);
  const username = esc(auth.username);
  const password = esc(auth.password);
  const successIndicator = esc(auth.successIndicator);
  const targetHost = esc(new URL(targetUrl).hostname.replace(/\./g, '\\.'));

  return `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<configuration>
  <context>
    <name>AuthContext</name>
    <desc>Auto-generated auth context for Code Hardener DAST scan</desc>
    <inscope>true</inscope>
    <incregexes>${targetHost}.*</incregexes>
    <tech><include>ALL</include></tech>
    <authentication>
      <type>2</type>
      <loggedin>${successIndicator}</loggedin>
      <form>
        <loginurl>${loginUrl}</loginurl>
        <loginbody>${usernameField}={%username%}&amp;${passwordField}={%password%}</loginbody>
      </form>
    </authentication>
    <users>
      <user>
        <name>scanner</name>
        <credentials>${usernameField}=${username}&amp;${passwordField}=${password}</credentials>
      </user>
    </users>
  </context>
</configuration>`;
}

function getOWASPFromZAP(cweid: string, wascid: string): string | null {
  // CWE-based mapping first (more specific)
  const cweToOWASP: Record<string, string> = {
    '79': 'A03:2021-Injection',    // XSS
    '89': 'A03:2021-Injection',    // SQL Injection
    '78': 'A03:2021-Injection',    // OS Command Injection
    '90': 'A03:2021-Injection',    // LDAP Injection
    '91': 'A03:2021-Injection',    // XML Injection
    '22': 'A01:2021-Broken Access Control',  // Path Traversal
    '352': 'A01:2021-Broken Access Control', // CSRF
    '601': 'A01:2021-Broken Access Control', // Open Redirect
    '200': 'A01:2021-Broken Access Control', // Information Exposure
    '614': 'A07:2021-Identification and Authentication Failures', // Cookie without Secure
    '311': 'A02:2021-Cryptographic Failures', // Missing encryption
    '319': 'A02:2021-Cryptographic Failures', // Cleartext transmission
    '327': 'A02:2021-Cryptographic Failures', // Broken crypto
    '16': 'A05:2021-Security Misconfiguration',   // Config
    '693': 'A05:2021-Security Misconfiguration',   // Protection mechanism failure
    '1021': 'A05:2021-Security Misconfiguration',  // Clickjacking
    '829': 'A08:2021-Software and Data Integrity Failures', // Untrusted functionality
  };

  if (cweid && cweToOWASP[cweid]) {
    return cweToOWASP[cweid];
  }

  // WASC-based fallback
  const wascToOWASP: Record<string, string> = {
    '8': 'A03:2021-Injection',
    '19': 'A03:2021-Injection',
    '31': 'A03:2021-Injection',
    '15': 'A01:2021-Broken Access Control',
    '13': 'A05:2021-Security Misconfiguration',
  };
  return wascToOWASP[wascid] || null;
}
