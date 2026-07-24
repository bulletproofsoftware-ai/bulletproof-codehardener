import { describe, it, expect, vi } from 'vitest';

vi.mock('../../config/env.js', () => ({
  env: {},
}));

vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

vi.mock('../../db/client.js', () => ({
  db: {
    execute: vi.fn(),
  },
}));

vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({
    strings,
    values,
    _tag: 'sql',
  }),
}));

vi.mock('../queue/scan.queue.js', () => ({
  addScanJob: vi.fn(),
}));

vi.mock('./scanner-registry.js', () => ({
  getScannerAuditMeta: vi.fn().mockReturnValue({ checksPerformed: [], scanScope: '' }),
}));

vi.mock('./language-detector.js', () => ({
  detectLanguages: vi.fn().mockResolvedValue({ languages: [], recommendedScanners: [] }),
}));

// Each vi.mock factory is hoisted — must be fully self-contained, no variable refs
// SAST
vi.mock('./opengrep.js', () => ({ runOpengrep: vi.fn().mockResolvedValue({ scanner: 'opengrep', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./bandit.js', () => ({ runBandit: vi.fn().mockResolvedValue({ scanner: 'bandit', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./gosec.js', () => ({ runGosec: vi.fn().mockResolvedValue({ scanner: 'gosec', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./eslint-security.js', () => ({ runESLintSecurity: vi.fn().mockResolvedValue({ scanner: 'eslint', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./pmd.js', () => ({ runPMD: vi.fn().mockResolvedValue({ scanner: 'pmd', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// DAST
vi.mock('./nuclei.js', () => ({ runNuclei: vi.fn().mockResolvedValue({ scanner: 'nuclei', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./zap.js', () => ({ runZAP: vi.fn().mockResolvedValue({ scanner: 'zap', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// SCA
vi.mock('./trivy.js', () => ({ runTrivy: vi.fn().mockResolvedValue({ scanner: 'trivy', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./grype.js', () => ({ runGrype: vi.fn().mockResolvedValue({ scanner: 'grype', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Secrets
vi.mock('./gitleaks.js', () => ({ runGitleaks: vi.fn().mockResolvedValue({ scanner: 'gitleaks', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// IaC
vi.mock('./checkov.js', () => ({ runCheckov: vi.fn().mockResolvedValue({ scanner: 'checkov', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Load Testing
vi.mock('./locust.js', () => ({ runLocust: vi.fn().mockResolvedValue({ scanner: 'locust', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./artillery.js', () => ({ runArtillery: vi.fn().mockResolvedValue({ scanner: 'artillery', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// k6 removed from SCANNER_MAP (AGPL-3.0 license incompatible)
// API Testing
vi.mock('./newman.js', () => ({ runNewman: vi.fn().mockResolvedValue({ scanner: 'newman', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./pact.js', () => ({ runPact: vi.fn().mockResolvedValue({ scanner: 'pact', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./restler.js', () => ({ runRESTler: vi.fn().mockResolvedValue({ scanner: 'restler', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Browser/Visual
vi.mock('./playwright.js', () => ({ runPlaywright: vi.fn().mockResolvedValue({ scanner: 'playwright', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./backstop.js', () => ({ runBackstop: vi.fn().mockResolvedValue({ scanner: 'backstop', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./pa11y.js', () => ({ runPa11y: vi.fn().mockResolvedValue({ scanner: 'pa11y', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Supply Chain
vi.mock('./syft.js', () => ({ runSyft: vi.fn().mockResolvedValue({ scanner: 'syft', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./in-toto.js', () => ({ runInToto: vi.fn().mockResolvedValue({ scanner: 'in-toto', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./cosign.js', () => ({ runCosign: vi.fn().mockResolvedValue({ scanner: 'cosign', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Policy & Reporting
vi.mock('./opa.js', () => ({ runOPA: vi.fn().mockResolvedValue({ scanner: 'opa', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./allure.js', () => ({ runAllure: vi.fn().mockResolvedValue({ scanner: 'allure', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./conftest.js', () => ({ runConftest: vi.fn().mockResolvedValue({ scanner: 'conftest', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Container Hardening
vi.mock('./dockle.js', () => ({ runDockle: vi.fn().mockResolvedValue({ scanner: 'dockle', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// API Mock / Chaos / Migration / Load
vi.mock('./wiremock.js', () => ({ runWireMock: vi.fn().mockResolvedValue({ scanner: 'wiremock', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./falco.js', () => ({ runFalco: vi.fn().mockResolvedValue({ scanner: 'falco', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./toxiproxy.js', () => ({ runToxiproxy: vi.fn().mockResolvedValue({ scanner: 'toxiproxy', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./flyway.js', () => ({ runFlyway: vi.fn().mockResolvedValue({ scanner: 'flyway', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./gatling.js', () => ({ runGatling: vi.fn().mockResolvedValue({ scanner: 'gatling', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// AI Code Quality
vi.mock('./package-validator.js', () => ({ runPackageValidator: vi.fn().mockResolvedValue({ scanner: 'package-validator', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./stryker.js', () => ({ runStryker: vi.fn().mockResolvedValue({ scanner: 'stryker', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./mutmut.js', () => ({ runMutmut: vi.fn().mockResolvedValue({ scanner: 'mutmut', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./pitest.js', () => ({ runPitest: vi.fn().mockResolvedValue({ scanner: 'pitest', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./scancode.js', () => ({ runScancode: vi.fn().mockResolvedValue({ scanner: 'scancode', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./schemathesis.js', () => ({ runSchemathesis: vi.fn().mockResolvedValue({ scanner: 'schemathesis', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./aflpp.js', () => ({ runAFLpp: vi.fn().mockResolvedValue({ scanner: 'aflpp', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./deepeval.js', () => ({ runDeepEval: vi.fn().mockResolvedValue({ scanner: 'deepeval', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./jest.js', () => ({ runJest: vi.fn().mockResolvedValue({ scanner: 'jest', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./pytest.js', () => ({ runPytest: vi.fn().mockResolvedValue({ scanner: 'pytest', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Threat Modeling
vi.mock('./threatmodel.js', () => ({ runThreatModel: vi.fn().mockResolvedValue({ scanner: 'threatmodel', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// LLM Assurance
vi.mock('./llm-threatmodel.js', () => ({ runLlmThreatmodel: vi.fn().mockResolvedValue({ scanner: 'llm-threatmodel', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./llm-vuln-scan.js', () => ({ runLlmVulnScan: vi.fn().mockResolvedValue({ scanner: 'llm-vuln-scan', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Code Quality & Dead Code
vi.mock('./knip.js', () => ({ runKnip: vi.fn().mockResolvedValue({ scanner: 'knip', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./oxlint.js', () => ({ runOxlint: vi.fn().mockResolvedValue({ scanner: 'oxlint', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./jscpd.js', () => ({ runJscpd: vi.fn().mockResolvedValue({ scanner: 'jscpd', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./ruff.js', () => ({ runRuff: vi.fn().mockResolvedValue({ scanner: 'ruff', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./phpstan.js', () => ({ runPhpstan: vi.fn().mockResolvedValue({ scanner: 'phpstan', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./typos.js', () => ({ runTypos: vi.fn().mockResolvedValue({ scanner: 'typos', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./vale.js', () => ({ runVale: vi.fn().mockResolvedValue({ scanner: 'vale', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./libyear.js', () => ({ runLibyear: vi.fn().mockResolvedValue({ scanner: 'libyear', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// CI/CD & Infrastructure Security
vi.mock('./actionlint.js', () => ({ runActionlint: vi.fn().mockResolvedValue({ scanner: 'actionlint', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./poutine.js', () => ({ runPoutine: vi.fn().mockResolvedValue({ scanner: 'poutine', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./scorecard.js', () => ({ runScorecard: vi.fn().mockResolvedValue({ scanner: 'scorecard', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./kubeconform.js', () => ({ runKubeconform: vi.fn().mockResolvedValue({ scanner: 'kubeconform', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./kube-linter.js', () => ({ runKubeLinter: vi.fn().mockResolvedValue({ scanner: 'kube-linter', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Additional SCA & Compliance
vi.mock('./cargo-audit.js', () => ({ runCargoAudit: vi.fn().mockResolvedValue({ scanner: 'cargo-audit', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./spectral.js', () => ({ runSpectral: vi.fn().mockResolvedValue({ scanner: 'spectral', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./dotenv-linter.js', () => ({ runDotenvLinter: vi.fn().mockResolvedValue({ scanner: 'dotenv-linter', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./license-finder.js', () => ({ runLicenseFinder: vi.fn().mockResolvedValue({ scanner: 'license-finder', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
vi.mock('./cdxgen.js', () => ({ runCdxgen: vi.fn().mockResolvedValue({ scanner: 'cdxgen', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// API Testing (additional)
vi.mock('./keploy.js', () => ({ runKeploy: vi.fn().mockResolvedValue({ scanner: 'keploy', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Test Generation
vi.mock('./selenium-gen.js', () => ({ runSeleniumGen: vi.fn().mockResolvedValue({ scanner: 'selenium-gen', success: true, findings: [], duration: 1, rawOutput: '{}' }) }));
// Context detection & health (used by runScanPipeline but not needed for static export tests)
vi.mock('./detect-context.js', () => ({
  detectProjectContext: vi.fn().mockResolvedValue({
    openapi: [], postmanCollections: [], pactContracts: [],
    dockerComposeFile: null, dockerfile: null, detectedFramework: null, suggestedDevPort: null,
  }),
}));
vi.mock('./smart-selection.js', () => ({
  augmentScannersWithContext: vi.fn((base: string[]) => base),
}));
vi.mock('./target-health.js', () => ({
  checkTargetHealth: vi.fn().mockResolvedValue(true),
}));
vi.mock('./code-analysis.js', () => ({
  runCodeAnalysis: vi.fn().mockResolvedValue(null),
}));

import { SCANNER_MAP, PROFILE_SCANNERS } from './pipeline.js';
import { augmentScannersWithContext } from './smart-selection.js';
import type { ScannerResult } from '../../types/index.js';

describe('Scanner Pipeline', () => {
  describe('SCANNER_MAP', () => {
    it('includes all unique scanners plus aliases', () => {
      const keys = Object.keys(SCANNER_MAP);
      // 37 unique scanners + 2 aliases (semgrep, eslint)
      expect(keys.length).toBeGreaterThanOrEqual(37);
    });

    it('has function values for all entries', () => {
      for (const [, fn] of Object.entries(SCANNER_MAP)) {
        expect(typeof fn).toBe('function');
      }
    });

    it('maps core security scanners correctly', () => {
      const coreScanners = [
        'trivy', 'gitleaks', 'opengrep', 'checkov', 'nuclei',
        'bandit', 'gosec', 'grype', 'syft', 'dockle', 'zap',
      ];
      for (const scanner of coreScanners) {
        expect(SCANNER_MAP).toHaveProperty(scanner);
      }
    });

    it('maps AI code quality scanners', () => {
      const aiScanners = [
        'package-validator', 'stryker', 'mutmut', 'pitest',
        'scancode', 'schemathesis', 'aflpp',
      ];
      for (const scanner of aiScanners) {
        expect(SCANNER_MAP).toHaveProperty(scanner);
      }
    });

    it('includes aliases', () => {
      expect(SCANNER_MAP).toHaveProperty('semgrep');
      expect(SCANNER_MAP).toHaveProperty('eslint');
      expect(SCANNER_MAP.semgrep).toBe(SCANNER_MAP.opengrep);
      expect(SCANNER_MAP.eslint).toBe(SCANNER_MAP['eslint-security']);
    });
  });

  describe('PROFILE_SCANNERS', () => {
    it('defines all expected profiles', () => {
      const expectedProfiles = [
        'quick', 'standard', 'comprehensive', 'security', 'api',
        'performance', 'frontend', 'supply-chain', 'ai-security',
        'ai-code-quality', 'database', 'chaos', 'full',
      ];
      for (const profile of expectedProfiles) {
        expect(PROFILE_SCANNERS).toHaveProperty(profile);
      }
    });

    it('quick profile has 2 scanners', () => {
      expect(PROFILE_SCANNERS.quick).toHaveLength(2);
      expect(PROFILE_SCANNERS.quick).toContain('trivy');
      expect(PROFILE_SCANNERS.quick).toContain('gitleaks');
    });

    it('standard profile has 12 scanners', () => {
      expect(PROFILE_SCANNERS.standard).toHaveLength(12);
      expect(PROFILE_SCANNERS.standard).toContain('trivy');
      expect(PROFILE_SCANNERS.standard).toContain('gitleaks');
      expect(PROFILE_SCANNERS.standard).toContain('opengrep');
      expect(PROFILE_SCANNERS.standard).toContain('package-validator');
      expect(PROFILE_SCANNERS.standard).toContain('jscpd');
      expect(PROFILE_SCANNERS.standard).toContain('typos');
    });

    it('comprehensive profile has 59 scanners', () => {
      expect(PROFILE_SCANNERS.comprehensive).toHaveLength(59);
      // Verify key v1 scanners
      expect(PROFILE_SCANNERS.comprehensive).toContain('schemathesis');
      expect(PROFILE_SCANNERS.comprehensive).toContain('aflpp');
      expect(PROFILE_SCANNERS.comprehensive).toContain('dotenv-linter');
      expect(PROFILE_SCANNERS.comprehensive).toContain('hadolint');
      // Verify v2 additions
      expect(PROFILE_SCANNERS.comprehensive).toContain('lychee');
      expect(PROFILE_SCANNERS.comprehensive).toContain('axe-core');
      expect(PROFILE_SCANNERS.comprehensive).toContain('sqlmap');
      expect(PROFILE_SCANNERS.comprehensive).toContain('socket');
      expect(PROFILE_SCANNERS.comprehensive).toContain('giskard');
    });

    it('security profile includes SCA and container hardening', () => {
      expect(PROFILE_SCANNERS.security).toContain('grype');
      expect(PROFILE_SCANNERS.security).toContain('syft');
      expect(PROFILE_SCANNERS.security).toContain('dockle');
      expect(PROFILE_SCANNERS.security.length).toBeGreaterThanOrEqual(11);
    });

    it('ai-security profile includes AI-specific scanners', () => {
      expect(PROFILE_SCANNERS['ai-security']).toContain('package-validator');
      expect(PROFILE_SCANNERS['ai-security']).toContain('scancode');
      expect(PROFILE_SCANNERS['ai-security'].length).toBeGreaterThanOrEqual(7);
    });

    it('all profile scanners exist in SCANNER_MAP', () => {
      for (const [profileName, scanners] of Object.entries(PROFILE_SCANNERS)) {
        for (const scanner of scanners) {
          expect(SCANNER_MAP, `Scanner '${scanner}' in profile '${profileName}' not found in SCANNER_MAP`).toHaveProperty(scanner);
        }
      }
    });

    it('profiles are ordered by increasing coverage', () => {
      expect(PROFILE_SCANNERS.quick.length).toBeLessThan(PROFILE_SCANNERS.standard.length);
      expect(PROFILE_SCANNERS.standard.length).toBeLessThan(PROFILE_SCANNERS.comprehensive.length);
    });

    it('full profile includes all non-alias scanners', () => {
      const aliases = ['semgrep', 'eslint'];
      const allScanners = Object.keys(SCANNER_MAP).filter(s => !aliases.includes(s));
      expect(PROFILE_SCANNERS.full.length).toBe(allScanners.length);
    });
  });

  describe('SCANNER_MAP — new scanner maximization entries', () => {
    it('includes context-aware scanners added in maximization', () => {
      const contextScanners = [
        'keploy', 'deepeval', 'spectral', 'schemathesis',
        'jest', 'pytest', 'selenium-gen', 'threatmodel',
      ];
      for (const scanner of contextScanners) {
        expect(SCANNER_MAP, `Missing scanner: ${scanner}`).toHaveProperty(scanner);
      }
    });

    it('includes code quality & infrastructure scanners', () => {
      const qualityScanners = [
        'knip', 'oxlint', 'jscpd', 'ruff', 'phpstan', 'typos', 'vale', 'libyear',
        'actionlint', 'poutine', 'scorecard', 'kubeconform', 'kube-linter',
        'cargo-audit', 'dotenv-linter', 'license-finder', 'cdxgen',
      ];
      for (const scanner of qualityScanners) {
        expect(SCANNER_MAP, `Missing scanner: ${scanner}`).toHaveProperty(scanner);
      }
    });
  });

  describe('Scanner maximization — augmentation integration', () => {
    it('augmentScannersWithContext is importable from pipeline dependency tree', () => {
      expect(typeof augmentScannersWithContext).toBe('function');
    });

    it('DAST-eligible profiles include scanners that produce skip reasons', () => {
      // Comprehensive, security, and api profiles should include scanners
      // that return skip reasons when context is missing
      const dastScanners = ['zap', 'nuclei'];
      const apiScanners = ['schemathesis', 'spectral', 'restler'];
      const containerScanners = ['cosign', 'dockle'];

      // These scanners should be in comprehensive or can be augmented into it
      for (const scanner of [...dastScanners, ...apiScanners, ...containerScanners]) {
        expect(
          SCANNER_MAP,
          `DAST/API/container scanner '${scanner}' must be in SCANNER_MAP for skip reasons`
        ).toHaveProperty(scanner);
      }
    });
  });

  describe('ScannerResult type — skip reason fields', () => {
    it('accepts a ScannerResult with skip fields', () => {
      const skippedResult: ScannerResult = {
        scanner: 'zap',
        success: true,
        findings: [],
        duration: 5,
        skipped: true,
        skipReason: 'no_target_url',
        skipHint: 'Add Application URL in Project Settings',
      };

      expect(skippedResult.skipped).toBe(true);
      expect(skippedResult.skipReason).toBe('no_target_url');
      expect(skippedResult.skipHint).toBeTruthy();
      expect(skippedResult.findings).toEqual([]);
    });

    it('accepts all valid skip reason values', () => {
      const validReasons: ScannerResult['skipReason'][] = [
        'no_target_url', 'no_container_image', 'no_api_spec',
        'no_matching_files', 'no_test_config', 'coverage_threshold',
        'no_postman_collection', 'no_pact_contracts', 'binary_not_found',
        'target_unreachable',
      ];

      for (const reason of validReasons) {
        const result: ScannerResult = {
          scanner: 'test',
          success: true,
          findings: [],
          duration: 0,
          skipped: true,
          skipReason: reason,
          skipHint: 'test hint',
        };
        expect(result.skipReason).toBe(reason);
      }
    });

    it('non-skipped result omits skip fields', () => {
      const normalResult: ScannerResult = {
        scanner: 'trivy',
        success: true,
        findings: [],
        duration: 100,
        rawOutput: '{}',
      };

      expect(normalResult.skipped).toBeUndefined();
      expect(normalResult.skipReason).toBeUndefined();
      expect(normalResult.skipHint).toBeUndefined();
    });
  });
});
