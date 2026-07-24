import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-opa');

export async function runOPA(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Look for Rego policy files
    const { stdout: policySearch } = await execAsync(
      `find /scan-target -name "*.rego" 2>/dev/null`
    );

    const policyFiles = policySearch.trim().split('\n').filter(Boolean);
    const rawOutputParts: string[] = [];

    if (policyFiles.length === 0) {
      logger.info('No OPA/Rego policy files found');
      return {
        scanner: 'opa',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No .rego policy files found — OPA requires Rego policies to evaluate',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No OPA/Rego policy files found',
      };
    }

    // Check each policy file for issues
    for (const policyFile of policyFiles) {
      // Check policy syntax and best practices
      const { stdout: checkOutput, stderr: checkError } = await execAsync(
        `opa check --strict "${policyFile}" 2>&1 || true`
      );

      const checkResult = checkOutput + checkError;
      rawOutputParts.push(checkResult);

      if (checkResult.includes('error') || checkResult.includes('Error')) {
        const lines = checkResult.split('\n');
        for (const line of lines) {
          if (line.includes('error') || line.includes('Error')) {
            const locationMatch = line.match(/:(\d+):(\d+):/);
            findings.push({
              ruleId: 'OPA-POLICY-ERROR',
              severity: 'high',
              title: 'OPA: Policy Syntax Error',
              description: line.trim(),
              filePath: policyFile.replace('/scan-target/', ''),
              lineNumber: locationMatch ? parseInt(locationMatch[1]) : null,
              columnNumber: locationMatch ? parseInt(locationMatch[2]) : null,
              codeSnippet: null,
              cweId: null,
              owaspCategory: 'A04:2021-Insecure Design',
              fixAvailable: true,
              fixDescription: 'Fix the Rego policy syntax error',
              metadata: {},
            });
          }
        }
      }

      // Check for security-related policy patterns
      const { stdout: policyContent } = await execAsync(`cat "${policyFile}"`);

      // Check for deny rules without default
      if (policyContent.includes('deny[') && !policyContent.includes('default deny')) {
        findings.push({
          ruleId: 'OPA-NO-DEFAULT-DENY',
          severity: 'medium',
          title: 'OPA: Missing Default Deny',
          description: 'Policy has deny rules but no default deny value (fail-open possible)',
          filePath: policyFile.replace('/scan-target/', ''),
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: 'A04:2021-Insecure Design',
          fixAvailable: true,
          fixDescription: 'Add "default deny = false" or "default deny = set()" to make policy explicit',
          metadata: {},
        });
      }

      // Check for allow rules without proper constraints
      const allowMatches = policyContent.match(/allow\s*{[^}]*}/g);
      if (allowMatches) {
        for (const allowBlock of allowMatches) {
          if (allowBlock.includes('allow { true }') || allowBlock.match(/allow\s*{\s*}/)) {
            findings.push({
              ruleId: 'OPA-UNCONDITIONAL-ALLOW',
              severity: 'critical',
              title: 'OPA: Unconditional Allow Rule',
              description: 'Policy contains an unconditional allow rule that bypasses security',
              filePath: policyFile.replace('/scan-target/', ''),
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: 'CWE-862',
              owaspCategory: 'A01:2021-Broken Access Control',
              fixAvailable: true,
              fixDescription: 'Add proper conditions to allow rules',
              metadata: {
                ruleSnippet: allowBlock.substring(0, 100),
              },
            });
          }
        }
      }

      // Run policy tests if test files exist
      const testFile = policyFile.replace('.rego', '_test.rego');
      const { stdout: testExists } = await execAsync(`test -f "${testFile}" && echo "exists" || echo "missing"`);

      if (testExists.trim() === 'exists') {
        const { stdout: testOutput, stderr: testError } = await execAsync(
          `opa test "${policyFile}" "${testFile}" --format json 2>&1 || true`
        );

        try {
          const testResults = JSON.parse(testOutput);
          for (const result of testResults || []) {
            if (result.fail) {
              findings.push({
                ruleId: 'OPA-TEST-FAIL',
                severity: 'high',
                title: `OPA: Policy Test Failed - ${result.name}`,
                description: `Policy test "${result.name}" failed`,
                filePath: testFile.replace('/scan-target/', ''),
                lineNumber: result.location?.row || null,
                columnNumber: result.location?.col || null,
                codeSnippet: null,
                cweId: null,
                owaspCategory: 'A04:2021-Insecure Design',
                fixAvailable: false,
                fixDescription: 'Review and fix the failing policy test',
                metadata: {
                  testName: result.name,
                  package: result.package,
                },
              });
            }
          }
        } catch {
          // Test output wasn't JSON, check for error patterns
          if (testOutput.includes('FAIL') || testError.includes('FAIL')) {
            findings.push({
              ruleId: 'OPA-TESTS-FAILED',
              severity: 'high',
              title: 'OPA: Policy Tests Failed',
              description: 'One or more OPA policy tests failed',
              filePath: policyFile.replace('/scan-target/', ''),
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: null,
              owaspCategory: 'A04:2021-Insecure Design',
              fixAvailable: false,
              fixDescription: 'Review and fix failing policy tests',
              metadata: {},
            });
          }
        }
      } else {
        // No tests for policy
        findings.push({
          ruleId: 'OPA-NO-TESTS',
          severity: 'low',
          title: 'OPA: Policy Missing Tests',
          description: `Policy file "${policyFile}" has no corresponding test file`,
          filePath: policyFile.replace('/scan-target/', ''),
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: 'A04:2021-Insecure Design',
          fixAvailable: true,
          fixDescription: 'Add tests for the policy to ensure correctness',
          metadata: {},
        });
      }
    }

    logger.info({ findingsCount: findings.length, policiesChecked: policyFiles.length }, 'OPA policy analysis completed');

    return {
      scanner: 'opa',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: rawOutputParts.join('\n'),
    };
  } catch (error) {
    logger.error({ error }, 'OPA policy analysis failed');
    return {
      scanner: 'opa',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
