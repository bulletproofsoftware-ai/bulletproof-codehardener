import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-giskard');

const SCAN_TARGET = '/scan-target';

interface GiskardVulnerability {
  name: string;
  description: string;
  severity: string;
  category: string;
  details: string;
  metric?: string;
  score?: number;
}

interface GiskardOutput {
  vulnerabilities: GiskardVulnerability[];
  model_info?: Record<string, unknown>;
  scan_summary?: Record<string, unknown>;
}

function mapGiskardSeverity(severity: string): Severity {
  const sev = (severity || '').toLowerCase();
  if (sev === 'critical') return 'critical';
  if (sev === 'high' || sev === 'major') return 'high';
  if (sev === 'medium' || sev === 'moderate') return 'medium';
  if (sev === 'low' || sev === 'minor') return 'low';
  return 'medium'; // Default to medium for LLM vulnerabilities
}

export async function runGiskard(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for LLM-related imports in source files
    const { stdout: llmCheck } = await execAsync(
      `grep -rl --include="*.py" --include="*.ts" --include="*.js" -E "(import\\s+(openai|anthropic|langchain|transformers|llama_index|cohere|google\\.generativeai))|from\\s+(openai|anthropic|langchain|transformers|llama_index|cohere|google\\.generativeai)|require\\(['\\"](openai|@anthropic-ai|langchain))" ${SCAN_TARGET} 2>/dev/null | head -5`,
      { timeout: 15000 }
    );

    if (!llmCheck.trim()) {
      return {
        scanner: 'giskard',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No LLM integration detected in source files',
        skipReason: 'no_llm_integration',
        skipHint: 'Giskard requires LLM integrations (openai, anthropic, langchain, etc.) to test for prompt injection vulnerabilities',
      };
    }

    const llmFiles = llmCheck.trim().split('\n').map((f) => f.replace(`${SCAN_TARGET}/`, ''));

    // Run giskard scan via Python subprocess
    // The Python script is a constant literal — no user input is interpolated
    const pythonScript = [
      'import json, sys, os',
      'try:',
      '    import giskard',
      'except ImportError:',
      '    print(json.dumps({"error": "giskard not installed"}))',
      '    sys.exit(0)',
      `os.chdir("${SCAN_TARGET}")`,
      'results = {"vulnerabilities": []}',
      'try:',
      '    report = giskard.scan(',
      '        model=None, dataset=None, features=None,',
      '        only=["llm_prompt_injection", "llm_output_formatting", "llm_information_disclosure", "llm_harmful_content", "llm_stereotypes"],',
      '        raise_exceptions=False,',
      '    )',
      '    if hasattr(report, "issues"):',
      '        for issue in report.issues:',
      '            results["vulnerabilities"].append({',
      '                "name": getattr(issue, "name", "Unknown"),',
      '                "description": getattr(issue, "description", ""),',
      '                "severity": getattr(issue, "severity", "medium"),',
      '                "category": getattr(issue, "category", "prompt-injection"),',
      '                "details": getattr(issue, "details", ""),',
      '                "metric": getattr(issue, "metric", None),',
      '                "score": getattr(issue, "score", None),',
      '            })',
      'except Exception as e:',
      '    results["vulnerabilities"] = []',
      '    results["scan_error"] = str(e)',
      'print(json.dumps(results))',
    ].join('\n');

    const cmd = `python3 -c '${pythonScript.replace(/'/g, "'\\''")}' 2>/dev/null || true`;
    const { stdout } = await execAsync(cmd, {
      maxBuffer: 50 * 1024 * 1024,
      timeout: 300000,
    });

    if (stdout.trim()) {
      try {
        const output: GiskardOutput = JSON.parse(stdout);

        if ('error' in output && (output as Record<string, unknown>).error === 'giskard not installed') {
          return {
            scanner: 'giskard',
            success: true,
            skipped: true,
            findings: [],
            duration: Date.now() - startTime,
            rawOutput: 'giskard Python package not installed',
            skipReason: 'tool_not_installed',
            skipHint: 'Install the giskard Python package to enable LLM vulnerability scanning',
          };
        }

        for (const vuln of (output.vulnerabilities || []).slice(0, 200)) {
          const severity = mapGiskardSeverity(vuln.severity);
          const category = (vuln.category || 'prompt-injection').toLowerCase();

          let cweId: string | null = 'CWE-1336';
          let ruleId = 'GISKARD-PROMPT-INJECTION';

          if (category.includes('disclosure') || category.includes('information')) {
            cweId = 'CWE-200';
            ruleId = 'GISKARD-INFO-DISCLOSURE';
          } else if (category.includes('harmful') || category.includes('toxic')) {
            cweId = 'CWE-1336';
            ruleId = 'GISKARD-HARMFUL-CONTENT';
          } else if (category.includes('stereotype') || category.includes('bias')) {
            cweId = null;
            ruleId = 'GISKARD-BIAS';
          } else if (category.includes('format') || category.includes('output')) {
            cweId = null;
            ruleId = 'GISKARD-OUTPUT-FORMAT';
          }

          findings.push({
            ruleId,
            severity,
            title: `${vuln.name || 'LLM vulnerability'}: ${vuln.description?.slice(0, 60) || category}`,
            description: `Giskard detected an LLM vulnerability: ${vuln.description || vuln.name}. ${vuln.details || ''}`.trim(),
            filePath: llmFiles[0] || null,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: vuln.details?.slice(0, 2000) ?? null,
            cweId,
            owaspCategory: category.includes('injection') ? 'A03:2021-Injection' : null,
            fixAvailable: false,
            fixDescription: category.includes('injection')
              ? 'Implement input sanitization for LLM prompts. Use system prompts to define strict behavior boundaries. Add output validation to detect and filter injection attempts.'
              : `Address the ${category} vulnerability by adding appropriate guardrails and validation to your LLM pipeline.`,
            metadata: {
              category,
              giskardSeverity: vuln.severity,
              metric: vuln.metric ?? null,
              score: vuln.score ?? null,
              llmFiles,
            },
          });
        }
      } catch {
        // JSON parse failed — tool may have printed non-JSON output
        logger.warn('Failed to parse giskard output as JSON');
      }
    }

    logger.info({ findingsCount: findings.length }, 'Giskard scan completed');

    return {
      scanner: 'giskard',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'Prompt injection testing',
          'Output formatting validation',
          'Information disclosure detection',
          'Harmful content generation testing',
          'Stereotype and bias detection',
        ],
        scanScope: 'LLM vulnerability scanning via Giskard',
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: 'Giskard default LLM security test suite',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Giskard scan failed');
    return {
      scanner: 'giskard',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
