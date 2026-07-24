import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../utils/logger.js';
import type { NormalizedFinding, Severity } from '../../types/index.js';

const logger = createLogger('policy-evaluator');

export interface PolicyViolation {
  policyId: string;
  policyName: string;
  ruleId: string;
  ruleType: string;
  action: 'block' | 'warn' | 'ignore';
  message: string;
}

export interface PolicyEvaluationResult {
  passed: boolean;
  shouldBlock: boolean;
  violations: PolicyViolation[];
  warnings: PolicyViolation[];
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * Evaluate findings against all active policies for a user.
 */
export async function evaluateFindings(
  userId: string,
  projectId: string,
  findings: NormalizedFinding[]
): Promise<PolicyEvaluationResult> {
  const policies = await db.execute(sql`
    SELECT * FROM policies WHERE user_id = ${userId} AND is_active = true
    ORDER BY is_default DESC, created_at ASC
  `);

  const violations: PolicyViolation[] = [];
  const warnings: PolicyViolation[] = [];
  let shouldBlock = false;

  for (const policy of policies.rows as Record<string, unknown>[]) {
    const rules = await db.execute(sql`
      SELECT * FROM policy_rules WHERE policy_id = ${policy.id} AND enabled = true ORDER BY order_index
    `);

    for (const rule of rules.rows as Record<string, unknown>[]) {
      const ruleType = rule.rule_type as string;
      const condition = rule.condition as Record<string, unknown>;
      const action = rule.action as 'block' | 'warn' | 'ignore';

      const violation = evaluateRule(ruleType, condition, findings);

      if (violation) {
        const v: PolicyViolation = {
          policyId: policy.id as string,
          policyName: policy.name as string,
          ruleId: rule.id as string,
          ruleType,
          action,
          message: (rule.message as string) || violation,
        };

        if (action === 'block') {
          violations.push(v);
          shouldBlock = true;
        } else if (action === 'warn') {
          warnings.push(v);
        }
      }
    }

    // Check severity threshold from policy level
    const threshold = policy.severity_threshold as string;
    if (threshold && policy.auto_fail) {
      const thresholdLevel = SEVERITY_ORDER[threshold as Severity] || 0;
      const hasViolating = findings.some(f => SEVERITY_ORDER[f.severity] >= thresholdLevel);

      if (hasViolating) {
        shouldBlock = true;
        violations.push({
          policyId: policy.id as string,
          policyName: policy.name as string,
          ruleId: 'severity-threshold',
          ruleType: 'severity_threshold',
          action: 'block',
          message: `Findings at or above ${threshold} severity found (auto-fail enabled)`,
        });
      }
    }
  }

  const passed = violations.length === 0;
  logger.info(
    { projectId, passed, violations: violations.length, warnings: warnings.length },
    'Policy evaluation complete'
  );

  return { passed, shouldBlock, violations, warnings };
}

function evaluateRule(
  ruleType: string,
  condition: Record<string, unknown>,
  findings: NormalizedFinding[]
): string | null {
  switch (ruleType) {
    case 'severity_threshold': {
      const severity = condition.severity as string;
      const maxAllowed = (condition.max_allowed as number) ?? 0;
      const count = findings.filter(f => f.severity === severity).length;
      if (count > maxAllowed) {
        return `Found ${count} ${severity} findings (max allowed: ${maxAllowed})`;
      }
      return null;
    }

    case 'scanner_required': {
      // This would require scan-level info, skip for finding-only eval
      return null;
    }

    case 'no_secrets': {
      const secretFindings = findings.filter(
        f => f.cweId === 'CWE-798' || f.ruleId?.includes('secret') || f.ruleId?.includes('key')
      );
      if (secretFindings.length > 0) {
        return `Found ${secretFindings.length} hardcoded secrets`;
      }
      return null;
    }

    case 'max_total_findings': {
      const max = (condition.max as number) ?? 100;
      if (findings.length > max) {
        return `Total findings (${findings.length}) exceeds maximum (${max})`;
      }
      return null;
    }

    case 'cwe_blocklist': {
      const blockedCwes = (condition.cwes as string[]) || [];
      const blocked = findings.filter(f => f.cweId && blockedCwes.includes(f.cweId));
      if (blocked.length > 0) {
        return `Found ${blocked.length} findings with blocked CWE IDs: ${blocked.map(f => f.cweId).join(', ')}`;
      }
      return null;
    }

    default:
      return null;
  }
}
