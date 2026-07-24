import type { Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendSuccess, sendCreated, sendNoContent, sendValidationError } from '../utils/apiResponse.js';
import { NotFoundError } from '../middleware/errorHandler.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('policies-controller');

/** Row shape for COUNT(*) aggregate queries */
interface CountRow {
  count: string;
}

/** Row shape for policy RETURNING * / SELECT */
interface PolicyRow {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  policy_type: string;
  severity_threshold: string;
  auto_fail: boolean;
  is_default: boolean;
  policy_content: string;
  created_at: string;
  updated_at: string;
  rule_count?: string;
}

const createPolicySchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  policyType: z.enum(['yaml', 'rego', 'json']).default('json'),
  severityThreshold: z.enum(['critical', 'high', 'medium', 'low']).default('high'),
  autoFail: z.boolean().default(false),
  isDefault: z.boolean().default(false),
  rules: z.array(z.object({
    ruleType: z.string(),
    condition: z.record(z.unknown()),
    action: z.enum(['block', 'warn', 'ignore']).default('warn'),
    message: z.string().optional(),
  })).optional(),
});

const updatePolicySchema = createPolicySchema.partial();

export async function listPolicies(req: Request, res: Response) {
  const querySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  }).passthrough();
  const { page, limit } = querySchema.parse(req.query);
  const offset = (page - 1) * limit;

  const [policies, countResult] = await Promise.all([
    db.execute(sql`
      SELECT p.*,
        (SELECT COUNT(*) FROM policy_rules pr WHERE pr.policy_id = p.id) as rule_count
      FROM policies p
      WHERE p.user_id = ${req.user!.id}
      ORDER BY p.is_default DESC, p.updated_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `),
    db.execute(sql`
      SELECT COUNT(*) as count FROM policies WHERE user_id = ${req.user!.id}
    `),
  ]);

  const total = parseInt((countResult.rows[0] as unknown as CountRow).count);

  return sendSuccess(res, {
    data: policies.rows,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

export async function getPolicy(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    SELECT p.* FROM policies p
    WHERE p.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Policy not found');
  }

  const policy = result.rows[0] as unknown as PolicyRow;

  // Get rules
  const rules = await db.execute(sql`
    SELECT * FROM policy_rules WHERE policy_id = ${id} ORDER BY order_index
  `);

  return sendSuccess(res, { ...policy, rules: rules.rows });
}

export async function createPolicy(req: Request, res: Response) {
  const validation = createPolicySchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { name, description, policyType, severityThreshold, autoFail, isDefault, rules } = validation.data;

  // If setting as default, unset existing defaults
  if (isDefault) {
    await db.execute(sql`
      UPDATE policies SET is_default = false WHERE user_id = ${req.user!.id} AND is_default = true
    `);
  }

  const result = await db.execute(sql`
    INSERT INTO policies (user_id, name, description, policy_type, severity_threshold, auto_fail, is_default, policy_content)
    VALUES (${req.user!.id}, ${name}, ${description || null}, ${policyType}, ${severityThreshold}, ${autoFail}, ${isDefault}, ${JSON.stringify(rules || [])})
    RETURNING *
  `);

  const policyId = (result.rows[0] as unknown as PolicyRow).id;

  // Insert rules
  if (rules && rules.length > 0) {
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      await db.execute(sql`
        INSERT INTO policy_rules (policy_id, rule_type, condition, action, message, order_index)
        VALUES (${policyId}, ${rule.ruleType}, ${JSON.stringify(rule.condition)}, ${rule.action}, ${rule.message || null}, ${i})
      `);
    }
  }

  logger.info({ policyId }, 'Policy created');
  return sendCreated(res, result.rows[0]);
}

export async function updatePolicy(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const validation = updatePolicySchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const existing = await db.execute(sql`
    SELECT id FROM policies WHERE id = ${id} AND user_id = ${req.user!.id}
  `);

  if (existing.rows.length === 0) {
    throw new NotFoundError('Policy not found');
  }

  const { name, description, severityThreshold, autoFail, isDefault, rules } = validation.data;

  if (isDefault) {
    await db.execute(sql`
      UPDATE policies SET is_default = false WHERE user_id = ${req.user!.id} AND is_default = true
    `);
  }

  const result = await db.execute(sql`
    UPDATE policies
    SET name = COALESCE(${name ?? null}, name),
        description = COALESCE(${description ?? null}, description),
        severity_threshold = COALESCE(${severityThreshold ?? null}, severity_threshold),
        auto_fail = COALESCE(${autoFail ?? null}, auto_fail),
        is_default = COALESCE(${isDefault ?? null}, is_default),
        updated_at = NOW()
    WHERE id = ${id}
    RETURNING *
  `);

  // Update rules if provided
  if (rules) {
    await db.execute(sql`DELETE FROM policy_rules WHERE policy_id = ${id}`);
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      await db.execute(sql`
        INSERT INTO policy_rules (policy_id, rule_type, condition, action, message, order_index)
        VALUES (${id}, ${rule.ruleType}, ${JSON.stringify(rule.condition)}, ${rule.action}, ${rule.message || null}, ${i})
      `);
    }
  }

  return sendSuccess(res, result.rows[0]);
}

export async function deletePolicy(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    DELETE FROM policies WHERE id = ${id} AND user_id = ${req.user!.id}
    RETURNING id
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Policy not found');
  }

  logger.info({ policyId: id }, 'Policy deleted');
  return sendNoContent(res);
}
