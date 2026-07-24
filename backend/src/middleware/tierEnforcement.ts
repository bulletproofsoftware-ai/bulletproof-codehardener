import type { Request, Response, NextFunction } from 'express';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('tier-enforcement');

/** Plan limits by tier. -1 = unlimited. */
const PLAN_LIMITS: Record<string, { projects: number; scansPerMonth: number }> = {
  free:       { projects: 3,   scansPerMonth: 200 },
  pro:        { projects: 10,  scansPerMonth: -1 },
  team:       { projects: 50,  scansPerMonth: -1 },
  enterprise: { projects: -1,  scansPerMonth: -1 },
};

/** Look up the active plan for a user. Defaults to 'free'. */
async function getUserPlan(userId: string): Promise<string> {
  const result = await db.execute(sql`
    SELECT plan_id FROM subscriptions
    WHERE user_id = ${userId} AND status IN ('active', 'trialing')
    ORDER BY created_at DESC
    LIMIT 1
  `);
  return (result.rows[0] as Record<string, unknown>)?.plan_id as string || 'free';
}

/**
 * Middleware: enforce project-count limit before creating a new project.
 */
export async function enforceProjectLimit(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user!.id;
    const planId = await getUserPlan(userId);
    const limits = PLAN_LIMITS[planId] || PLAN_LIMITS.free;

    if (limits.projects === -1) {
      next();
      return;
    }

    const countResult = await db.execute(sql`
      SELECT COUNT(*)::int as count FROM projects WHERE user_id = ${userId}
    `);
    const current = (countResult.rows[0] as Record<string, unknown>).count as number;

    if (current >= limits.projects) {
      logger.info({ userId, planId, current, limit: limits.projects }, 'Project limit reached');
      res.status(403).json({
        error: 'Project limit reached',
        message: `Your ${planId} plan allows ${limits.projects} projects. You currently have ${current}. Upgrade to create more.`,
        currentUsage: current,
        limit: limits.projects,
        upgradeUrl: '/settings/billing',
      });
      return;
    }

    next();
  } catch (error) {
    logger.error({ error }, 'Tier enforcement check failed — allowing request');
    next();
  }
}

/**
 * Middleware: enforce scan-count-per-month limit before creating a new scan.
 */
export async function enforceScanLimit(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user!.id;
    const planId = await getUserPlan(userId);
    const limits = PLAN_LIMITS[planId] || PLAN_LIMITS.free;

    if (limits.scansPerMonth === -1) {
      next();
      return;
    }

    const countResult = await db.execute(sql`
      SELECT COUNT(*)::int as count
      FROM scans s
      JOIN projects p ON p.id = s.project_id
      WHERE p.user_id = ${userId}
        AND s.created_at >= date_trunc('month', CURRENT_DATE)
    `);
    const current = (countResult.rows[0] as Record<string, unknown>).count as number;

    if (current >= limits.scansPerMonth) {
      logger.info({ userId, planId, current, limit: limits.scansPerMonth }, 'Monthly scan limit reached');
      res.status(403).json({
        error: 'Monthly scan limit reached',
        message: `Your ${planId} plan allows ${limits.scansPerMonth} scans/month. You've used ${current}. Upgrade for unlimited scans.`,
        currentUsage: current,
        limit: limits.scansPerMonth,
        upgradeUrl: '/settings/billing',
      });
      return;
    }

    next();
  } catch (error) {
    logger.error({ error }, 'Tier enforcement check failed — allowing request');
    next();
  }
}
