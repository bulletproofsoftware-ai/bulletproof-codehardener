import { Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { apiSuccess, apiError } from '../utils/apiResponse.js';

interface Notification {
  id: string;
  user_id: string;
  type: 'info' | 'warning' | 'error' | 'success';
  title: string;
  message: string;
  link: string | null;
  read: boolean;
  created_at: Date;
  updated_at: Date;
}

/** Row shape returned by SELECT id, type, title, message, link, read, created_at FROM notifications */
interface NotificationListRow {
  id: string;
  type: string;
  title: string;
  message: string;
  link: string | null;
  read: boolean;
  created_at: string;
}

/** Row shape for COUNT(*) aggregate queries */
interface CountRow {
  count: string;
}

/** Row shape for notification_preferences SELECT */
interface NotificationPreferencesRow {
  preferences: {
    slackConnected?: boolean;
    slackChannel?: string | null;
    settings?: Array<{ id: string; email: boolean; slack: boolean }>;
  };
}

/** Row shape for RETURNING id */
interface IdRow {
  id: string;
}

// List notifications
export async function listNotifications(req: Request, res: Response) {
  const userId = req.user!.id;
  const querySchema = z.object({
    unreadOnly: z.enum(['true', 'false']).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(50),
  }).passthrough();
  const { unreadOnly: unreadOnlyStr, limit } = querySchema.parse(req.query);
  const unreadOnly = unreadOnlyStr === 'true';

  const result = unreadOnly
    ? await db.execute(sql`
        SELECT id, type, title, message, link, read, created_at
        FROM notifications
        WHERE user_id = ${userId} AND read = false
        ORDER BY created_at DESC
        LIMIT ${limit}
      `)
    : await db.execute(sql`
        SELECT id, type, title, message, link, read, created_at
        FROM notifications
        WHERE user_id = ${userId}
        ORDER BY created_at DESC
        LIMIT ${limit}
      `);

  const notifications = (result.rows as unknown as NotificationListRow[]).map((row) => ({
    id: row.id,
    type: row.type,
    title: row.title,
    message: row.message,
    link: row.link,
    read: row.read,
    createdAt: new Date(row.created_at).toISOString(),
  }));

  return apiSuccess(res, notifications);
}

// Get unread count
export async function getUnreadCount(req: Request, res: Response) {
  const userId = req.user!.id;

  const result = await db.execute(sql`
    SELECT COUNT(*) as count FROM notifications WHERE user_id = ${userId} AND read = false
  `);

  return apiSuccess(res, {
    count: parseInt((result.rows[0] as unknown as CountRow)?.count ?? '0', 10),
  });
}

// Mark notification as read
export async function markAsRead(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const result = await db.execute(sql`
    UPDATE notifications
    SET read = true, updated_at = NOW()
    WHERE id = ${id} AND user_id = ${userId}
    RETURNING id
  `);

  if (result.rows.length === 0) {
    return apiError(res, 'Notification not found', 404);
  }

  return res.status(204).send();
}

// Mark all as read
export async function markAllAsRead(req: Request, res: Response) {
  const userId = req.user!.id;

  const result = await db.execute(sql`
    UPDATE notifications
    SET read = true, updated_at = NOW()
    WHERE user_id = ${userId} AND read = false
  `);

  return apiSuccess(res, { updated: result.rowCount ?? 0 });
}

// Delete notification
export async function deleteNotification(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const result = await db.execute(sql`
    DELETE FROM notifications WHERE id = ${id} AND user_id = ${userId} RETURNING id
  `);

  if (result.rows.length === 0) {
    return apiError(res, 'Notification not found', 404);
  }

  return res.status(204).send();
}

// Delete all read notifications
export async function deleteAllRead(req: Request, res: Response) {
  const userId = req.user!.id;

  const result = await db.execute(sql`
    DELETE FROM notifications WHERE user_id = ${userId} AND read = true
  `);

  return apiSuccess(res, { deleted: result.rowCount ?? 0 });
}

// Default notification settings
const DEFAULT_NOTIFICATION_SETTINGS = [
  {
    id: 'scan_completed',
    label: 'Scan completed',
    description: 'When a security scan finishes',
    email: true,
    slack: true,
  },
  {
    id: 'critical_findings',
    label: 'Critical findings detected',
    description: 'When critical severity issues are found',
    email: true,
    slack: true,
  },
  {
    id: 'high_findings',
    label: 'High severity findings detected',
    description: 'When high severity issues are found',
    email: true,
    slack: true,
  },
  {
    id: 'medium_findings',
    label: 'Medium severity findings detected',
    description: 'When medium severity issues are found',
    email: false,
    slack: false,
  },
  {
    id: 'weekly_summary',
    label: 'Weekly security summary',
    description: 'Summary of security status across all projects',
    email: false,
    slack: false,
  },
  {
    id: 'billing_alerts',
    label: 'Account and billing alerts',
    description: 'Important account and billing notifications',
    email: true,
    slack: false,
  },
];

// Get notification preferences
export async function getPreferences(req: Request, res: Response) {
  const userId = req.user!.id;

  const result = await db.execute(sql`
    SELECT preferences FROM notification_preferences WHERE user_id = ${userId}
  `);

  if (result.rows.length === 0) {
    return apiSuccess(res, {
      slackConnected: false,
      slackChannel: null,
      settings: DEFAULT_NOTIFICATION_SETTINGS,
    });
  }

  const prefs = (result.rows[0] as unknown as NotificationPreferencesRow).preferences;

  // Merge stored preferences with defaults
  const mergedSettings = DEFAULT_NOTIFICATION_SETTINGS.map((def) => {
    const stored = prefs.settings?.find((s: { id: string }) => s.id === def.id);
    return stored ? { ...def, email: stored.email, slack: stored.slack } : def;
  });

  return apiSuccess(res, {
    slackConnected: prefs.slackConnected || false,
    slackChannel: prefs.slackChannel || null,
    settings: mergedSettings,
  });
}

// Update notification preferences
export async function updatePreferences(req: Request, res: Response) {
  const userId = req.user!.id;
  const { settings } = req.body;

  // Get existing preferences to preserve slack connection status
  const existingResult = await db.execute(sql`
    SELECT preferences FROM notification_preferences WHERE user_id = ${userId}
  `);

  const existingPrefs = (existingResult.rows[0] as unknown as NotificationPreferencesRow | undefined)?.preferences || {};

  const preferences = {
    slackConnected: existingPrefs.slackConnected || false,
    slackChannel: existingPrefs.slackChannel || null,
    settings,
  };

  // Upsert preferences
  await db.execute(sql`
    INSERT INTO notification_preferences (user_id, preferences, created_at, updated_at)
    VALUES (${userId}, ${JSON.stringify(preferences)}, NOW(), NOW())
    ON CONFLICT (user_id)
    DO UPDATE SET preferences = ${JSON.stringify(preferences)}, updated_at = NOW()
  `);

  return apiSuccess(res, { message: 'Preferences saved successfully' });
}

// Helper function to create a notification (for use by other services)
export async function createNotification(
  userId: string,
  type: Notification['type'],
  title: string,
  message: string,
  link?: string
): Promise<string> {
  const result = await db.execute(sql`
    INSERT INTO notifications (user_id, type, title, message, link, read, created_at)
    VALUES (${userId}, ${type}, ${title}, ${message}, ${link ?? null}, false, NOW())
    RETURNING id
  `);

  return (result.rows[0] as unknown as IdRow).id;
}
