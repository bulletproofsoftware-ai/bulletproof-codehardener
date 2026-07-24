import { Request, Response } from 'express';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../utils/logger.js';
import { apiSuccess, apiError } from '../utils/apiResponse.js';
import crypto from 'node:crypto';

const logger = createLogger('team-controller');

const ROLE_HIERARCHY: Record<string, number> = {
  owner: 4,
  admin: 3,
  member: 2,
  viewer: 1,
};

/** Row shape for team_members role/team lookup */
interface TeamMembershipRow {
  team_id: string;
  role: string;
}

/** Row shape for basic user info */
interface UserBasicRow {
  id: string;
  email: string;
  name: string;
}

/** Row shape for team member list with user join */
interface TeamMemberListRow {
  id: string;
  user_id: string;
  email: string;
  name: string;
  role: string;
  status: string;
  created_at: string;
}

/** Row shape for pending team invites */
interface TeamInviteListRow {
  id: string;
  email: string;
  role: string;
  created_at: string;
  expires_at: string;
}

/** Row shape for invite lookup */
interface TeamInviteRow {
  id: string;
  team_id: string;
  email: string;
  role: string;
  expires_at: string;
}

/** Row shape for user email lookup */
interface UserEmailRow {
  email: string;
}

/** Row shape for target member role */
interface MemberRoleRow {
  user_id: string;
  role: string;
}

// List team members
export async function listTeamMembers(req: Request, res: Response) {
  const userId = req.user!.id;

  // Get user's team
  const teamResult = await db.execute(sql`
    SELECT team_id, role FROM team_members WHERE user_id = ${userId} AND status = 'active'
  `);

  if (teamResult.rows.length === 0) {
    // User has no team, return just themselves
    const userResult = await db.execute(sql`
      SELECT id, email, name FROM users WHERE id = ${userId}
    `);

    const user = userResult.rows[0] as unknown as UserBasicRow;
    return apiSuccess(res, {
      members: [
        {
          id: user.id,
          email: user.email,
          name: user.name,
          role: 'owner',
          status: 'active',
          joinedAt: new Date().toISOString(),
        },
      ],
      pendingInvites: [],
    });
  }

  const teamId = (teamResult.rows[0] as unknown as TeamMembershipRow).team_id;

  // Get all team members
  const membersResult = await db.execute(sql`
    SELECT tm.id, tm.user_id, u.email, u.name, tm.role, tm.status, tm.created_at
    FROM team_members tm
    JOIN users u ON tm.user_id = u.id
    WHERE tm.team_id = ${teamId}
    ORDER BY tm.role DESC, tm.created_at ASC
  `);

  // Get pending invites
  const invitesResult = await db.execute(sql`
    SELECT id, email, role, created_at, expires_at
    FROM team_invites
    WHERE team_id = ${teamId} AND expires_at > NOW()
    ORDER BY created_at DESC
  `);

  const members = (membersResult.rows as unknown as TeamMemberListRow[]).map((row) => ({
    id: row.id,
    userId: row.user_id,
    email: row.email,
    name: row.name,
    role: row.role,
    status: row.status,
    joinedAt: new Date(row.created_at).toISOString(),
  }));

  const pendingInvites = (invitesResult.rows as unknown as TeamInviteListRow[]).map((row) => ({
    id: row.id,
    email: row.email,
    role: row.role,
    invitedAt: new Date(row.created_at).toISOString(),
    expiresAt: new Date(row.expires_at).toISOString(),
  }));

  return apiSuccess(res, { members, pendingInvites });
}

// Invite team member
export async function inviteTeamMember(req: Request, res: Response) {
  const userId = req.user!.id;
  const { email, role } = req.body;

  if (!email || !role) {
    return apiError(res, 'Email and role are required', 400);
  }

  if (!['admin', 'member', 'viewer'].includes(role)) {
    return apiError(res, 'Invalid role. Must be admin, member, or viewer', 400);
  }

  // Get user's team and role
  const teamResult = await db.execute(sql`
    SELECT team_id, role FROM team_members WHERE user_id = ${userId} AND status = 'active'
  `);

  let teamId: string;

  if (teamResult.rows.length === 0) {
    // Create a new team for this user
    teamId = crypto.randomUUID();
    await db.execute(sql`
      INSERT INTO teams (id, name, created_at, updated_at)
      VALUES (${teamId}, 'My Team', NOW(), NOW())
    `);

    await db.execute(sql`
      INSERT INTO team_members (id, team_id, user_id, role, status, created_at, updated_at)
      VALUES (${crypto.randomUUID()}, ${teamId}, ${userId}, 'owner', 'active', NOW(), NOW())
    `);
  } else {
    teamId = (teamResult.rows[0] as unknown as TeamMembershipRow).team_id;
    const userRole = (teamResult.rows[0] as unknown as TeamMembershipRow).role;

    // Check permission to invite
    if (ROLE_HIERARCHY[userRole] < ROLE_HIERARCHY.admin) {
      return apiError(res, 'You do not have permission to invite members', 403);
    }

    // Can't invite someone with a higher role
    if (ROLE_HIERARCHY[role] >= ROLE_HIERARCHY[userRole] && userRole !== 'owner') {
      return apiError(res, 'Cannot invite someone with equal or higher role', 403);
    }
  }

  // Check if user is already a member
  const existingMember = await db.execute(sql`
    SELECT tm.id FROM team_members tm
    JOIN users u ON tm.user_id = u.id
    WHERE tm.team_id = ${teamId} AND u.email = ${email}
  `);

  if (existingMember.rows.length > 0) {
    return apiError(res, 'User is already a team member', 400);
  }

  // Check if invite already exists
  const existingInvite = await db.execute(sql`
    SELECT id FROM team_invites WHERE team_id = ${teamId} AND email = ${email} AND expires_at > NOW()
  `);

  if (existingInvite.rows.length > 0) {
    return apiError(res, 'An invite has already been sent to this email', 400);
  }

  // Create invite
  const inviteId = crypto.randomUUID();
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  await db.execute(sql`
    INSERT INTO team_invites (id, team_id, email, role, token, expires_at, created_at)
    VALUES (${inviteId}, ${teamId}, ${email}, ${role}, ${token}, ${expiresAt.toISOString()}, NOW())
  `);

  logger.info({ inviteId, teamId, email, role }, 'Team invite created');

  // In production, send email with invite link
  // For now, just return success
  return apiSuccess(res, {
    id: inviteId,
    email,
    role,
    expiresAt: expiresAt.toISOString(),
    message: 'Invitation sent successfully',
  }, 201);
}

// Accept team invite
export async function acceptInvite(req: Request, res: Response) {
  const userId = req.user!.id;
  const { token } = req.params;

  // Find valid invite
  const inviteResult = await db.execute(sql`
    SELECT id, team_id, email, role, expires_at
    FROM team_invites
    WHERE token = ${token} AND expires_at > NOW()
  `);

  if (inviteResult.rows.length === 0) {
    return apiError(res, 'Invalid or expired invite', 404);
  }

  const invite = inviteResult.rows[0] as unknown as TeamInviteRow;

  // Verify email matches
  const userResult = await db.execute(sql`
    SELECT email FROM users WHERE id = ${userId}
  `);

  if ((userResult.rows[0] as unknown as UserEmailRow).email !== invite.email) {
    return apiError(res, 'This invite was sent to a different email address', 403);
  }

  // Check if already a member
  const existingMember = await db.execute(sql`
    SELECT id FROM team_members WHERE team_id = ${invite.team_id} AND user_id = ${userId}
  `);

  if (existingMember.rows.length > 0) {
    // Delete the invite and return success
    await db.execute(sql`DELETE FROM team_invites WHERE id = ${invite.id}`);
    return apiSuccess(res, { message: 'You are already a member of this team' });
  }

  // Add user to team
  const memberId = crypto.randomUUID();
  await db.execute(sql`
    INSERT INTO team_members (id, team_id, user_id, role, status, created_at, updated_at)
    VALUES (${memberId}, ${invite.team_id}, ${userId}, ${invite.role}, 'active', NOW(), NOW())
  `);

  // Delete the invite
  await db.execute(sql`DELETE FROM team_invites WHERE id = ${invite.id}`);

  logger.info({ memberId, teamId: invite.team_id, userId }, 'User joined team');

  return apiSuccess(res, {
    message: 'Successfully joined team',
    role: invite.role,
  });
}

// Update team member role
export async function updateMemberRole(req: Request, res: Response) {
  const userId = req.user!.id;
  const { memberId } = req.params;
  const { role } = req.body;

  if (!role || !['admin', 'member', 'viewer'].includes(role)) {
    return apiError(res, 'Invalid role. Must be admin, member, or viewer', 400);
  }

  // Get current user's team and role
  const userTeamResult = await db.execute(sql`
    SELECT team_id, role FROM team_members WHERE user_id = ${userId} AND status = 'active'
  `);

  if (userTeamResult.rows.length === 0) {
    return apiError(res, 'You are not a member of any team', 404);
  }

  const { team_id: teamId, role: userRole } = userTeamResult.rows[0] as unknown as TeamMembershipRow;

  // Check permission
  if (ROLE_HIERARCHY[userRole] < ROLE_HIERARCHY.admin) {
    return apiError(res, 'You do not have permission to update roles', 403);
  }

  // Get target member
  const targetResult = await db.execute(sql`
    SELECT user_id, role FROM team_members WHERE id = ${memberId} AND team_id = ${teamId}
  `);

  if (targetResult.rows.length === 0) {
    return apiError(res, 'Team member not found', 404);
  }

  const target = targetResult.rows[0] as unknown as MemberRoleRow;

  // Can't modify owner
  if (target.role === 'owner') {
    return apiError(res, 'Cannot modify owner role', 403);
  }

  // Can't modify someone with equal or higher role (unless owner)
  if (ROLE_HIERARCHY[target.role] >= ROLE_HIERARCHY[userRole] && userRole !== 'owner') {
    return apiError(res, 'Cannot modify member with equal or higher role', 403);
  }

  // Can't assign equal or higher role (unless owner)
  if (ROLE_HIERARCHY[role] >= ROLE_HIERARCHY[userRole] && userRole !== 'owner') {
    return apiError(res, 'Cannot assign equal or higher role', 403);
  }

  // Update role
  await db.execute(sql`
    UPDATE team_members SET role = ${role}, updated_at = NOW() WHERE id = ${memberId}
  `);

  logger.info({ memberId, teamId, newRole: role }, 'Team member role updated');

  return apiSuccess(res, { message: 'Role updated successfully' });
}

// Remove team member
export async function removeMember(req: Request, res: Response) {
  const userId = req.user!.id;
  const { memberId } = req.params;

  // Get current user's team and role
  const userTeamResult = await db.execute(sql`
    SELECT team_id, role FROM team_members WHERE user_id = ${userId} AND status = 'active'
  `);

  if (userTeamResult.rows.length === 0) {
    return apiError(res, 'You are not a member of any team', 404);
  }

  const { team_id: teamId, role: userRole } = userTeamResult.rows[0] as unknown as TeamMembershipRow;

  // Get target member
  const targetResult = await db.execute(sql`
    SELECT user_id, role FROM team_members WHERE id = ${memberId} AND team_id = ${teamId}
  `);

  if (targetResult.rows.length === 0) {
    return apiError(res, 'Team member not found', 404);
  }

  const target = targetResult.rows[0] as unknown as MemberRoleRow;

  // Can't remove owner
  if (target.role === 'owner') {
    return apiError(res, 'Cannot remove the team owner', 403);
  }

  // Check permission (admin+ can remove, or user can remove themselves)
  if (target.user_id !== userId) {
    if (ROLE_HIERARCHY[userRole] < ROLE_HIERARCHY.admin) {
      return apiError(res, 'You do not have permission to remove members', 403);
    }
    if (ROLE_HIERARCHY[target.role] >= ROLE_HIERARCHY[userRole] && userRole !== 'owner') {
      return apiError(res, 'Cannot remove member with equal or higher role', 403);
    }
  }

  // Remove member
  await db.execute(sql`DELETE FROM team_members WHERE id = ${memberId}`);

  logger.info({ memberId, teamId }, 'Team member removed');

  return res.status(204).send();
}

// Cancel pending invite
export async function cancelInvite(req: Request, res: Response) {
  const userId = req.user!.id;
  const { inviteId } = req.params;

  // Get current user's team and role
  const userTeamResult = await db.execute(sql`
    SELECT team_id, role FROM team_members WHERE user_id = ${userId} AND status = 'active'
  `);

  if (userTeamResult.rows.length === 0) {
    return apiError(res, 'You are not a member of any team', 404);
  }

  const { team_id: teamId, role: userRole } = userTeamResult.rows[0] as unknown as TeamMembershipRow;

  // Check permission
  if (ROLE_HIERARCHY[userRole] < ROLE_HIERARCHY.admin) {
    return apiError(res, 'You do not have permission to cancel invites', 403);
  }

  // Delete invite
  const result = await db.execute(sql`
    DELETE FROM team_invites WHERE id = ${inviteId} AND team_id = ${teamId} RETURNING id
  `);

  if (result.rows.length === 0) {
    return apiError(res, 'Invite not found', 404);
  }

  logger.info({ inviteId, teamId }, 'Team invite cancelled');

  return res.status(204).send();
}

// Resend invite
export async function resendInvite(req: Request, res: Response) {
  const userId = req.user!.id;
  const { inviteId } = req.params;

  // Get current user's team and role
  const userTeamResult = await db.execute(sql`
    SELECT team_id, role FROM team_members WHERE user_id = ${userId} AND status = 'active'
  `);

  if (userTeamResult.rows.length === 0) {
    return apiError(res, 'You are not a member of any team', 404);
  }

  const { team_id: teamId, role: userRole } = userTeamResult.rows[0] as unknown as TeamMembershipRow;

  // Check permission
  if (ROLE_HIERARCHY[userRole] < ROLE_HIERARCHY.admin) {
    return apiError(res, 'You do not have permission to resend invites', 403);
  }

  // Get and update invite
  const newToken = crypto.randomBytes(32).toString('hex');
  const newExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const result = await db.execute(sql`
    UPDATE team_invites
    SET token = ${newToken}, expires_at = ${newExpiry.toISOString()}
    WHERE id = ${inviteId} AND team_id = ${teamId}
    RETURNING email
  `);

  if (result.rows.length === 0) {
    return apiError(res, 'Invite not found', 404);
  }

  logger.info({ inviteId, teamId }, 'Team invite resent');

  // In production, resend email
  return apiSuccess(res, {
    message: 'Invite resent successfully',
    expiresAt: newExpiry.toISOString(),
  });
}
