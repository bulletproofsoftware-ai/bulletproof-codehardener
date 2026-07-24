import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  listTeamMembers,
  inviteTeamMember,
  acceptInvite,
  updateMemberRole,
  removeMember,
  cancelInvite,
  resendInvite,
} from '../controllers/team.controller.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

router.get('/members', asyncHandler(listTeamMembers));
router.post('/invite', asyncHandler(inviteTeamMember));
router.post('/invite/:token/accept', asyncHandler(acceptInvite));
router.patch('/members/:memberId/role', asyncHandler(updateMemberRole));
router.delete('/members/:memberId', asyncHandler(removeMember));
router.delete('/invites/:inviteId', asyncHandler(cancelInvite));
router.post('/invites/:inviteId/resend', asyncHandler(resendInvite));

export { router as teamRoutes };
