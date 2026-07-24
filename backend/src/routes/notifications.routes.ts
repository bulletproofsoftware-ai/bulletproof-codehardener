import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  listNotifications,
  getUnreadCount,
  markAsRead,
  markAllAsRead,
  deleteNotification,
  deleteAllRead,
  getPreferences,
  updatePreferences,
} from '../controllers/notifications.controller.js';

const router = Router();

// All routes require authentication
router.use(authenticate);

router.get('/', asyncHandler(listNotifications));
router.get('/unread-count', asyncHandler(getUnreadCount));
router.get('/preferences', asyncHandler(getPreferences));
router.put('/preferences', asyncHandler(updatePreferences));
router.post('/read-all', asyncHandler(markAllAsRead));
router.post('/:id/read', asyncHandler(markAsRead));
router.delete('/:id', asyncHandler(deleteNotification));
router.delete('/', asyncHandler(deleteAllRead));

export { router as notificationRoutes };
