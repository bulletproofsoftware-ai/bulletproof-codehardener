import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { sendSuccess, sendCreated, sendValidationError } from '../utils/apiResponse.js';
import { registerUser, loginUser, refreshTokens, updateUserPassword } from '../services/auth.service.js';
import { authenticate } from '../middleware/auth.js';
import { authRateLimiter } from '../middleware/rateLimiter.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('auth-routes');
const router = Router();

// Validation schemas
const registerSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  name: z.string().min(1).max(100).optional(),
});

const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required'),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string().min(8, 'New password must be at least 8 characters'),
});

// Register new user
router.post('/register', authRateLimiter, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const validation = registerSchema.safeParse(req.body);
    if (!validation.success) {
      sendValidationError(res, validation.error.errors);
      return;
    }

    const { email, password, name } = validation.data;
    const result = await registerUser(email, password, name);

    sendCreated(res, {
      user: result.user,
      tokens: result.tokens,
    });
  } catch (error) {
    next(error);
  }
});

// Login
router.post('/login', authRateLimiter, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const validation = loginSchema.safeParse(req.body);
    if (!validation.success) {
      sendValidationError(res, validation.error.errors);
      return;
    }

    const { email, password } = validation.data;
    const result = await loginUser(email, password);

    sendSuccess(res, {
      user: result.user,
      tokens: result.tokens,
    });
  } catch (error) {
    next(error);
  }
});

// Refresh tokens
router.post('/refresh', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const validation = refreshSchema.safeParse(req.body);
    if (!validation.success) {
      sendValidationError(res, validation.error.errors);
      return;
    }

    const { refreshToken } = validation.data;
    const tokens = await refreshTokens(refreshToken);

    sendSuccess(res, { tokens });
  } catch (error) {
    next(error);
  }
});

// Get current user
router.get('/me', authenticate, (req: Request, res: Response): void => {
  sendSuccess(res, { user: req.user });
});

// Change password
router.post('/change-password', authenticate, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const validation = changePasswordSchema.safeParse(req.body);
    if (!validation.success) {
      sendValidationError(res, validation.error.errors);
      return;
    }

    const { currentPassword, newPassword } = validation.data;
    await updateUserPassword(req.user!.id, currentPassword, newPassword);

    sendSuccess(res, { message: 'Password changed successfully' });
  } catch (error) {
    next(error);
  }
});

// Logout (client-side token removal, but we can blacklist if needed)
router.post('/logout', authenticate, (req: Request, res: Response): void => {
  // In a production system, you might want to blacklist the token
  // For now, we just acknowledge the logout
  logger.info({ userId: req.user!.id }, 'User logged out');
  sendSuccess(res, { message: 'Logged out successfully' });
});

export { router as authRoutes };
