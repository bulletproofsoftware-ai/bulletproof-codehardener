import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { createLogger } from '../utils/logger.js';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { UnauthorizedError, ConflictError, NotFoundError } from '../middleware/errorHandler.js';

const logger = createLogger('auth-service');

const SALT_ROUNDS = 12;

export interface TokenPayload {
  userId: string;
  email: string;
  type: 'access' | 'refresh';
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface UserData {
  id: string;
  email: string;
  name: string | null;
  createdAt: Date;
}

// Parse duration string to seconds
function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)([smhd])$/);
  if (!match) return 900; // default 15 minutes

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 3600;
    case 'd': return value * 86400;
    default: return 900;
  }
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function generateTokens(userId: string, email: string): AuthTokens {
  const accessExpiresIn = parseDuration(env.JWT_ACCESS_EXPIRES_IN);
  const refreshExpiresIn = parseDuration(env.JWT_REFRESH_EXPIRES_IN);

  const accessToken = jwt.sign(
    { userId, email, type: 'access' } as TokenPayload,
    env.JWT_SECRET,
    { expiresIn: accessExpiresIn }
  );

  const refreshToken = jwt.sign(
    { userId, email, type: 'refresh' } as TokenPayload,
    env.JWT_SECRET,
    { expiresIn: refreshExpiresIn }
  );

  return {
    accessToken,
    refreshToken,
    expiresIn: accessExpiresIn,
  };
}

export function verifyToken(token: string): TokenPayload {
  try {
    return jwt.verify(token, env.JWT_SECRET) as TokenPayload;
  } catch {
    throw new UnauthorizedError('Invalid or expired token');
  }
}

export async function registerUser(
  email: string,
  password: string,
  name?: string
): Promise<{ user: UserData; tokens: AuthTokens }> {
  // Check if user already exists
  const existingUser = await db.execute(
    sql`SELECT id FROM users WHERE email = ${email.toLowerCase()}`
  );

  if (existingUser.rows.length > 0) {
    throw new ConflictError('User with this email already exists');
  }

  // Hash password
  const passwordHash = await hashPassword(password);

  // Create user
  const result = await db.execute(
    sql`INSERT INTO users (email, password_hash, name)
        VALUES (${email.toLowerCase()}, ${passwordHash}, ${name || null})
        RETURNING id, email, name, created_at`
  );

  const user = result.rows[0] as any;
  logger.info({ userId: user.id }, 'User registered');

  const tokens = generateTokens(user.id, user.email);

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.created_at,
    },
    tokens,
  };
}

export async function loginUser(
  email: string,
  password: string
): Promise<{ user: UserData; tokens: AuthTokens }> {
  // Find user
  const result = await db.execute(
    sql`SELECT id, email, name, password_hash, created_at
        FROM users WHERE email = ${email.toLowerCase()}`
  );

  if (result.rows.length === 0) {
    throw new UnauthorizedError('Invalid email or password');
  }

  const user = result.rows[0] as any;

  // Verify password
  const isValid = await verifyPassword(password, user.password_hash);
  if (!isValid) {
    throw new UnauthorizedError('Invalid email or password');
  }

  // Update last login
  await db.execute(
    sql`UPDATE users SET updated_at = NOW() WHERE id = ${user.id}`
  );

  logger.info({ userId: user.id }, 'User logged in');

  const tokens = generateTokens(user.id, user.email);

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.created_at,
    },
    tokens,
  };
}

export async function refreshTokens(refreshToken: string): Promise<AuthTokens> {
  const payload = verifyToken(refreshToken);

  if (payload.type !== 'refresh') {
    throw new UnauthorizedError('Invalid refresh token');
  }

  // Verify user still exists
  const result = await db.execute(
    sql`SELECT id, email FROM users WHERE id = ${payload.userId}`
  );

  if (result.rows.length === 0) {
    throw new UnauthorizedError('User not found');
  }

  const user = result.rows[0] as any;
  return generateTokens(user.id, user.email);
}

export async function getUserById(userId: string): Promise<UserData | null> {
  const result = await db.execute(
    sql`SELECT id, email, name, created_at FROM users WHERE id = ${userId}`
  );

  if (result.rows.length === 0) {
    return null;
  }

  const user = result.rows[0] as any;
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    createdAt: user.created_at,
  };
}

export async function updateUserPassword(
  userId: string,
  currentPassword: string,
  newPassword: string
): Promise<void> {
  const result = await db.execute(
    sql`SELECT password_hash FROM users WHERE id = ${userId}`
  );

  if (result.rows.length === 0) {
    throw new NotFoundError('User not found');
  }

  const user = result.rows[0] as any;
  const isValid = await verifyPassword(currentPassword, user.password_hash);

  if (!isValid) {
    throw new UnauthorizedError('Current password is incorrect');
  }

  const newHash = await hashPassword(newPassword);
  await db.execute(
    sql`UPDATE users SET password_hash = ${newHash}, updated_at = NOW() WHERE id = ${userId}`
  );

  logger.info({ userId }, 'Password updated');
}
