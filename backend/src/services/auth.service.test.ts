import { describe, it, expect, vi } from 'vitest';
import jwt from 'jsonwebtoken';

// Mock dependencies before importing the module
vi.mock('../config/env.js', () => ({
  env: {
    JWT_SECRET: 'test-secret-key-for-testing-only',
    JWT_ACCESS_EXPIRES_IN: '15m',
    JWT_REFRESH_EXPIRES_IN: '7d',
  },
}));

vi.mock('../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

vi.mock('../db/client.js', () => ({
  db: {
    execute: vi.fn(),
  },
}));

// Import after mocks are set up
import {
  hashPassword,
  verifyPassword,
  generateTokens,
  verifyToken,
} from './auth.service.js';
import { UnauthorizedError } from '../middleware/errorHandler.js';

describe('Auth Service', () => {
  describe('hashPassword', () => {
    it('returns a hashed password different from input', async () => {
      const password = 'mySecurePassword123';
      const hash = await hashPassword(password);

      expect(hash).not.toBe(password);
      expect(hash).toHaveLength(60); // bcrypt hash length
      expect(hash).toMatch(/^\$2[aby]\$/); // bcrypt prefix
    });

    it('produces different hashes for same password (salt)', async () => {
      const password = 'mySecurePassword123';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyPassword', () => {
    it('returns true for correct password', async () => {
      const password = 'mySecurePassword123';
      const hash = await hashPassword(password);

      const result = await verifyPassword(password, hash);
      expect(result).toBe(true);
    });

    it('returns false for incorrect password', async () => {
      const password = 'mySecurePassword123';
      const wrongPassword = 'wrongPassword456';
      const hash = await hashPassword(password);

      const result = await verifyPassword(wrongPassword, hash);
      expect(result).toBe(false);
    });

    it('handles empty password', async () => {
      const password = 'mySecurePassword123';
      const hash = await hashPassword(password);

      const result = await verifyPassword('', hash);
      expect(result).toBe(false);
    });
  });

  describe('generateTokens', () => {
    it('generates access and refresh tokens', () => {
      const userId = 'user-123';
      const email = 'test@example.com';

      const tokens = generateTokens(userId, email);

      expect(tokens).toHaveProperty('accessToken');
      expect(tokens).toHaveProperty('refreshToken');
      expect(tokens).toHaveProperty('expiresIn');
      expect(typeof tokens.accessToken).toBe('string');
      expect(typeof tokens.refreshToken).toBe('string');
      expect(tokens.expiresIn).toBe(900); // 15m = 900s
    });

    it('access token contains correct payload', () => {
      const userId = 'user-123';
      const email = 'test@example.com';

      const tokens = generateTokens(userId, email);
      const decoded = jwt.decode(tokens.accessToken) as any;

      expect(decoded.userId).toBe(userId);
      expect(decoded.email).toBe(email);
      expect(decoded.type).toBe('access');
    });

    it('refresh token contains correct payload', () => {
      const userId = 'user-123';
      const email = 'test@example.com';

      const tokens = generateTokens(userId, email);
      const decoded = jwt.decode(tokens.refreshToken) as any;

      expect(decoded.userId).toBe(userId);
      expect(decoded.email).toBe(email);
      expect(decoded.type).toBe('refresh');
    });

    it('generates different tokens for different users', () => {
      const tokens1 = generateTokens('user-123', 'user1@example.com');
      const tokens2 = generateTokens('user-456', 'user2@example.com');

      expect(tokens1.accessToken).not.toBe(tokens2.accessToken);
      expect(tokens1.refreshToken).not.toBe(tokens2.refreshToken);
    });

    it('access and refresh tokens are different', () => {
      const userId = 'user-123';
      const email = 'test@example.com';

      const tokens = generateTokens(userId, email);

      expect(tokens.accessToken).not.toBe(tokens.refreshToken);
    });
  });

  describe('verifyToken', () => {
    it('successfully verifies valid access token', () => {
      const userId = 'user-123';
      const email = 'test@example.com';
      const tokens = generateTokens(userId, email);

      const payload = verifyToken(tokens.accessToken);

      expect(payload.userId).toBe(userId);
      expect(payload.email).toBe(email);
      expect(payload.type).toBe('access');
    });

    it('successfully verifies valid refresh token', () => {
      const userId = 'user-123';
      const email = 'test@example.com';
      const tokens = generateTokens(userId, email);

      const payload = verifyToken(tokens.refreshToken);

      expect(payload.userId).toBe(userId);
      expect(payload.email).toBe(email);
      expect(payload.type).toBe('refresh');
    });

    it('throws UnauthorizedError for invalid token', () => {
      expect(() => verifyToken('invalid-token')).toThrow(UnauthorizedError);
    });

    it('throws UnauthorizedError for expired token', () => {
      // Create a token that's already expired
      const expiredToken = jwt.sign(
        { userId: 'user-123', email: 'test@example.com', type: 'access' },
        'test-secret-key-for-testing-only',
        { expiresIn: -10 } // Already expired
      );

      expect(() => verifyToken(expiredToken)).toThrow(UnauthorizedError);
    });

    it('throws UnauthorizedError for token signed with wrong secret', () => {
      const wrongSecretToken = jwt.sign(
        { userId: 'user-123', email: 'test@example.com', type: 'access' },
        'wrong-secret-key',
        { expiresIn: 900 }
      );

      expect(() => verifyToken(wrongSecretToken)).toThrow(UnauthorizedError);
    });

    it('throws UnauthorizedError for empty token', () => {
      expect(() => verifyToken('')).toThrow(UnauthorizedError);
    });
  });

  describe('password and token integration', () => {
    it('complete auth flow works correctly', async () => {
      // Simulate registration flow
      const password = 'SecurePass123!';
      const hash = await hashPassword(password);

      // Verify password
      const isValid = await verifyPassword(password, hash);
      expect(isValid).toBe(true);

      // Generate tokens
      const userId = 'user-new-123';
      const email = 'newuser@example.com';
      const tokens = generateTokens(userId, email);

      // Verify access token
      const accessPayload = verifyToken(tokens.accessToken);
      expect(accessPayload.userId).toBe(userId);
      expect(accessPayload.type).toBe('access');

      // Verify refresh token
      const refreshPayload = verifyToken(tokens.refreshToken);
      expect(refreshPayload.userId).toBe(userId);
      expect(refreshPayload.type).toBe('refresh');
    });
  });
});
