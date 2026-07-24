import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response } from 'express';

// ── Mocks ──────────────────────────────────────────────────────

const mockVerifyToken = vi.fn();
const mockGetUserById = vi.fn();
vi.mock('../services/auth.service.js', () => ({
  verifyToken: (...args: unknown[]) => mockVerifyToken(...args),
  getUserById: (...args: unknown[]) => mockGetUserById(...args),
}));

vi.mock('../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

const mockDbExecute = vi.fn();
vi.mock('../db/client.js', () => ({
  db: {
    execute: (...args: unknown[]) => mockDbExecute(...args),
  },
  pool: {
    connect: vi.fn(),
  },
}));

vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({
    strings,
    values,
    _tag: 'sql',
  }),
}));

// Control isDev via a mutable reference so individual tests can change it
let mockIsDev = false;
vi.mock('../config/env.js', () => ({
  get isDev() {
    return mockIsDev;
  },
}));

// Mock apiResponse
const mockSendUnauthorized = vi.fn();
const mockSendForbidden = vi.fn();
vi.mock('../utils/apiResponse.js', () => ({
  sendUnauthorized: (...args: unknown[]) => mockSendUnauthorized(...args),
  sendForbidden: (...args: unknown[]) => mockSendForbidden(...args),
}));

// ── Imports ────────────────────────────────────────────────────

import { authenticate, optionalAuth, requireScope, requireOwnership } from './auth.js';

// ── Helpers ────────────────────────────────────────────────────

function mockReq(overrides: Partial<Request> = {}): Request {
  return {
    headers: {},
    params: {},
    ...overrides,
  } as unknown as Request;
}

function mockRes(): Response {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as Response;
  return res;
}

// ── Tests ──────────────────────────────────────────────────────

describe('auth middleware - authenticate', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIsDev = false;
  });

  it('rejects request with no authorization header (401)', async () => {
    const req = mockReq();
    const res = mockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(mockSendUnauthorized).toHaveBeenCalledWith(res, 'Authorization header required');
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects request with invalid authorization format (401)', async () => {
    const req = mockReq({
      headers: { authorization: 'Basic dXNlcjpwYXNz' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(mockSendUnauthorized).toHaveBeenCalledWith(res, 'Invalid authorization format');
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects request with invalid token (401)', async () => {
    mockVerifyToken.mockImplementation(() => {
      throw new Error('Invalid or expired token');
    });

    const req = mockReq({
      headers: { authorization: 'Bearer invalid-token' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(mockSendUnauthorized).toHaveBeenCalledWith(res, 'Authentication failed');
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects request with non-access token type (401)', async () => {
    mockVerifyToken.mockReturnValue({
      userId: 'user-1',
      email: 'test@test.com',
      type: 'refresh',
    });

    const req = mockReq({
      headers: { authorization: 'Bearer refresh-token' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(mockSendUnauthorized).toHaveBeenCalledWith(res, 'Invalid token type');
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects request when user not found for valid token (401)', async () => {
    mockVerifyToken.mockReturnValue({
      userId: 'user-deleted',
      email: 'deleted@test.com',
      type: 'access',
    });
    mockGetUserById.mockResolvedValue(null);

    const req = mockReq({
      headers: { authorization: 'Bearer valid-token-deleted-user' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(mockSendUnauthorized).toHaveBeenCalledWith(res, 'User not found');
    expect(next).not.toHaveBeenCalled();
  });

  it('passes request through with valid JWT and sets req.user', async () => {
    const userData = {
      id: 'user-1',
      email: 'test@test.com',
      name: 'Test User',
      createdAt: new Date(),
    };
    mockVerifyToken.mockReturnValue({
      userId: 'user-1',
      email: 'test@test.com',
      type: 'access',
    });
    mockGetUserById.mockResolvedValue(userData);

    const req = mockReq({
      headers: { authorization: 'Bearer valid-jwt-token' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toEqual(userData);
    expect(mockSendUnauthorized).not.toHaveBeenCalled();
  });

  it('dev mode bypasses auth with X-User-Id header (existing user)', async () => {
    mockIsDev = true;

    mockDbExecute.mockResolvedValueOnce({
      rows: [{
        id: 'user-dev-1',
        email: 'dev@codehardener.local',
        name: 'Dev User',
        createdAt: new Date(),
      }],
    });

    const req = mockReq({
      headers: { 'x-user-id': 'dev@codehardener.local' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toBeDefined();
    expect(req.user!.id).toBe('user-dev-1');
    expect(mockSendUnauthorized).not.toHaveBeenCalled();
  });

  it('dev mode creates user when X-User-Id does not exist', async () => {
    mockIsDev = true;

    // First query: user not found
    mockDbExecute.mockResolvedValueOnce({ rows: [] });
    // Second query: user created
    mockDbExecute.mockResolvedValueOnce({
      rows: [{
        id: 'user-new-1',
        email: 'newuser@test.local',
        name: 'Test User',
        createdAt: new Date(),
      }],
    });

    const req = mockReq({
      headers: { 'x-user-id': 'newuser' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toBeDefined();
    expect(req.user!.id).toBe('user-new-1');
    expect(mockDbExecute).toHaveBeenCalledTimes(2);
  });

  it('dev mode appends @test.local to X-User-Id without @ sign', async () => {
    mockIsDev = true;

    mockDbExecute.mockResolvedValueOnce({
      rows: [{
        id: 'user-simple',
        email: 'testuser@test.local',
        name: 'Test User',
        createdAt: new Date(),
      }],
    });

    const req = mockReq({
      headers: { 'x-user-id': 'testuser' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(next).toHaveBeenCalled();
    // The email used for lookup should be testuser@test.local
    expect(req.user).toBeDefined();
  });

  it('dev mode without X-User-Id still requires auth header', async () => {
    mockIsDev = true;

    const req = mockReq({
      headers: {},
    });
    const res = mockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(mockSendUnauthorized).toHaveBeenCalledWith(res, 'Authorization header required');
    expect(next).not.toHaveBeenCalled();
  });
});

describe('auth middleware - optionalAuth', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIsDev = false;
  });

  it('continues without auth when no authorization header', async () => {
    const req = mockReq();
    const res = mockRes();
    const next = vi.fn();

    await optionalAuth(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toBeUndefined();
  });

  it('continues without auth when header is not Bearer', async () => {
    const req = mockReq({
      headers: { authorization: 'ApiKey abc123' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await optionalAuth(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toBeUndefined();
  });

  it('sets req.user when valid Bearer token provided', async () => {
    const userData = {
      id: 'user-opt-1',
      email: 'opt@test.com',
      name: 'Optional User',
      createdAt: new Date(),
    };
    mockVerifyToken.mockReturnValue({
      userId: 'user-opt-1',
      email: 'opt@test.com',
      type: 'access',
    });
    mockGetUserById.mockResolvedValue(userData);

    const req = mockReq({
      headers: { authorization: 'Bearer valid-optional-token' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await optionalAuth(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toEqual(userData);
  });

  it('continues without error when token verification fails', async () => {
    mockVerifyToken.mockImplementation(() => {
      throw new Error('expired');
    });

    const req = mockReq({
      headers: { authorization: 'Bearer expired-token' } as Record<string, string>,
    });
    const res = mockRes();
    const next = vi.fn();

    await optionalAuth(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toBeUndefined();
  });
});

describe('auth middleware - requireScope', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('allows JWT auth (no apiKey) without scope check', () => {
    const middleware = requireScope('read:projects');
    const req = mockReq();
    // No apiKey set = JWT auth
    const res = mockRes();
    const next = vi.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(mockSendForbidden).not.toHaveBeenCalled();
  });

  it('allows API key with matching scope', () => {
    const middleware = requireScope('read:projects');
    const req = mockReq();
    req.apiKey = {
      id: 'key-1',
      userId: 'user-1',
      scopes: ['read:projects', 'write:projects'],
    };
    const res = mockRes();
    const next = vi.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('allows API key with wildcard scope', () => {
    const middleware = requireScope('write:scans');
    const req = mockReq();
    req.apiKey = {
      id: 'key-1',
      userId: 'user-1',
      scopes: ['*'],
    };
    const res = mockRes();
    const next = vi.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('rejects API key without required scope (403)', () => {
    const middleware = requireScope('admin:settings');
    const req = mockReq();
    req.apiKey = {
      id: 'key-1',
      userId: 'user-1',
      scopes: ['read:projects'],
    };
    const res = mockRes();
    const next = vi.fn();

    middleware(req, res, next);

    expect(mockSendForbidden).toHaveBeenCalledWith(res, 'Missing required scope: admin:settings');
    expect(next).not.toHaveBeenCalled();
  });
});

describe('auth middleware - requireOwnership', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects unauthenticated request (401)', () => {
    const middleware = requireOwnership();
    const req = mockReq();
    const res = mockRes();
    const next = vi.fn();

    middleware(req, res, next);

    expect(mockSendUnauthorized).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('allows request when user matches param userId', () => {
    const middleware = requireOwnership();
    const req = mockReq({
      params: { userId: 'user-1' },
    });
    req.user = {
      id: 'user-1',
      email: 'test@test.com',
      name: 'Test',
      createdAt: new Date(),
    };
    const res = mockRes();
    const next = vi.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(mockSendForbidden).not.toHaveBeenCalled();
  });

  it('rejects request when user does not match param userId (403)', () => {
    const middleware = requireOwnership();
    const req = mockReq({
      params: { userId: 'user-other' },
    });
    req.user = {
      id: 'user-1',
      email: 'test@test.com',
      name: 'Test',
      createdAt: new Date(),
    };
    const res = mockRes();
    const next = vi.fn();

    middleware(req, res, next);

    expect(mockSendForbidden).toHaveBeenCalledWith(res, 'Access denied');
    expect(next).not.toHaveBeenCalled();
  });

  it('allows request when no userId param exists (no ownership check)', () => {
    const middleware = requireOwnership();
    const req = mockReq({
      params: {},
    });
    req.user = {
      id: 'user-1',
      email: 'test@test.com',
      name: 'Test',
      createdAt: new Date(),
    };
    const res = mockRes();
    const next = vi.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });
});
