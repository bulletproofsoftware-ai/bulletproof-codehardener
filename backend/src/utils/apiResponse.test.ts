import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Response } from 'express';
import {
  sendSuccess,
  sendError,
  sendCreated,
  sendNoContent,
  sendNotFound,
  sendUnauthorized,
  sendForbidden,
  sendValidationError,
  sendInternalError,
} from './apiResponse.js';

// Create a mock Response object
function createMockResponse(): Response {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    send: vi.fn().mockReturnThis(),
  } as unknown as Response;
  return res;
}

describe('API Response Utilities', () => {
  let mockRes: Response;

  beforeEach(() => {
    mockRes = createMockResponse();
  });

  describe('sendSuccess', () => {
    it('sends success response with data and 200 status', () => {
      const data = { id: 1, name: 'Test' };
      sendSuccess(mockRes, data);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        data,
      });
    });

    it('sends success response with custom status code', () => {
      const data = { id: 1 };
      sendSuccess(mockRes, data, 201);

      expect(mockRes.status).toHaveBeenCalledWith(201);
    });

    it('includes meta information when provided', () => {
      const data = [{ id: 1 }, { id: 2 }];
      const meta = { page: 1, limit: 10, total: 100, totalPages: 10 };
      sendSuccess(mockRes, data, 200, meta);

      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        data,
        meta,
      });
    });

    it('includes extra fields when provided', () => {
      const data = [{ id: 1 }];
      const extras = { summary: { count: 1 } };
      sendSuccess(mockRes, data, 200, undefined, extras);

      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        data,
        summary: { count: 1 },
      });
    });

    it('handles null data', () => {
      sendSuccess(mockRes, null);

      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        data: null,
      });
    });

    it('handles array data', () => {
      const data = [1, 2, 3];
      sendSuccess(mockRes, data);

      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        data,
      });
    });
  });

  describe('sendError', () => {
    it('sends error response with code, message, and status', () => {
      sendError(mockRes, 'INVALID_INPUT', 'Invalid input provided', 400);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'INVALID_INPUT',
          message: 'Invalid input provided',
          details: undefined,
        },
      });
    });

    it('defaults to 400 status code', () => {
      sendError(mockRes, 'ERROR', 'Some error');

      expect(mockRes.status).toHaveBeenCalledWith(400);
    });

    it('includes details when provided', () => {
      const details = { field: 'email', issue: 'invalid format' };
      sendError(mockRes, 'VALIDATION_ERROR', 'Validation failed', 422, details);

      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details,
        },
      });
    });
  });

  describe('sendCreated', () => {
    it('sends 201 status with data', () => {
      const data = { id: 'new-123', name: 'Created resource' };
      sendCreated(mockRes, data);

      expect(mockRes.status).toHaveBeenCalledWith(201);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        data,
      });
    });
  });

  describe('sendNoContent', () => {
    it('sends 204 status with no body', () => {
      sendNoContent(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(204);
      expect(mockRes.send).toHaveBeenCalled();
      expect(mockRes.json).not.toHaveBeenCalled();
    });
  });

  describe('sendNotFound', () => {
    it('sends 404 with default message', () => {
      sendNotFound(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(404);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'Resource not found',
          details: undefined,
        },
      });
    });

    it('sends 404 with custom message', () => {
      sendNotFound(mockRes, 'User not found');

      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'User not found',
          details: undefined,
        },
      });
    });
  });

  describe('sendUnauthorized', () => {
    it('sends 401 with default message', () => {
      sendUnauthorized(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Unauthorized',
          details: undefined,
        },
      });
    });

    it('sends 401 with custom message', () => {
      sendUnauthorized(mockRes, 'Token expired');

      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Token expired',
          details: undefined,
        },
      });
    });
  });

  describe('sendForbidden', () => {
    it('sends 403 with default message', () => {
      sendForbidden(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'Forbidden',
          details: undefined,
        },
      });
    });

    it('sends 403 with custom message', () => {
      sendForbidden(mockRes, 'Insufficient permissions');

      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'Insufficient permissions',
          details: undefined,
        },
      });
    });
  });

  describe('sendValidationError', () => {
    it('sends 422 with validation details', () => {
      const details = [
        { path: ['email'], message: 'Invalid email format' },
        { path: ['password'], message: 'Too short' },
      ];
      sendValidationError(mockRes, details);

      expect(mockRes.status).toHaveBeenCalledWith(422);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details,
        },
      });
    });
  });

  describe('sendInternalError', () => {
    it('sends 500 with default message', () => {
      sendInternalError(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Internal server error',
          details: undefined,
        },
      });
    });

    it('sends 500 with custom message', () => {
      sendInternalError(mockRes, 'Database connection failed');

      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Database connection failed',
          details: undefined,
        },
      });
    });
  });
});
