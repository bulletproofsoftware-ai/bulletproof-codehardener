import type { Response } from 'express';

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
  meta?: {
    page?: number;
    limit?: number;
    total?: number;
    totalPages?: number;
  };
  summary?: Record<string, unknown>;
  [key: string]: unknown;
}

export const sendSuccess = <T>(
  res: Response,
  data: T,
  statusCode = 200,
  meta?: ApiResponse['meta'],
  extras?: Record<string, unknown>
): Response => {
  const response: ApiResponse<T> = {
    success: true,
    data,
  };

  if (meta) {
    response.meta = meta;
  }

  // Add any extra top-level fields (like summary)
  if (extras) {
    Object.assign(response, extras);
  }

  return res.status(statusCode).json(response);
};

export const sendError = (
  res: Response,
  code: string,
  message: string,
  statusCode = 400,
  details?: unknown
): Response => {
  const response: ApiResponse = {
    success: false,
    error: {
      code,
      message,
      details,
    },
  };

  return res.status(statusCode).json(response);
};

export const sendCreated = <T>(res: Response, data: T): Response => {
  return sendSuccess(res, data, 201);
};

export const sendNoContent = (res: Response): Response => {
  return res.status(204).send();
};

export const sendNotFound = (res: Response, message = 'Resource not found'): Response => {
  return sendError(res, 'NOT_FOUND', message, 404);
};

export const sendUnauthorized = (res: Response, message = 'Unauthorized'): Response => {
  return sendError(res, 'UNAUTHORIZED', message, 401);
};

export const sendForbidden = (res: Response, message = 'Forbidden'): Response => {
  return sendError(res, 'FORBIDDEN', message, 403);
};

export const sendValidationError = (res: Response, details: unknown): Response => {
  return sendError(res, 'VALIDATION_ERROR', 'Validation failed', 422, details);
};

export const sendInternalError = (res: Response, message = 'Internal server error'): Response => {
  return sendError(res, 'INTERNAL_ERROR', message, 500);
};

// Simplified aliases for common use cases
export const apiSuccess = <T>(res: Response, data: T, statusCode = 200): Response => {
  return sendSuccess(res, data, statusCode);
};

export const apiError = (res: Response, message: string, statusCode = 400): Response => {
  const codes: Record<number, string> = {
    400: 'BAD_REQUEST',
    401: 'UNAUTHORIZED',
    403: 'FORBIDDEN',
    404: 'NOT_FOUND',
    409: 'CONFLICT',
    422: 'VALIDATION_ERROR',
    500: 'INTERNAL_ERROR',
  };
  return sendError(res, codes[statusCode] || 'ERROR', message, statusCode);
};
