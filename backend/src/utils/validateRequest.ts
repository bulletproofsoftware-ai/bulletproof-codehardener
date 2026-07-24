import { z } from 'zod';
import type { Request } from 'express';

// Common param schemas
export const uuidParam = z.object({ id: z.string().uuid() });
export const stringParam = (name: string) => z.object({ [name]: z.string().min(1) });

// Validate and return typed params
export function validateParams<T extends z.ZodType>(req: Request, schema: T): z.infer<T> {
  return schema.parse(req.params);
}

export function validateQuery<T extends z.ZodType>(req: Request, schema: T): z.infer<T> {
  return schema.parse(req.query);
}
