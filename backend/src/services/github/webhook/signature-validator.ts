/**
 * Webhook Signature Validator (GH-023, SEC-005)
 *
 * Validates GitHub webhook signatures using HMAC-SHA256.
 * - Timing-safe comparison to prevent timing attacks
 * - Support for both sha256 and sha1 signatures
 */

import crypto from 'crypto';
import { logger } from '../../../utils/logger.js';

export interface SignatureValidationResult {
  valid: boolean;
  error?: string;
}

export class WebhookSignatureValidator {
  private readonly SIGNATURE_PREFIX_256 = 'sha256=';
  private readonly SIGNATURE_PREFIX_1 = 'sha1=';

  /**
   * Validate a GitHub webhook signature
   *
   * @param payload - Raw request body as string or Buffer
   * @param signature - X-Hub-Signature-256 or X-Hub-Signature header value
   * @param secret - Webhook secret
   */
  validate(
    payload: string | Buffer,
    signature: string | undefined,
    secret: string
  ): SignatureValidationResult {
    if (!signature) {
      return { valid: false, error: 'Missing signature header' };
    }

    if (!secret) {
      return { valid: false, error: 'Webhook secret not configured' };
    }

    const payloadBuffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');

    // Prefer SHA-256 signature
    if (signature.startsWith(this.SIGNATURE_PREFIX_256)) {
      return this.validateSha256(payloadBuffer, signature, secret);
    }

    // Fall back to SHA-1 for older webhooks
    if (signature.startsWith(this.SIGNATURE_PREFIX_1)) {
      logger.warn('Webhook using deprecated SHA-1 signature');
      return this.validateSha1(payloadBuffer, signature, secret);
    }

    return { valid: false, error: 'Invalid signature format' };
  }

  /**
   * Validate SHA-256 signature
   */
  private validateSha256(
    payload: Buffer,
    signature: string,
    secret: string
  ): SignatureValidationResult {
    try {
      const expectedSignature = signature.slice(this.SIGNATURE_PREFIX_256.length);
      const computedSignature = crypto
        .createHmac('sha256', secret)
        .update(payload)
        .digest('hex');

      // Use timing-safe comparison
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');
      const computedBuffer = Buffer.from(computedSignature, 'hex');

      if (expectedBuffer.length !== computedBuffer.length) {
        return { valid: false, error: 'Signature length mismatch' };
      }

      const valid = crypto.timingSafeEqual(expectedBuffer, computedBuffer);

      if (!valid) {
        return { valid: false, error: 'Signature verification failed' };
      }

      return { valid: true };
    } catch (error) {
      logger.error({ error }, 'Signature validation error');
      return { valid: false, error: 'Signature validation error' };
    }
  }

  /**
   * Validate SHA-1 signature (legacy)
   */
  private validateSha1(
    payload: Buffer,
    signature: string,
    secret: string
  ): SignatureValidationResult {
    try {
      const expectedSignature = signature.slice(this.SIGNATURE_PREFIX_1.length);
      const computedSignature = crypto
        .createHmac('sha1', secret)
        .update(payload)
        .digest('hex');

      // Use timing-safe comparison
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');
      const computedBuffer = Buffer.from(computedSignature, 'hex');

      if (expectedBuffer.length !== computedBuffer.length) {
        return { valid: false, error: 'Signature length mismatch' };
      }

      const valid = crypto.timingSafeEqual(expectedBuffer, computedBuffer);

      if (!valid) {
        return { valid: false, error: 'Signature verification failed' };
      }

      return { valid: true };
    } catch (error) {
      logger.error({ error }, 'SHA-1 signature validation error');
      return { valid: false, error: 'Signature validation error' };
    }
  }

  /**
   * Generate a webhook secret
   */
  static generateSecret(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Sign a payload (for testing)
   */
  sign(payload: string | Buffer, secret: string, algorithm: 'sha256' | 'sha1' = 'sha256'): string {
    const payloadBuffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
    const signature = crypto.createHmac(algorithm, secret).update(payloadBuffer).digest('hex');
    return algorithm === 'sha256'
      ? `${this.SIGNATURE_PREFIX_256}${signature}`
      : `${this.SIGNATURE_PREFIX_1}${signature}`;
  }
}

// Singleton instance
let signatureValidatorInstance: WebhookSignatureValidator | null = null;

/**
 * Get the singleton WebhookSignatureValidator instance
 */
export function getWebhookSignatureValidator(): WebhookSignatureValidator {
  if (!signatureValidatorInstance) {
    signatureValidatorInstance = new WebhookSignatureValidator();
  }
  return signatureValidatorInstance;
}

/**
 * Reset the singleton instance (for testing)
 */
export function resetWebhookSignatureValidator(): void {
  signatureValidatorInstance = null;
}
