/**
 * Token Encryption Service (SEC-001)
 *
 * Implements AES-256-GCM encryption for GitHub OAuth tokens.
 * - 32-byte master key from environment variable
 * - Random 12-byte IV per encryption
 * - 16-byte authentication tag
 */

import crypto from 'crypto';
import type { EncryptedData, EncryptedTokenSet, OAuthTokens } from '../../../types/github.types.js';

export class TokenEncryption {
  private readonly ALGORITHM = 'aes-256-gcm' as const;
  private readonly IV_LENGTH = 12;
  private readonly TAG_LENGTH = 16;
  private readonly KEY_LENGTH = 32;
  private readonly masterKey: Buffer;

  constructor(masterKeyHex?: string) {
    const keyHex = masterKeyHex || process.env.GITHUB_TOKEN_ENCRYPTION_KEY;

    if (!keyHex) {
      throw new Error(
        'GITHUB_TOKEN_ENCRYPTION_KEY environment variable is required. ' +
        'Generate with: openssl rand -hex 32'
      );
    }

    // Validate key format (64 hex characters = 32 bytes)
    if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
      throw new Error(
        'GITHUB_TOKEN_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes). ' +
        'Generate with: openssl rand -hex 32'
      );
    }

    this.masterKey = Buffer.from(keyHex, 'hex');

    if (this.masterKey.length !== this.KEY_LENGTH) {
      throw new Error(`Encryption key must be ${this.KEY_LENGTH} bytes`);
    }
  }

  /**
   * Encrypt a plaintext string using AES-256-GCM
   */
  encrypt(plaintext: string): EncryptedData {
    if (!plaintext) {
      throw new Error('Cannot encrypt empty or null value');
    }

    // Generate random IV for each encryption
    const iv = crypto.randomBytes(this.IV_LENGTH);

    // Create cipher with master key and IV
    const cipher = crypto.createCipheriv(this.ALGORITHM, this.masterKey, iv, {
      authTagLength: this.TAG_LENGTH,
    });

    // Encrypt the plaintext
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);

    // Get authentication tag
    const tag = cipher.getAuthTag();

    return {
      ciphertext: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
    };
  }

  /**
   * Decrypt an encrypted value using AES-256-GCM
   */
  decrypt(encryptedData: EncryptedData): string {
    if (!encryptedData.ciphertext || !encryptedData.iv || !encryptedData.tag) {
      throw new Error('Invalid encrypted data: missing ciphertext, iv, or tag');
    }

    try {
      const ciphertext = Buffer.from(encryptedData.ciphertext, 'base64');
      const iv = Buffer.from(encryptedData.iv, 'base64');
      const tag = Buffer.from(encryptedData.tag, 'base64');

      // Validate IV length
      if (iv.length !== this.IV_LENGTH) {
        throw new Error(`Invalid IV length: expected ${this.IV_LENGTH}, got ${iv.length}`);
      }

      // Validate tag length
      if (tag.length !== this.TAG_LENGTH) {
        throw new Error(`Invalid tag length: expected ${this.TAG_LENGTH}, got ${tag.length}`);
      }

      // Create decipher with master key and IV
      const decipher = crypto.createDecipheriv(this.ALGORITHM, this.masterKey, iv, {
        authTagLength: this.TAG_LENGTH,
      });

      // Set authentication tag
      decipher.setAuthTag(tag);

      // Decrypt
      const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);

      return decrypted.toString('utf8');
    } catch (error) {
      if (error instanceof Error && error.message.includes('Unsupported state or unable to authenticate')) {
        throw new Error('Decryption failed: authentication tag verification failed (data may have been tampered)');
      }
      throw error;
    }
  }

  /**
   * Encrypt a complete OAuth token set
   */
  encryptTokens(tokens: OAuthTokens): EncryptedTokenSet {
    const encryptedAccessToken = this.encrypt(tokens.accessToken);

    let encryptedRefreshToken: EncryptedData | null = null;
    if (tokens.refreshToken) {
      encryptedRefreshToken = this.encrypt(tokens.refreshToken);
    }

    return {
      accessToken: encryptedAccessToken,
      refreshToken: encryptedRefreshToken,
      expiresAt: tokens.expiresAt || null,
      scope: tokens.scope,
    };
  }

  /**
   * Decrypt a complete OAuth token set
   */
  decryptTokens(encryptedTokens: EncryptedTokenSet): OAuthTokens {
    const accessToken = this.decrypt(encryptedTokens.accessToken);

    let refreshToken: string | undefined;
    if (encryptedTokens.refreshToken) {
      refreshToken = this.decrypt(encryptedTokens.refreshToken);
    }

    return {
      accessToken,
      refreshToken,
      expiresAt: encryptedTokens.expiresAt || undefined,
      scope: encryptedTokens.scope,
    };
  }

  /**
   * Securely wipe sensitive data from memory
   * Note: JavaScript doesn't guarantee memory wiping, but this is a best effort
   */
  static secureWipe(buffer: Buffer): void {
    crypto.randomFillSync(buffer);
    buffer.fill(0);
  }

  /**
   * Generate a new encryption key (for setup/rotation)
   */
  static generateKey(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Validate that a key is properly formatted
   */
  static validateKey(keyHex: string): boolean {
    return /^[0-9a-fA-F]{64}$/.test(keyHex);
  }
}

// Singleton instance
let tokenEncryptionInstance: TokenEncryption | null = null;

/**
 * Get the singleton TokenEncryption instance
 */
export function getTokenEncryption(): TokenEncryption {
  if (!tokenEncryptionInstance) {
    tokenEncryptionInstance = new TokenEncryption();
  }
  return tokenEncryptionInstance;
}

/**
 * Reset the singleton instance (for testing)
 */
export function resetTokenEncryption(): void {
  tokenEncryptionInstance = null;
}
