import { TokenEncryption } from '../github/oauth/token-encryption.js';

/**
 * Credential encryption utilities for auth_config and registry credentials.
 * Reuses the existing TokenEncryption class (AES-256-GCM) and its env var
 * (GITHUB_TOKEN_ENCRYPTION_KEY). Falls back to CREDENTIAL_ENCRYPTION_KEY
 * if the GitHub key is not set.
 */
function getEncryptor(): TokenEncryption {
  const key = process.env.GITHUB_TOKEN_ENCRYPTION_KEY || process.env.CREDENTIAL_ENCRYPTION_KEY;
  if (!key) {
    throw new Error(
      'Encryption key required for authenticated scanning. ' +
      'Set GITHUB_TOKEN_ENCRYPTION_KEY or CREDENTIAL_ENCRYPTION_KEY (openssl rand -hex 32).'
    );
  }
  return new TokenEncryption(key);
}

export interface EncryptedValue {
  encrypted: string;
  iv: string;
  tag: string;
}

/** Encrypt a plaintext credential string. Returns { encrypted, iv, tag }. */
export function encryptCredential(plaintext: string): EncryptedValue {
  const enc = getEncryptor();
  const result = enc.encrypt(plaintext);
  // Map from TokenEncryption's { ciphertext, iv, tag } to our { encrypted, iv, tag }
  return { encrypted: result.ciphertext, iv: result.iv, tag: result.tag };
}

/** Decrypt a credential from its encrypted/iv/tag components. */
export function decryptCredential(encrypted: string, iv: string, tag: string): string {
  const enc = getEncryptor();
  // Map back to TokenEncryption's { ciphertext, iv, tag } format
  return enc.decrypt({ ciphertext: encrypted, iv, tag });
}

/** Auth config as stored in the DB (password is an encrypted object). */
export interface StoredAuthConfig {
  loginUrl: string;
  usernameField: string;
  passwordField: string;
  username: string;
  password: EncryptedValue;
  csrfTokenSelector?: string;
  successIndicator: string;
}

/** Auth config with plaintext password (only exists in-memory during scan). */
export interface PlaintextAuthConfig {
  loginUrl: string;
  usernameField: string;
  passwordField: string;
  username: string;
  password: string;
  csrfTokenSelector?: string;
  successIndicator: string;
}

/** Encrypt only the password field of an auth config. */
export function encryptAuthConfig(config: PlaintextAuthConfig): StoredAuthConfig {
  const { password, ...rest } = config;
  return {
    ...rest,
    password: encryptCredential(password),
  };
}

/** Decrypt the password field of a stored auth config. */
export function decryptAuthConfig(stored: StoredAuthConfig): PlaintextAuthConfig {
  const { password, ...rest } = stored;
  return {
    ...rest,
    password: decryptCredential(password.encrypted, password.iv, password.tag),
  };
}
