import { describe, it, expect, beforeAll } from 'vitest';
import { encryptCredential, decryptCredential, encryptAuthConfig, decryptAuthConfig } from './credential-encryption.js';

// Set a test encryption key (64 hex chars = 32 bytes)
beforeAll(() => {
  process.env.GITHUB_TOKEN_ENCRYPTION_KEY = 'a'.repeat(64);
});

describe('credential-encryption', () => {
  describe('encryptCredential / decryptCredential', () => {
    it('round-trips a password', () => {
      const plaintext = 'my-secret-password-123!@#';
      const { encrypted, iv, tag } = encryptCredential(plaintext);
      expect(encrypted).not.toBe(plaintext);
      expect(iv).toBeTruthy();
      expect(tag).toBeTruthy();
      const result = decryptCredential(encrypted, iv, tag);
      expect(result).toBe(plaintext);
    });

    it('produces different ciphertext each time', () => {
      const plaintext = 'same-input';
      const a = encryptCredential(plaintext);
      const b = encryptCredential(plaintext);
      expect(a.encrypted).not.toBe(b.encrypted);
    });
  });

  describe('encryptAuthConfig / decryptAuthConfig', () => {
    it('encrypts only the password field', () => {
      const config = {
        loginUrl: 'https://app.example.com/login',
        usernameField: '#email',
        passwordField: '#password',
        username: 'test@example.com',
        password: 'plaintext-secret',
        successIndicator: '.dashboard',
      };
      const encrypted = encryptAuthConfig(config);
      expect(encrypted.username).toBe('test@example.com');
      expect(encrypted.loginUrl).toBe('https://app.example.com/login');
      expect(typeof encrypted.password).toBe('object');
      expect((encrypted.password as any).encrypted).toBeTruthy();
      expect((encrypted.password as any).iv).toBeTruthy();
      expect((encrypted.password as any).tag).toBeTruthy();
    });

    it('round-trips auth config', () => {
      const config = {
        loginUrl: 'https://app.example.com/login',
        usernameField: '#email',
        passwordField: '#password',
        username: 'test@example.com',
        password: 'plaintext-secret',
        successIndicator: '.dashboard',
      };
      const encrypted = encryptAuthConfig(config);
      const decrypted = decryptAuthConfig(encrypted);
      expect(decrypted.password).toBe('plaintext-secret');
      expect(decrypted.loginUrl).toBe(config.loginUrl);
    });
  });
});
