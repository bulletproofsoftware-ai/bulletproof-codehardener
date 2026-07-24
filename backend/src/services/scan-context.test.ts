import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildScanContext } from './scan-context.js';

// Mock logger
vi.mock('../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

// Mock db
const mockExecute = vi.fn();
vi.mock('../db/client.js', () => ({
  db: {
    execute: (...args: unknown[]) => mockExecute(...args),
  },
}));

vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({
    strings,
    values,
    _tag: 'sql',
  }),
}));

// Mock crypto module
const mockDecryptCredential = vi.fn();
const mockDecryptAuthConfig = vi.fn();
vi.mock('./crypto/credential-encryption.js', () => ({
  decryptCredential: (...args: unknown[]) => mockDecryptCredential(...args),
  decryptAuthConfig: (...args: unknown[]) => mockDecryptAuthConfig(...args),
}));

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('buildScanContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns empty context when project not found', async () => {
    mockExecute.mockResolvedValue({ rows: [] });

    const result = await buildScanContext('nonexistent-project');

    expect(result).toEqual({});
  });

  it('returns empty context when project has no DAST fields', async () => {
    mockExecute.mockResolvedValue({
      rows: [{
        target_url: null,
        container_image: null,
        openapi_spec_path: null,
        auth_config: null,
        registry_credentials_id: null,
        registry: null,
        username: null,
        password_encrypted: null,
        password_iv: null,
        password_tag: null,
      }],
    });

    const result = await buildScanContext('proj-1');

    expect(result.targetUrl).toBeUndefined();
    expect(result.containerImage).toBeUndefined();
    expect(result.openapiSpecPath).toBeUndefined();
    expect(result.authConfig).toBeUndefined();
    expect(result.registryCredentials).toBeUndefined();
  });

  it('returns targetUrl from project', async () => {
    mockExecute.mockResolvedValue({
      rows: [{
        target_url: 'https://app.example.com',
        container_image: null,
        openapi_spec_path: null,
        auth_config: null,
        registry_credentials_id: null,
        registry: null,
        username: null,
        password_encrypted: null,
        password_iv: null,
        password_tag: null,
      }],
    });

    const result = await buildScanContext('proj-1');

    expect(result.targetUrl).toBe('https://app.example.com');
  });

  it('per-scan override wins over project default for targetUrl', async () => {
    mockExecute.mockResolvedValue({
      rows: [{
        target_url: 'https://project-default.example.com',
        container_image: null,
        openapi_spec_path: null,
        auth_config: null,
        registry_credentials_id: null,
        registry: null,
        username: null,
        password_encrypted: null,
        password_iv: null,
        password_tag: null,
      }],
    });

    const result = await buildScanContext('proj-1', {
      targetUrl: 'https://scan-override.example.com',
    });

    expect(result.targetUrl).toBe('https://scan-override.example.com');
  });

  it('per-scan override wins over project default for containerImage', async () => {
    mockExecute.mockResolvedValue({
      rows: [{
        target_url: null,
        container_image: 'registry.example.com/app:v1',
        openapi_spec_path: null,
        auth_config: null,
        registry_credentials_id: null,
        registry: null,
        username: null,
        password_encrypted: null,
        password_iv: null,
        password_tag: null,
      }],
    });

    const result = await buildScanContext('proj-1', {
      containerImage: 'registry.example.com/app:v2-override',
    });

    expect(result.containerImage).toBe('registry.example.com/app:v2-override');
  });

  it('decrypts auth_config password correctly', async () => {
    const storedAuthConfig = {
      loginUrl: 'https://app.example.com/login',
      usernameField: 'email',
      passwordField: 'password',
      username: 'admin@example.com',
      password: { encrypted: 'enc-data', iv: 'iv-data', tag: 'tag-data' },
      successIndicator: 'Dashboard',
    };

    mockExecute.mockResolvedValue({
      rows: [{
        target_url: null,
        container_image: null,
        openapi_spec_path: null,
        auth_config: storedAuthConfig,
        registry_credentials_id: null,
        registry: null,
        username: null,
        password_encrypted: null,
        password_iv: null,
        password_tag: null,
      }],
    });

    mockDecryptAuthConfig.mockReturnValue({
      loginUrl: 'https://app.example.com/login',
      usernameField: 'email',
      passwordField: 'password',
      username: 'admin@example.com',
      password: 'plaintext-secret',
      successIndicator: 'Dashboard',
    });

    const result = await buildScanContext('proj-1');

    expect(mockDecryptAuthConfig).toHaveBeenCalledWith(storedAuthConfig);
    expect(result.authConfig).toBeDefined();
    expect(result.authConfig!.password).toBe('plaintext-secret');
    expect(result.authConfig!.loginUrl).toBe('https://app.example.com/login');
  });

  it('decrypts registry credentials password correctly', async () => {
    mockExecute.mockResolvedValue({
      rows: [{
        target_url: null,
        container_image: null,
        openapi_spec_path: null,
        auth_config: null,
        registry_credentials_id: 'rc-1',
        registry: 'ghcr.io',
        username: 'bot-user',
        password_encrypted: 'enc-pw',
        password_iv: 'iv-pw',
        password_tag: 'tag-pw',
      }],
    });

    mockDecryptCredential.mockReturnValue('ghp_plaintext_token');

    const result = await buildScanContext('proj-1');

    expect(mockDecryptCredential).toHaveBeenCalledWith('enc-pw', 'iv-pw', 'tag-pw');
    expect(result.registryCredentials).toBeDefined();
    expect(result.registryCredentials!.registry).toBe('ghcr.io');
    expect(result.registryCredentials!.username).toBe('bot-user');
    expect(result.registryCredentials!.password).toBe('ghp_plaintext_token');
  });

  it('returns undefined for auth_config when decryption fails (e.g. missing key)', async () => {
    mockExecute.mockResolvedValue({
      rows: [{
        target_url: null,
        container_image: null,
        openapi_spec_path: null,
        auth_config: { loginUrl: 'https://example.com', password: { encrypted: 'x', iv: 'y', tag: 'z' } },
        registry_credentials_id: null,
        registry: null,
        username: null,
        password_encrypted: null,
        password_iv: null,
        password_tag: null,
      }],
    });

    mockDecryptAuthConfig.mockImplementation(() => {
      throw new Error('Encryption key required for authenticated scanning.');
    });

    const result = await buildScanContext('proj-1');

    expect(result.authConfig).toBeUndefined();
  });

  it('returns undefined for registry credentials when decryption fails', async () => {
    mockExecute.mockResolvedValue({
      rows: [{
        target_url: null,
        container_image: null,
        openapi_spec_path: null,
        auth_config: null,
        registry_credentials_id: 'rc-1',
        registry: 'ghcr.io',
        username: 'bot-user',
        password_encrypted: 'enc-pw',
        password_iv: 'iv-pw',
        password_tag: 'tag-pw',
      }],
    });

    mockDecryptCredential.mockImplementation(() => {
      throw new Error('Encryption key required');
    });

    const result = await buildScanContext('proj-1');

    expect(result.registryCredentials).toBeUndefined();
  });

  it('includes openapiSpecPath from project when set', async () => {
    mockExecute.mockResolvedValue({
      rows: [{
        target_url: null,
        container_image: null,
        openapi_spec_path: '/specs/openapi.yaml',
        auth_config: null,
        registry_credentials_id: null,
        registry: null,
        username: null,
        password_encrypted: null,
        password_iv: null,
        password_tag: null,
      }],
    });

    const result = await buildScanContext('proj-1');

    expect(result.openapiSpecPath).toBe('/specs/openapi.yaml');
  });
});
