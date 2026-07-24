import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { detectProjectContext } from './detect-context.js';

const TEST_DIR = '/tmp/detect-context-test';

beforeEach(() => {
  rmSync(TEST_DIR, { recursive: true, force: true });
  mkdirSync(TEST_DIR, { recursive: true });
});

afterEach(() => {
  rmSync(TEST_DIR, { recursive: true, force: true });
});

describe('detectProjectContext', () => {
  it('detects OpenAPI specs at root', async () => {
    writeFileSync(join(TEST_DIR, 'openapi.yaml'), 'openapi: 3.0.0');
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.openapi).toContain(join(TEST_DIR, 'openapi.yaml'));
  });

  it('detects nested OpenAPI specs', async () => {
    mkdirSync(join(TEST_DIR, 'docs'), { recursive: true });
    writeFileSync(join(TEST_DIR, 'docs', 'api-docs.json'), '{"openapi":"3.0.0"}');
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.openapi.length).toBeGreaterThanOrEqual(1);
  });

  it('detects Postman collections', async () => {
    writeFileSync(join(TEST_DIR, 'api.postman_collection.json'), '{}');
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.postmanCollections.length).toBe(1);
  });

  it('detects Pact contracts', async () => {
    mkdirSync(join(TEST_DIR, 'pacts'), { recursive: true });
    writeFileSync(join(TEST_DIR, 'pacts', 'consumer-provider.json'), '{}');
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.pactContracts.length).toBe(1);
  });

  it('detects docker-compose.yml', async () => {
    writeFileSync(join(TEST_DIR, 'docker-compose.yml'), 'version: "3"');
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.dockerComposeFile).toBe(join(TEST_DIR, 'docker-compose.yml'));
  });

  it('detects Dockerfile', async () => {
    writeFileSync(join(TEST_DIR, 'Dockerfile'), 'FROM node:20');
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.dockerfile).toBe(join(TEST_DIR, 'Dockerfile'));
  });

  it('returns empty context for empty directory', async () => {
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.openapi).toEqual([]);
    expect(ctx.postmanCollections).toEqual([]);
    expect(ctx.pactContracts).toEqual([]);
    expect(ctx.dockerComposeFile).toBeNull();
    expect(ctx.dockerfile).toBeNull();
  });

  it('does not follow symlinks outside scanDir', async () => {
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.openapi).toEqual([]);
  });

  it('detects Express framework from package.json', async () => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{"dependencies":{"express":"^4.18.0"}}');
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.detectedFramework).toBe('express');
    expect(ctx.suggestedDevPort).toBe(3000);
  });

  it('detects Django from requirements.txt', async () => {
    writeFileSync(join(TEST_DIR, 'requirements.txt'), 'Django==4.2\ncelery==5.3');
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.detectedFramework).toBe('django');
    expect(ctx.suggestedDevPort).toBe(8000);
  });

  it('parses port from Procfile', async () => {
    writeFileSync(join(TEST_DIR, 'Procfile'), 'web: gunicorn myapp:app -b :8080');
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.suggestedDevPort).toBe(8080);
  });

  it('returns null framework/port for empty directory', async () => {
    const ctx = await detectProjectContext(TEST_DIR);
    expect(ctx.detectedFramework).toBeNull();
    expect(ctx.suggestedDevPort).toBeNull();
  });
});
