import { describe, it, expect, vi } from 'vitest';

vi.mock('../../config/env.js', () => ({
  env: {
    DEFECTDOJO_URL: 'http://defectdojo:8080',
    DEFECTDOJO_API_KEY: '',
    DEFECTDOJO_ENABLED: false,
    N8N_URL: 'http://n8n:5678',
    N8N_ENABLED: false,
    N8N_WEBHOOK_BASE: 'http://n8n:5678/webhook',
    N8N_API_KEY: '',
  },
}));

vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

vi.mock('../../db/client.js', () => ({
  db: {
    execute: vi.fn(),
  },
}));

vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({
    strings,
    values,
    _tag: 'sql',
  }),
}));

vi.mock('../queue/scan.queue.js', () => ({
  addScanJob: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../assurance/quality-score.js', () => ({
  calculateQualityScore: vi.fn().mockReturnValue({ score: 850, qualityLevel: 'low' }),
  getQualityBadge: vi.fn().mockReturnValue({ text: 'A', color: '#22c55e' }),
}));

vi.mock('../translator/plain-language.js', () => ({
  translateFinding: vi.fn().mockReturnValue({
    titleSimple: 'Simple Title',
    descriptionSimple: 'Simple Description',
    actionRequired: 'Fix this',
    riskExplanation: 'This is risky',
  }),
}));

import { getMcpToolDefinitions, executeMcpTool, MCP_TOOLS, handleMcpTool } from './server.js';

describe('MCP Protocol', () => {
  describe('MCP_TOOLS', () => {
    it('defines all 10 base tools', () => {
      const toolNames = Object.values(MCP_TOOLS).map(t => t.name);

      expect(toolNames).toContain('codehardener_scan');
      expect(toolNames).toContain('codehardener_status');
      expect(toolNames).toContain('codehardener_findings');
      expect(toolNames).toContain('codehardener_fix');
      expect(toolNames).toContain('codehardener_score');
      expect(toolNames).toContain('codehardener_attestation');
      expect(toolNames).toContain('codehardener_sbom');
      expect(toolNames).toContain('codehardener_compare');
      expect(toolNames).toContain('codehardener_dismiss');
      expect(toolNames).toContain('codehardener_history');
    });

    it('each tool has name, description, and inputSchema', () => {
      for (const tool of Object.values(MCP_TOOLS)) {
        expect(tool.name).toBeDefined();
        expect(tool.name).toMatch(/^codehardener_/);
        expect(tool.description).toBeDefined();
        expect(tool.description.length).toBeGreaterThan(10);
        expect(tool.inputSchema).toBeDefined();
        expect(tool.inputSchema.type).toBe('object');
        expect(tool.inputSchema.properties).toBeDefined();
      }
    });

    it('required fields are specified as arrays', () => {
      for (const tool of Object.values(MCP_TOOLS)) {
        if (tool.inputSchema.required) {
          expect(Array.isArray(tool.inputSchema.required)).toBe(true);
          for (const field of tool.inputSchema.required) {
            expect(tool.inputSchema.properties).toHaveProperty(field);
          }
        }
      }
    });
  });

  describe('getMcpToolDefinitions', () => {
    it('returns all tools including high-level orchestrated tools', () => {
      const tools = getMcpToolDefinitions();

      expect(Array.isArray(tools)).toBe(true);
      // Should have 10 base tools + high-level tools
      expect(tools.length).toBeGreaterThanOrEqual(10);

      const names = tools.map((t: { name: string }) => t.name);
      // Base tools
      expect(names).toContain('codehardener_scan');
      expect(names).toContain('codehardener_findings');
      // High-level tools
      expect(names).toContain('codehardener_scan_project');
      expect(names).toContain('codehardener_get_findings');
      expect(names).toContain('codehardener_get_quality_score');
      expect(names).toContain('codehardener_get_trends');
      expect(names).toContain('codehardener_run_tests');
      expect(names).toContain('codehardener_workflow_status');
    });

    it('each tool definition has required fields for MCP SDK', () => {
      const tools = getMcpToolDefinitions();

      for (const tool of tools) {
        expect(tool).toHaveProperty('name');
        expect(tool).toHaveProperty('description');
        expect(tool).toHaveProperty('inputSchema');
      }
    });

    it('no duplicate tool names', () => {
      const tools = getMcpToolDefinitions();
      const names = tools.map((t: { name: string }) => t.name);
      const unique = new Set(names);
      expect(unique.size).toBe(names.length);
    });
  });

  describe('handleMcpTool', () => {
    it('throws on unknown tool', async () => {
      await expect(handleMcpTool('nonexistent_tool', {}, 'user-1'))
        .rejects.toThrow('Unknown tool: nonexistent_tool');
    });
  });

  describe('executeMcpTool', () => {
    it('routes to high-level handlers for orchestrated tools', async () => {
      // codehardener_get_quality_score should route to query-defectdojo handler
      // It will try DefectDojo first (disabled), then fall back to DB
      const { db } = await import('../../db/client.js');
      (db.execute as ReturnType<typeof vi.fn>).mockResolvedValue({
        rows: [{ severity: 'high', count: '3' }],
      });

      // This should not throw - just return some result
      const result = await executeMcpTool('codehardener_get_quality_score', { project_id: 'proj-1' });
      expect(result).toBeDefined();
    });

    it('falls back to base handlers for low-level tools', async () => {
      const { db } = await import('../../db/client.js');
      (db.execute as ReturnType<typeof vi.fn>).mockResolvedValue({
        rows: [{ id: 'scan-1', status: 'completed', score: 800, quality_level: 'low', project_name: 'Test' }],
      });

      const result = await executeMcpTool('codehardener_status', { scanId: 'scan-1' });
      expect(result).toBeDefined();
    });
  });
});
