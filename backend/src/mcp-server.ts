#!/usr/bin/env node
/**
 * Code Hardener MCP Server — stdio entry point
 *
 * Run with: node dist/mcp-server.js
 * Or: npx tsx src/mcp-server.ts
 *
 * This is the primary interface for AI agents (Claude Code, Cursor).
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { config } from 'dotenv';

// Load environment
config();

import { getMcpToolDefinitions, executeMcpTool } from './services/mcp/server.js';
import { createLogger } from './utils/logger.js';

const logger = createLogger('mcp-stdio');

async function main() {
  const server = new Server(
    {
      name: 'codehardener',
      version: '0.1.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // List available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: getMcpToolDefinitions() };
  });

  // Execute tool
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      const result = await executeMcpTool(name, args || {});
      return {
        content: [
          {
            type: 'text' as const,
            text: typeof result === 'string' ? result : JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        content: [{ type: 'text' as const, text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  // Connect via stdio
  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info('Code Hardener MCP server running on stdio');
}

main().catch((error) => {
  console.error('MCP server failed to start:', error);
  process.exit(1);
});
