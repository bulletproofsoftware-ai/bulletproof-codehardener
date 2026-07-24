import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';
import { sendSuccess, sendValidationError, sendError } from '../utils/apiResponse.js';
import { authenticate } from '../middleware/auth.js';
import { MCP_TOOLS, handleMcpTool } from '../services/mcp/server.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('mcp-routes');
const router = Router();

const toolCallSchema = z.object({
  tool: z.string(),
  arguments: z.record(z.any()).optional(),
});

// List available MCP tools
router.get('/tools', (_req: Request, res: Response) => {
  const tools = Object.values(MCP_TOOLS).map(tool => ({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
  }));

  return sendSuccess(res, { tools });
});

// Execute MCP tool (requires auth)
router.post('/execute', authenticate, async (req: Request, res: Response) => {
  try {
    const validation = toolCallSchema.safeParse(req.body);
    if (!validation.success) {
      return sendValidationError(res, validation.error.errors);
    }

    const { tool, arguments: args = {} } = validation.data;

    // Verify tool exists
    const toolDef = Object.values(MCP_TOOLS).find(t => t.name === tool);
    if (!toolDef) {
      return sendError(res, 'TOOL_NOT_FOUND', `Unknown tool: ${tool}`, 404);
    }

    logger.info({ tool, userId: req.user!.id }, 'Executing MCP tool');

    const result = await handleMcpTool(tool, args, req.user!.id);

    return sendSuccess(res, { result });
  } catch (error: any) {
    logger.error({ error }, 'MCP tool execution failed');
    return sendError(res, 'TOOL_ERROR', error.message || 'Tool execution failed', 500);
  }
});

// MCP SSE endpoint for real-time updates
router.get('/stream', authenticate, (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  // Send initial connection message
  res.write(`data: ${JSON.stringify({ type: 'connected', userId: req.user!.id })}\n\n`);

  // Keep connection alive
  const keepAlive = setInterval(() => {
    res.write(`: keepalive\n\n`);
  }, 30000);

  // Cleanup on disconnect
  req.on('close', () => {
    clearInterval(keepAlive);
  });
});

export { router as mcpRoutes };
