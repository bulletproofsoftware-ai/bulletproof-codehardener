/**
 * SSE Transport for remote MCP connections.
 * Exposes MCP protocol over HTTP Server-Sent Events for remote AI agents.
 */

import { Router, Request, Response } from 'express';
import { getMcpToolDefinitions, executeMcpTool } from './server.js';
import { createLogger } from '../../utils/logger.js';
import { authenticate } from '../../middleware/auth.js';
import { asyncHandler } from '../../utils/asyncHandler.js';

const logger = createLogger('mcp-sse');

const router = Router();

// All MCP routes require authentication (JWT or API key)
router.use(asyncHandler(authenticate));

/**
 * SSE endpoint for MCP protocol.
 * Client connects via GET, sends tool calls via POST.
 */
router.get('/sse', (req: Request, res: Response): void => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });

  // Send initial capabilities
  const capabilities = {
    jsonrpc: '2.0',
    method: 'server/capabilities',
    params: {
      name: 'codehardener',
      version: '0.1.0',
      capabilities: { tools: {} },
    },
  };

  res.write(`data: ${JSON.stringify(capabilities)}\n\n`);

  // Keep alive
  const keepAlive = setInterval(() => {
    res.write(': keepalive\n\n');
  }, 30000);

  req.on('close', () => {
    clearInterval(keepAlive);
    logger.debug('SSE client disconnected');
  });
});

/**
 * JSON-RPC endpoint for MCP tool calls over HTTP.
 */
router.post('/rpc', async (req: Request, res: Response): Promise<void> => {
  const { method, params, id } = req.body;

  try {
    if (method === 'tools/list') {
      res.json({
        jsonrpc: '2.0',
        id,
        result: { tools: getMcpToolDefinitions() },
      });
      return;
    }

    if (method === 'tools/call') {
      const { name, arguments: args } = params;
      const result = await executeMcpTool(name, args || {});

      res.json({
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: typeof result === 'string' ? result : JSON.stringify(result, null, 2),
            },
          ],
        },
      });
      return;
    }

    res.json({
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Method not found: ${method}` },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.json({
      jsonrpc: '2.0',
      id,
      error: { code: -32000, message },
    });
  }
});

export { router as mcpSseRouter };
