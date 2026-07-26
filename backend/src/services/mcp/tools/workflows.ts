import { env } from '../../../config/env.js';
import { createLogger } from '../../../utils/logger.js';

const logger = createLogger('mcp-workflows');

export const workflowTools = [
  {
    name: 'codehardener_run_tests',
    description:
      'Trigger test case execution via n8n workflow. Runs generated test cases against a target and returns results.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        projectId: {
          type: 'string',
          description: 'Project ID to run tests for',
        },
        testType: {
          type: 'string',
          enum: ['security', 'api', 'performance', 'all'],
          description: 'Type of tests to run (default: all)',
        },
        targetUrl: {
          type: 'string',
          description: 'Target URL for API/DAST tests',
        },
      },
      required: ['projectId'],
    },
  },
  {
    name: 'codehardener_workflow_status',
    description:
      'Check the status of a running n8n workflow execution.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        executionId: {
          type: 'string',
          description: 'n8n execution ID',
        },
      },
      required: ['executionId'],
    },
  },
];

export async function handleRunTests(args: Record<string, unknown>): Promise<unknown> {
  if (!env.N8N_ENABLED) {
    return {
      error: 'n8n is not enabled',
      message: 'Set N8N_ENABLED=true and configure n8n to use workflow features.',
    };
  }

  const projectId = args.projectId as string;
  const testType = (args.testType as string) || 'all';
  const targetUrl = args.targetUrl as string | undefined;

  try {
    const webhookUrl = `${env.N8N_WEBHOOK_BASE}/test-runner`;
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(env.N8N_API_KEY ? { 'X-N8N-API-KEY': env.N8N_API_KEY } : {}),
      },
      body: JSON.stringify({
        projectId,
        testType,
        targetUrl,
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      return {
        error: 'Failed to trigger test workflow',
        status: response.status,
      };
    }

    const result = await response.json() as { executionId?: string; message?: string };

    return {
      status: 'triggered',
      executionId: result.executionId,
      message: result.message || 'Test execution started',
      checkWith: `Use codehardener_workflow_status with executionId to check progress`,
    };
  } catch (error) {
    logger.error({ error }, 'Failed to trigger test workflow');
    return {
      error: 'n8n unavailable',
      message: 'Could not reach n8n. Ensure it is running and accessible.',
    };
  }
}

export async function handleWorkflowStatus(args: Record<string, unknown>): Promise<unknown> {
  if (!env.N8N_ENABLED) {
    return {
      error: 'n8n is not enabled',
    };
  }

  const executionId = args.executionId as string;

  // executionId comes straight from an MCP tool caller and is interpolated into
  // the n8n API URL below. n8n execution IDs are short opaque identifiers, so
  // anything outside that alphabet (path traversal, a second scheme, encoded
  // separators) is rejected rather than sent.
  if (typeof executionId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(executionId)) {
    return { error: 'Invalid executionId' };
  }

  try {
    const response = await fetch(
      `${env.N8N_URL}/api/v1/executions/${executionId}`,
      {
        headers: env.N8N_API_KEY ? { 'X-N8N-API-KEY': env.N8N_API_KEY } : {},
        signal: AbortSignal.timeout(10000),
      }
    );

    if (!response.ok) {
      return { error: 'Execution not found', executionId };
    }

    const execution = await response.json() as {
      id: string;
      finished: boolean;
      status: string;
      startedAt: string;
      stoppedAt?: string;
      data?: { resultData?: { runData?: Record<string, unknown> } };
    };

    return {
      executionId: execution.id,
      status: execution.status,
      finished: execution.finished,
      startedAt: execution.startedAt,
      stoppedAt: execution.stoppedAt,
    };
  } catch (error) {
    logger.error({ error }, 'Failed to check workflow status');
    return {
      error: 'n8n unavailable',
      executionId,
    };
  }
}
