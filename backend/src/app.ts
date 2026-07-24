import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { corsOrigins, isDev } from './config/env.js';
import { requestLogger, rateLimiter, errorHandler, notFoundHandler } from './middleware/index.js';
import { attachRLS } from './middleware/auth.js';
import { healthRoutes } from './routes/health.routes.js';
import { authRoutes } from './routes/auth.routes.js';
import { projectRoutes } from './routes/projects.routes.js';
import { scanRoutes } from './routes/scans.routes.js';
import { findingRoutes } from './routes/findings.routes.js';
import { dashboardRoutes } from './routes/dashboard.routes.js';
import { mcpRoutes } from './routes/mcp.routes.js';
import { attestationsRoutes } from './routes/attestations.routes.js';
import { reportsRoutes } from './routes/reports.routes.js';
import { policiesRoutes } from './routes/policies.routes.js';
import { testsRoutes } from './routes/tests.routes.js';
import { badgeRoutes } from './routes/badges.routes.js';
import { apiKeyRoutes } from './routes/api-keys.routes.js';
import { webhookRoutes } from './routes/webhooks.routes.js';
import { notificationRoutes } from './routes/notifications.routes.js';
import { integrationRoutes } from './routes/integrations.routes.js';
import { teamRoutes } from './routes/team.routes.js';
import { billingRoutes } from './routes/billing.routes.js';
import { toolsRoutes } from './routes/tools.routes.js';
import { promptRoutes } from './routes/prompts.routes.js';
import { testGeneratorRoutes } from './routes/test-generator.routes.js';
import { githubRoutes } from './routes/github.routes.js';
import { ssoRoutes } from './routes/sso.routes.js';
import { gdprRoutes } from './routes/gdpr.routes.js';
import { suppressionRoutes } from './routes/suppressions.routes.js';
import { registryCredentialRoutes } from './routes/registry-credentials.routes.js';
import { captureRawBody } from './middleware/webhookSignature.js';
import { n8nHooksRoutes } from './routes/n8n-hooks.routes.js';
import { mcpSseRouter } from './services/mcp/sse-transport.js';

export function createApp() {
  const app = express();

  // Security middleware
  app.use(helmet());

  // CORS configuration
  app.use(cors({
    origin: isDev ? true : corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-API-Key', 'X-User-Id'],
  }));

  // Body parsing with raw body capture for webhook signature verification
  app.use(express.json({
    limit: '10mb',
    verify: captureRawBody,
  }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Request logging
  app.use(requestLogger);

  // Rate limiting
  app.use(rateLimiter);

  // RLS context helper (lazy — reads req.user at call time, not mount time)
  app.use(attachRLS);

  // Health routes (no prefix)
  app.use(healthRoutes);

  // API routes
  app.use('/api/v1/auth', authRoutes);
  app.use('/api/v1/projects', projectRoutes);
  app.use('/api/v1/scans', scanRoutes);
  app.use('/api/v1/findings', findingRoutes);
  app.use('/api/v1/dashboard', dashboardRoutes);
  app.use('/api/v1/mcp', mcpRoutes);
  app.use('/api/v1/attestations', attestationsRoutes);
  app.use('/api/v1/reports', reportsRoutes);
  app.use('/api/v1/policies', policiesRoutes);
  app.use('/api/v1/tests', testsRoutes);
  app.use('/api/v1/badges', badgeRoutes);
  app.use('/api/v1/api-keys', apiKeyRoutes);
  app.use('/api/v1/webhooks', webhookRoutes);
  app.use('/api/v1/notifications', notificationRoutes);
  app.use('/api/v1/integrations', integrationRoutes);
  app.use('/api/v1/team', teamRoutes);
  app.use('/api/v1/billing', billingRoutes);
  app.use('/api/v1/tools', toolsRoutes);
  app.use('/api/v1/prompts', promptRoutes);
  app.use('/api/v1/test-generator', testGeneratorRoutes);
  app.use('/api/v1/github', githubRoutes);
  app.use('/api/v1/sso', ssoRoutes);
  app.use('/api/v1/gdpr', gdprRoutes);
  app.use('/api/v1/suppressions', suppressionRoutes);
  app.use('/api/v1/registry-credentials', registryCredentialRoutes);

  // Internal routes (n8n hooks - internal API key auth)
  app.use('/internal', n8nHooksRoutes);

  // MCP SSE transport (remote MCP connections)
  app.use('/mcp', mcpSseRouter);

  // 404 handler
  app.use(notFoundHandler);

  // Error handler (must be last)
  app.use(errorHandler);

  return app;
}
