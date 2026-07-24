import { createApp } from './app.js';
import { env } from './config/env.js';
import { logger } from './utils/logger.js';
import { checkDbConnection, closeDbConnection } from './db/client.js';

const app = createApp();

// Graceful shutdown handler
async function shutdown(signal: string) {
  logger.info({ signal }, 'Received shutdown signal');

  try {
    await closeDbConnection();
    logger.info('Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    logger.error({ error }, 'Error during graceful shutdown');
    process.exit(1);
  }
}

// Handle shutdown signals
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  logger.fatal({ error }, 'Uncaught exception');
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  // Log but don't crash - the error handler should handle most cases
  // Only crash on truly fatal rejections
  logger.error({ reason, promise }, 'Unhandled rejection');

  // If this is an AppError, it's a handled error that just wasn't caught properly
  // Don't crash for these
  if (reason && typeof reason === 'object' && 'name' in reason && (reason as any).name === 'AppError') {
    return;
  }
});

// Start server
async function start() {
  try {
    // Check database connection
    const dbConnected = await checkDbConnection();
    if (!dbConnected) {
      logger.warn('Database not connected, continuing with limited functionality');
    } else {
      logger.info('Database connected successfully');
    }

    // Start HTTP server
    app.listen(env.PORT, env.HOST, () => {
      logger.info(
        { port: env.PORT, host: env.HOST, env: env.NODE_ENV },
        'Server started'
      );
    });
  } catch (error) {
    logger.fatal({ error }, 'Failed to start server');
    process.exit(1);
  }
}

start();
