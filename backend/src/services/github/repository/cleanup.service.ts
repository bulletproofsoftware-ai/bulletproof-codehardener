/**
 * Clone Cleanup Service (SEC-009)
 *
 * Manages cleanup of cloned repositories:
 * - Automatic expiration after 30 minutes
 * - Secure deletion with overwrite
 * - Periodic cleanup of orphaned clones
 */

import path from 'path';
import os from 'os';
import { promises as fs } from 'fs';
import crypto from 'crypto';
import { getActiveClones } from './repository.service.js';
import { logger } from '../../../utils/logger.js';
import { safePath } from '../../../utils/safePath.js';

const CLONE_BASE_DIR = path.join(os.tmpdir(), 'codehardener-clones');
const MAX_CLONE_AGE_MS = 30 * 60 * 1000; // 30 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const SECURE_DELETE_PASSES = 1; // Number of overwrite passes

export class CloneCleanupService {
  private cleanupInterval: NodeJS.Timeout | null = null;

  /**
   * Start the cleanup service
   */
  start(): void {
    if (this.cleanupInterval) {
      return; // Already running
    }

    logger.info('Clone cleanup service starting');

    // Initial cleanup
    this.runCleanup().catch((err) => {
      logger.error({ error: err }, 'Initial cleanup failed');
    });

    // Schedule periodic cleanup
    this.cleanupInterval = setInterval(() => {
      this.runCleanup().catch((err) => {
        logger.error({ error: err }, 'Periodic cleanup failed');
      });
    }, CLEANUP_INTERVAL_MS);

  }

  /**
   * Stop the cleanup service
   */
  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    logger.info('Clone cleanup service stopped');
  }

  /**
   * Run cleanup process
   */
  async runCleanup(): Promise<{ cleaned: number; errors: number }> {
    let cleaned = 0;
    let errors = 0;

    // Clean up tracked clones
    const activeClones = getActiveClones();
    const now = Date.now();

    for (const [cloneId, record] of activeClones.entries()) {
      if (now > record.expiresAt.getTime()) {
        try {
          await this.secureDelete(record.path);
          activeClones.delete(cloneId);
          cleaned++;
          logger.debug({ cloneId }, 'Expired clone cleaned up');
        } catch (error) {
          errors++;
          logger.error({ error, cloneId }, 'Failed to clean up expired clone');
        }
      }
    }

    // Clean up orphaned clones (directories without tracking)
    try {
      const orphaned = await this.findOrphanedClones();
      for (const orphanPath of orphaned) {
        try {
          await this.secureDelete(orphanPath);
          cleaned++;
          logger.debug({ path: orphanPath }, 'Orphaned clone cleaned up');
        } catch (error) {
          errors++;
          logger.error({ error, path: orphanPath }, 'Failed to clean up orphaned clone');
        }
      }
    } catch (error) {
      logger.error({ error }, 'Failed to scan for orphaned clones');
    }

    if (cleaned > 0 || errors > 0) {
      logger.info({ cleaned, errors }, 'Cleanup completed');
    }

    return { cleaned, errors };
  }

  /**
   * Find orphaned clone directories
   */
  private async findOrphanedClones(): Promise<string[]> {
    const orphaned: string[] = [];

    try {
      await fs.access(CLONE_BASE_DIR);
    } catch {
      // Directory doesn't exist, nothing to clean
      return orphaned;
    }

    const entries = await fs.readdir(CLONE_BASE_DIR, { withFileTypes: true });
    const activeClones = getActiveClones();
    const trackedIds = new Set(Array.from(activeClones.values()).map((r) => r.path));

    for (const entry of entries) {
      if (entry.isDirectory()) {
        const fullPath = safePath(CLONE_BASE_DIR, entry.name);

        // Check if this directory is tracked
        if (!trackedIds.has(fullPath)) {
          // Check age
          try {
            const stats = await fs.stat(fullPath);
            const age = Date.now() - stats.mtimeMs;

            if (age > MAX_CLONE_AGE_MS) {
              orphaned.push(fullPath);
            }
          } catch {
            // If we can't stat it, try to delete it anyway
            orphaned.push(fullPath);
          }
        }
      }
    }

    return orphaned;
  }

  /**
   * Securely delete a directory
   * Overwrites files with random data before deletion
   */
  async secureDelete(dirPath: string): Promise<void> {
    // Validate path is within clone directory (prevent directory traversal)
    const normalizedPath = path.normalize(dirPath);
    const normalizedBase = path.normalize(CLONE_BASE_DIR);

    if (!normalizedPath.startsWith(normalizedBase)) {
      throw new Error('Invalid path: outside of clone directory');
    }

    try {
      await fs.access(dirPath);
    } catch {
      // Directory doesn't exist, nothing to delete
      return;
    }

    // Recursively overwrite and delete files
    await this.secureDeleteRecursive(dirPath);
  }

  /**
   * Recursively overwrite and delete files in a directory
   */
  private async secureDeleteRecursive(dirPath: string): Promise<void> {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = safePath(dirPath, entry.name);

      if (entry.isDirectory()) {
        await this.secureDeleteRecursive(fullPath);
      } else if (entry.isFile()) {
        await this.secureOverwriteFile(fullPath);
      }
    }

    // Remove the directory itself
    await fs.rm(dirPath, { recursive: true, force: true });
  }

  /**
   * Overwrite a file with random data before deletion
   */
  private async secureOverwriteFile(filePath: string): Promise<void> {
    try {
      const stats = await fs.stat(filePath);
      const size = stats.size;

      // Skip very large files (> 100MB) for performance
      if (size > 100 * 1024 * 1024) {
        await fs.unlink(filePath);
        return;
      }

      // Overwrite with random data
      for (let pass = 0; pass < SECURE_DELETE_PASSES; pass++) {
        const randomData = crypto.randomBytes(Math.min(size, 1024 * 1024));
        const handle = await fs.open(filePath, 'w');

        try {
          let written = 0;
          while (written < size) {
            const toWrite = Math.min(randomData.length, size - written);
            await handle.write(randomData, 0, toWrite);
            written += toWrite;
          }
        } finally {
          await handle.close();
        }
      }

      // Delete the file
      await fs.unlink(filePath);
    } catch {
      // If overwrite fails, still try to delete
      try {
        await fs.unlink(filePath);
      } catch {
        // Ignore deletion error
      }
    }
  }

  /**
   * Force cleanup of all clones (for shutdown)
   */
  async cleanupAll(): Promise<void> {
    logger.info('Cleaning up all clones');

    const activeClones = getActiveClones();

    for (const [cloneId, record] of activeClones.entries()) {
      try {
        await this.secureDelete(record.path);
        activeClones.delete(cloneId);
      } catch (error) {
        logger.error({ error, cloneId }, 'Failed to clean up clone on shutdown');
      }
    }

    // Also clean the base directory
    try {
      await fs.rm(CLONE_BASE_DIR, { recursive: true, force: true });
    } catch {
      // Ignore error
    }
  }

  /**
   * Get cleanup statistics
   */
  async getStats(): Promise<{
    activeClones: number;
    totalSize: number;
    oldestCloneAge: number | null;
  }> {
    const activeClones = getActiveClones();
    let totalSize = 0;
    let oldestCreatedAt: Date | null = null;

    for (const record of activeClones.values()) {
      try {
        const size = await this.getDirectorySize(record.path);
        totalSize += size;
      } catch {
        // Ignore
      }

      if (!oldestCreatedAt || record.createdAt < oldestCreatedAt) {
        oldestCreatedAt = record.createdAt;
      }
    }

    return {
      activeClones: activeClones.size,
      totalSize,
      oldestCloneAge: oldestCreatedAt ? Date.now() - oldestCreatedAt.getTime() : null,
    };
  }

  /**
   * Get size of a directory recursively
   */
  private async getDirectorySize(dirPath: string): Promise<number> {
    let size = 0;

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = safePath(dirPath, entry.name);

        if (entry.isDirectory()) {
          size += await this.getDirectorySize(fullPath);
        } else if (entry.isFile()) {
          const stats = await fs.stat(fullPath);
          size += stats.size;
        }
      }
    } catch {
      // Ignore errors
    }

    return size;
  }
}

// Singleton instance
let cleanupServiceInstance: CloneCleanupService | null = null;

/**
 * Get the singleton CloneCleanupService instance
 */
export function getCloneCleanupService(): CloneCleanupService {
  if (!cleanupServiceInstance) {
    cleanupServiceInstance = new CloneCleanupService();
  }
  return cleanupServiceInstance;
}

/**
 * Reset the singleton instance (for testing)
 */
export function resetCloneCleanupService(): void {
  if (cleanupServiceInstance) {
    cleanupServiceInstance.stop();
  }
  cleanupServiceInstance = null;
}
