/**
 * CA-010: Large Repository Handling
 * Handles large repositories with streaming analysis and chunking
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { randomInt } from 'crypto';
import { createLogger } from '../../../utils/logger.js';
import { safePath } from '../../../utils/safePath.js';
// Types are re-exported from types.js and used by caller modules

const logger = createLogger('large-repo-handler');

// Thresholds for large repository handling
const THRESHOLDS = {
  maxFiles: 10000,
  maxTotalSize: 500 * 1024 * 1024, // 500MB
  maxFileSize: 10 * 1024 * 1024, // 10MB per file
  chunkSize: 100, // Files per chunk
  sampleRatio: 0.2, // Sample 20% of files for very large repos
  maxAnalysisTime: 5 * 60 * 1000, // 5 minutes max
};

export interface RepoStats {
  totalFiles: number;
  totalSize: number;
  largestFile: { path: string; size: number } | null;
  filesByExtension: Map<string, number>;
  isLargeRepo: boolean;
  estimatedAnalysisTime: number;
  recommendedStrategy: 'full' | 'sampled' | 'chunked';
}

export interface AnalysisChunk {
  id: number;
  files: string[];
  startTime?: number;
  endTime?: number;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  error?: string;
}

export interface ChunkedAnalysisResult<T> {
  results: T[];
  chunksProcessed: number;
  totalChunks: number;
  totalFiles: number;
  processingTimeMs: number;
  wassampled: boolean;
  sampleRatio?: number;
}

interface FileInfo {
  path: string;
  relativePath: string;
  size: number;
  extension: string;
}

/**
 * Scan repository to gather statistics
 */
export async function scanRepository(repoPath: string): Promise<RepoStats> {
  logger.info({ repoPath }, 'Scanning repository for statistics');

  const startTime = Date.now();
  let totalFiles = 0;
  let totalSize = 0;
  let largestFile: { path: string; size: number } | null = null;
  const filesByExtension = new Map<string, number>();

  const excludeDirs = new Set([
    'node_modules', '.git', 'vendor', 'dist', 'build',
    '__pycache__', 'venv', '.venv', 'target', '.next',
    '.nuxt', 'coverage', '.cache', 'tmp', 'temp',
  ]);

  async function scan(dirPath: string, depth: number = 0): Promise<void> {
    if (depth > 20 || totalFiles > THRESHOLDS.maxFiles) return;

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        if (totalFiles > THRESHOLDS.maxFiles) break;

        const fullPath = safePath(dirPath, entry.name);

        if (entry.isDirectory()) {
          if (!excludeDirs.has(entry.name) && !entry.name.startsWith('.')) {
            await scan(fullPath, depth + 1);
          }
        } else if (entry.isFile()) {
          try {
            const stats = await fs.stat(fullPath);
            totalFiles++;
            totalSize += stats.size;

            if (!largestFile || stats.size > largestFile.size) {
              largestFile = { path: fullPath, size: stats.size };
            }

            const ext = path.extname(entry.name).toLowerCase() || '(no ext)';
            filesByExtension.set(ext, (filesByExtension.get(ext) || 0) + 1);
          } catch {
            // Skip files we can't stat
          }
        }
      }
    } catch {
      // Skip directories we can't access
    }
  }

  await scan(repoPath);

  const isLargeRepo = totalFiles > 1000 || totalSize > 100 * 1024 * 1024;

  // Estimate analysis time (rough heuristic)
  const estimatedAnalysisTime = Math.min(
    THRESHOLDS.maxAnalysisTime,
    (totalFiles * 50) + (totalSize / 10000) // ~50ms per file + size factor
  );

  // Determine recommended strategy
  let recommendedStrategy: RepoStats['recommendedStrategy'] = 'full';
  if (totalFiles > 5000 || totalSize > 200 * 1024 * 1024) {
    recommendedStrategy = 'sampled';
  } else if (totalFiles > 1000 || totalSize > 50 * 1024 * 1024) {
    recommendedStrategy = 'chunked';
  }

  const stats: RepoStats = {
    totalFiles,
    totalSize,
    largestFile,
    filesByExtension,
    isLargeRepo,
    estimatedAnalysisTime,
    recommendedStrategy,
  };

  logger.info(
    {
      repoPath,
      totalFiles,
      totalSizeMB: Math.round(totalSize / 1024 / 1024),
      isLargeRepo,
      recommendedStrategy,
      durationMs: Date.now() - startTime,
    },
    'Repository scan completed'
  );

  return stats;
}

/**
 * Get files from repository with optional filtering
 */
async function getFiles(
  repoPath: string,
  extensions: string[],
  maxFiles: number
): Promise<FileInfo[]> {
  const files: FileInfo[] = [];

  const excludeDirs = new Set([
    'node_modules', '.git', 'vendor', 'dist', 'build',
    '__pycache__', 'venv', '.venv', 'target',
  ]);

  async function scan(dirPath: string, depth: number = 0): Promise<void> {
    if (depth > 15 || files.length >= maxFiles) return;

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        if (files.length >= maxFiles) break;

        const fullPath = safePath(dirPath, entry.name);
        const relativePath = path.relative(repoPath, fullPath);

        if (entry.isDirectory()) {
          if (!excludeDirs.has(entry.name)) {
            await scan(fullPath, depth + 1);
          }
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (extensions.includes(ext) || extensions.length === 0) {
            try {
              const stats = await fs.stat(fullPath);
              if (stats.size <= THRESHOLDS.maxFileSize) {
                files.push({
                  path: fullPath,
                  relativePath,
                  size: stats.size,
                  extension: ext,
                });
              }
            } catch {
              // Skip files we can't stat
            }
          }
        }
      }
    } catch {
      // Skip directories we can't access
    }
  }

  await scan(repoPath);
  return files;
}

/** Fisher-Yates shuffle (in-place, unbiased) */
function fisherYatesShuffle<T>(arr: T[]): T[] {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(0, i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/**
 * Sample files from a large repository
 */
export function sampleFiles(files: FileInfo[], sampleRatio: number): FileInfo[] {
  if (sampleRatio >= 1) return files;

  const targetCount = Math.max(100, Math.floor(files.length * sampleRatio));

  // Group files by extension to ensure representative sampling
  const byExtension = new Map<string, FileInfo[]>();
  for (const file of files) {
    const existing = byExtension.get(file.extension) || [];
    existing.push(file);
    byExtension.set(file.extension, existing);
  }

  const sampled: FileInfo[] = [];

  // Sample proportionally from each extension group
  for (const [, extFiles] of byExtension) {
    const extSampleCount = Math.ceil((extFiles.length / files.length) * targetCount);
    fisherYatesShuffle(extFiles);
    sampled.push(...extFiles.slice(0, extSampleCount));
  }

  // Ensure we have at least the minimum sample size
  if (sampled.length < targetCount) {
    const remaining = files.filter(f => !sampled.includes(f));
    fisherYatesShuffle(remaining);
    sampled.push(...remaining.slice(0, targetCount - sampled.length));
  }

  return sampled;
}

/**
 * Create analysis chunks from files
 */
export function createChunks(files: FileInfo[], chunkSize: number = THRESHOLDS.chunkSize): AnalysisChunk[] {
  const chunks: AnalysisChunk[] = [];

  for (let i = 0; i < files.length; i += chunkSize) {
    chunks.push({
      id: chunks.length,
      files: files.slice(i, i + chunkSize).map(f => f.path),
      status: 'pending',
    });
  }

  return chunks;
}

/**
 * Process files in chunks with a processor function
 */
export async function processInChunks<T>(
  repoPath: string,
  extensions: string[],
  processor: (files: string[]) => Promise<T[]>,
  options: {
    maxFiles?: number;
    chunkSize?: number;
    sampleRatio?: number;
    timeout?: number;
    onProgress?: (processed: number, total: number) => void;
  } = {}
): Promise<ChunkedAnalysisResult<T>> {
  const {
    maxFiles = THRESHOLDS.maxFiles,
    chunkSize = THRESHOLDS.chunkSize,
    sampleRatio = 1,
    timeout = THRESHOLDS.maxAnalysisTime,
    onProgress,
  } = options;

  logger.info(
    { repoPath, maxFiles, chunkSize, sampleRatio },
    'Starting chunked analysis'
  );

  const startTime = Date.now();
  const allResults: T[] = [];

  // Get files
  let files = await getFiles(repoPath, extensions, maxFiles);
  const totalFilesFound = files.length;

  // Sample if needed
  const wasSampled = sampleRatio < 1;
  if (wasSampled) {
    files = sampleFiles(files, sampleRatio);
    logger.info(
      { originalCount: totalFilesFound, sampledCount: files.length },
      'Sampled files for analysis'
    );
  }

  // Create chunks
  const chunks = createChunks(files, chunkSize);
  let chunksProcessed = 0;

  // Process chunks
  for (const chunk of chunks) {
    // Check timeout
    if (Date.now() - startTime > timeout) {
      logger.warn(
        { chunksProcessed, totalChunks: chunks.length },
        'Analysis timeout reached'
      );
      break;
    }

    try {
      chunk.status = 'processing';
      chunk.startTime = Date.now();

      const results = await processor(chunk.files);
      allResults.push(...results);

      chunk.status = 'completed';
      chunk.endTime = Date.now();
      chunksProcessed++;

      if (onProgress) {
        onProgress(chunksProcessed, chunks.length);
      }
    } catch (error) {
      chunk.status = 'failed';
      chunk.error = error instanceof Error ? error.message : 'Unknown error';
      logger.error({ chunkId: chunk.id, error: chunk.error }, 'Chunk processing failed');
    }
  }

  const processingTimeMs = Date.now() - startTime;

  logger.info(
    {
      chunksProcessed,
      totalChunks: chunks.length,
      totalResults: allResults.length,
      processingTimeMs,
      wasSampled,
    },
    'Chunked analysis completed'
  );

  return {
    results: allResults,
    chunksProcessed,
    totalChunks: chunks.length,
    totalFiles: files.length,
    processingTimeMs,
    wassampled: wasSampled,
    sampleRatio: wasSampled ? sampleRatio : undefined,
  };
}

/**
 * Estimate memory usage for analysis
 */
export function estimateMemoryUsage(stats: RepoStats): {
  estimatedMB: number;
  isMemorySafe: boolean;
  recommendation: string;
} {
  // Rough estimate: ~100 bytes per line of code on average
  // Plus overhead for parsed structures (avgBytesPerFile used for future optimizations)
  const _avgBytesPerFile = stats.totalSize / stats.totalFiles;
  void _avgBytesPerFile; // Reserved for future memory optimization logic
  const estimatedBytes = stats.totalSize + (stats.totalFiles * 1000); // 1KB overhead per file

  const estimatedMB = Math.round(estimatedBytes / 1024 / 1024);
  const isMemorySafe = estimatedMB < 1024; // Less than 1GB

  let recommendation = 'Full analysis is recommended.';
  if (estimatedMB > 2048) {
    recommendation = 'Consider using sampled analysis to reduce memory usage.';
  } else if (estimatedMB > 1024) {
    recommendation = 'Consider using chunked analysis for better memory management.';
  }

  return {
    estimatedMB,
    isMemorySafe,
    recommendation,
  };
}

/**
 * Get recommended analysis configuration
 */
export function getAnalysisConfig(stats: RepoStats): {
  strategy: 'full' | 'chunked' | 'sampled';
  maxFiles: number;
  chunkSize: number;
  sampleRatio: number;
  timeout: number;
} {
  if (stats.totalFiles <= 500 && stats.totalSize <= 50 * 1024 * 1024) {
    return {
      strategy: 'full',
      maxFiles: THRESHOLDS.maxFiles,
      chunkSize: stats.totalFiles,
      sampleRatio: 1,
      timeout: THRESHOLDS.maxAnalysisTime,
    };
  }

  if (stats.totalFiles <= 2000 && stats.totalSize <= 200 * 1024 * 1024) {
    return {
      strategy: 'chunked',
      maxFiles: THRESHOLDS.maxFiles,
      chunkSize: THRESHOLDS.chunkSize,
      sampleRatio: 1,
      timeout: THRESHOLDS.maxAnalysisTime,
    };
  }

  // Very large repository - use sampling
  return {
    strategy: 'sampled',
    maxFiles: Math.min(stats.totalFiles, 5000),
    chunkSize: THRESHOLDS.chunkSize,
    sampleRatio: Math.min(THRESHOLDS.sampleRatio, 2000 / stats.totalFiles),
    timeout: THRESHOLDS.maxAnalysisTime,
  };
}

/**
 * Progress tracker for long-running analysis
 */
export class AnalysisProgressTracker {
  private startTime: number;
  private totalSteps: number;
  private completedSteps: number = 0;
  private currentStep: string = '';

  constructor(totalSteps: number) {
    this.startTime = Date.now();
    this.totalSteps = totalSteps;
  }

  startStep(stepName: string): void {
    this.currentStep = stepName;
    logger.debug({ step: stepName, progress: this.getProgress() }, 'Starting analysis step');
  }

  completeStep(): void {
    this.completedSteps++;
    logger.debug(
      { step: this.currentStep, progress: this.getProgress() },
      'Completed analysis step'
    );
  }

  getProgress(): {
    completed: number;
    total: number;
    percentage: number;
    elapsedMs: number;
    estimatedRemainingMs: number;
  } {
    const percentage = Math.round((this.completedSteps / this.totalSteps) * 100);
    const elapsedMs = Date.now() - this.startTime;
    const avgTimePerStep = this.completedSteps > 0 ? elapsedMs / this.completedSteps : 0;
    const estimatedRemainingMs = avgTimePerStep * (this.totalSteps - this.completedSteps);

    return {
      completed: this.completedSteps,
      total: this.totalSteps,
      percentage,
      elapsedMs,
      estimatedRemainingMs,
    };
  }
}
