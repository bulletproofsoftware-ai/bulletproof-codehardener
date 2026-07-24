'use client';

import { useState, useEffect, useCallback } from 'react';
import {
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  RefreshCw,
  FileCode2,
  AlertCircle,
  ChevronRight,
  TestTube2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatRelativeTime } from '@/lib/utils';
import { EmptyState } from '@/components/EmptyState';
import { testsApi } from '@/lib/api';

interface TestFile {
  name: string;
  path: string;
  tests: number;
  passed: number;
  failed: number;
  duration: number;
}

interface TestResults {
  total: number;
  passed: number;
  failed: number;
  skipped?: number;
  files?: TestFile[];
}

interface TestRun {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt: string;
  completedAt?: string;
  duration?: number;
  testType: string;
  coverage: boolean;
  results?: TestResults;
  recentOutput?: string[];
  output?: string[];
  error?: string;
}

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

function getStatusInfo(status: string): {
  icon: React.ReactNode;
  label: string;
  color: string;
} {
  switch (status) {
    case 'running':
      return {
        icon: <Loader2 className="h-4 w-4 animate-spin" />,
        label: 'Running',
        color: 'text-primary-500',
      };
    case 'pending':
      return {
        icon: <Clock className="h-4 w-4" />,
        label: 'Pending',
        color: 'text-text-tertiary',
      };
    case 'failed':
      return {
        icon: <XCircle className="h-4 w-4" />,
        label: 'Failed',
        color: 'text-error',
      };
    case 'completed':
      return {
        icon: <CheckCircle2 className="h-4 w-4" />,
        label: 'Completed',
        color: 'text-success',
      };
    default:
      return {
        icon: <Clock className="h-4 w-4" />,
        label: 'Unknown',
        color: 'text-text-tertiary',
      };
  }
}

export default function TestsPage() {
  const [isRunning, setIsRunning] = useState(false);
  const [currentRun, setCurrentRun] = useState<TestRun | null>(null);
  const [history, setHistory] = useState<TestRun[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [testType, setTestType] = useState<string>('unit');
  const [withCoverage, setWithCoverage] = useState(false);
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(new Set());
  const [showOutput, setShowOutput] = useState(false);
  const [historyFetched, setHistoryFetched] = useState(false);

  // Fetch test history on mount (once only)
  const fetchHistory = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const response = await testsApi.getHistory({ limit: 20 });
      setHistory(response.data || []);
    } catch (err) {
      console.error('Failed to fetch test history:', err);
      // Don't show error for expected failures when backend is unreachable
      if (err instanceof Error && !err.message.includes('fetch')) {
        setError(err.message);
      }
      setHistory([]);
    } finally {
      setIsLoading(false);
      setHistoryFetched(true);
    }
  }, []);

  useEffect(() => {
    if (!historyFetched) {
      fetchHistory();
    }
  }, [historyFetched, fetchHistory]);

  // Poll for status when a test is running
  useEffect(() => {
    if (!currentRun || (currentRun.status !== 'pending' && currentRun.status !== 'running')) {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const status = await testsApi.getStatus(currentRun.id);
        setCurrentRun(status);

        if (status.status === 'completed' || status.status === 'failed') {
          setIsRunning(false);
          // Refresh history after completion
          setHistoryFetched(false);
        }
      } catch (err) {
        console.error('Failed to get test status:', err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [currentRun?.id, currentRun?.status]);

  async function runTests() {
    try {
      setIsRunning(true);
      setError(null);
      setCurrentRun(null);
      setShowOutput(true);

      const response = await testsApi.run({
        testType: testType as 'unit' | 'integration' | 'all',
        coverage: withCoverage,
      });

      // Get initial status
      const status = await testsApi.getStatus(response.runId);
      setCurrentRun(status);
    } catch (err) {
      console.error('Failed to run tests:', err);
      setError(err instanceof Error ? err.message : 'Failed to start test run');
      setIsRunning(false);
    }
  }

  async function viewRunDetails(runId: string) {
    try {
      const details = await testsApi.getDetails(runId);
      setCurrentRun(details);
      setShowOutput(true);
    } catch (err) {
      console.error('Failed to get run details:', err);
    }
  }

  const toggleFileExpand = useCallback((path: string) => {
    setExpandedFiles(prev => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  }, []);

  if (isLoading && !historyFetched) {
    return <TestsPageSkeleton />;
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Test Runner</h1>
          <p className="text-text-secondary mt-1">
            Run and monitor backend unit tests
          </p>
        </div>
        <button
          onClick={runTests}
          disabled={isRunning}
          className="btn-primary"
        >
          {isRunning ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Running...
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              Run Tests
            </>
          )}
        </button>
      </div>

      {/* Test Options */}
      <div className="card p-4">
        <h3 className="text-sm font-medium text-text-primary mb-3">Test Options</h3>
        <div className="flex flex-wrap gap-4">
          <div className="flex items-center gap-2">
            <label className="text-sm text-text-secondary">Type:</label>
            <select
              value={testType}
              onChange={(e) => setTestType(e.target.value as 'unit' | 'integration' | 'all')}
              disabled={isRunning}
              className="input w-32"
            >
              <option value="unit">Unit</option>
              <option value="integration">Integration</option>
              <option value="all">All</option>
            </select>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={withCoverage}
              onChange={(e) => setWithCoverage(e.target.checked)}
              disabled={isRunning}
              className="form-checkbox h-4 w-4 text-primary-500 rounded border-border-primary"
            />
            <span className="text-sm text-text-secondary">With Coverage</span>
          </label>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="card p-4 bg-error/10 border-error">
          <div className="flex items-center gap-2 text-error">
            <AlertCircle className="h-5 w-5" />
            <span className="font-medium">Error</span>
          </div>
          <p className="text-sm text-text-secondary mt-1">{error}</p>
        </div>
      )}

      {/* Current Run Status */}
      {currentRun && showOutput && (
        <div className="card p-0 overflow-hidden">
          <div className="p-4 border-b border-border-primary bg-bg-secondary">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className={cn('flex items-center gap-1.5', getStatusInfo(currentRun.status).color)}>
                  {getStatusInfo(currentRun.status).icon}
                  <span className="font-medium">{getStatusInfo(currentRun.status).label}</span>
                </span>
                {currentRun.duration && (
                  <span className="text-sm text-text-tertiary">
                    {formatDuration(currentRun.duration)}
                  </span>
                )}
              </div>
              <button
                onClick={() => setShowOutput(false)}
                className="text-text-tertiary hover:text-text-secondary"
              >
                <XCircle className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Test Results Summary */}
          {currentRun.results && (
            <div className="p-4 border-b border-border-primary">
              <div className="flex items-center gap-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-text-primary">{currentRun.results.total}</div>
                  <div className="text-xs text-text-tertiary">Total</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-success">{currentRun.results.passed}</div>
                  <div className="text-xs text-text-tertiary">Passed</div>
                </div>
                <div className="text-center">
                  <div className={cn('text-2xl font-bold', currentRun.results.failed > 0 ? 'text-error' : 'text-text-primary')}>
                    {currentRun.results.failed}
                  </div>
                  <div className="text-xs text-text-tertiary">Failed</div>
                </div>
                {currentRun.results.skipped !== undefined && currentRun.results.skipped > 0 && (
                  <div className="text-center">
                    <div className="text-2xl font-bold text-warning">{currentRun.results.skipped}</div>
                    <div className="text-xs text-text-tertiary">Skipped</div>
                  </div>
                )}
              </div>

              {/* File breakdown */}
              {currentRun.results.files && currentRun.results.files.length > 0 && (
                <div className="mt-4 space-y-2">
                  <h4 className="text-sm font-medium text-text-secondary">Test Files</h4>
                  {currentRun.results.files.map((file) => (
                    <div key={file.path}>
                      <div
                        className="flex items-center justify-between p-2 rounded-md bg-bg-secondary hover:bg-bg-hover cursor-pointer"
                        onClick={() => toggleFileExpand(file.path)}
                      >
                        <div className="flex items-center gap-2">
                          <ChevronRight className={cn("h-4 w-4 text-text-tertiary transition-transform", expandedFiles.has(file.path) && "rotate-90")} />
                          <FileCode2 className="h-4 w-4 text-text-tertiary" />
                          <span className="text-sm text-text-primary">{file.name}</span>
                        </div>
                        <div className="flex items-center gap-4 text-sm">
                          <span className="text-success">{file.passed} passed</span>
                          {file.failed > 0 && <span className="text-error">{file.failed} failed</span>}
                          <span className="text-text-tertiary">{file.duration}ms</span>
                        </div>
                      </div>
                      {expandedFiles.has(file.path) && (
                        <div className="ml-8 mt-1 mb-2 text-xs text-text-tertiary font-mono">
                          {file.path}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Console Output */}
          <div className="p-4">
            <h4 className="text-sm font-medium text-text-secondary mb-2">Console Output</h4>
            <div className="bg-gray-900 text-gray-100 p-4 rounded-lg font-mono text-xs overflow-x-auto max-h-80 overflow-y-auto">
              {(currentRun.output || currentRun.recentOutput || []).map((line, i) => (
                <div key={i} className="whitespace-pre-wrap">{line}</div>
              ))}
              {(currentRun.status === 'pending' || currentRun.status === 'running') && (
                <div className="flex items-center gap-2 text-primary-400 mt-2">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  <span>Running tests...</span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Test History */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-text-primary">Test History</h2>
          <button onClick={() => setHistoryFetched(false)} className="btn-secondary btn-sm">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>

        {history.length === 0 ? (
          <EmptyState
            icon={TestTube2}
            title="No test runs yet"
            description="Run your first test to see results here"
            action={{
              label: 'Run Tests',
              onClick: runTests,
            }}
          />
        ) : (
          <div className="card p-0 overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="text-left text-xs font-medium text-text-tertiary uppercase tracking-wide border-b border-border-primary">
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Results</th>
                  <th className="px-4 py-3">Duration</th>
                  <th className="px-4 py-3">Date</th>
                  <th className="px-4 py-3 w-16"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-primary">
                {history.map((run) => {
                  const status = getStatusInfo(run.status);
                  return (
                    <tr
                      key={run.id}
                      className="hover:bg-bg-hover cursor-pointer"
                      onClick={() => viewRunDetails(run.id)}
                    >
                      <td className="px-4 py-3">
                        <span className={cn('flex items-center gap-1.5', status.color)}>
                          {status.icon}
                          <span className="text-sm">{status.label}</span>
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs px-2 py-0.5 rounded bg-primary-500/10 text-primary-500">
                          {run.testType}
                        </span>
                        {run.coverage && (
                          <span className="text-xs px-2 py-0.5 rounded bg-accent-500/10 text-accent-500 ml-1">
                            coverage
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {run.results ? (
                          <div className="flex items-center gap-2 text-sm">
                            <span className="text-success">{run.results.passed}</span>
                            <span className="text-text-tertiary">/</span>
                            <span className={run.results.failed > 0 ? 'text-error' : 'text-text-primary'}>
                              {run.results.failed}
                            </span>
                            <span className="text-text-tertiary">/</span>
                            <span className="text-text-secondary">{run.results.total}</span>
                          </div>
                        ) : run.error ? (
                          <span className="text-sm text-error">Error</span>
                        ) : (
                          <span className="text-text-tertiary">-</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-text-secondary">
                          {run.duration ? formatDuration(run.duration) : '-'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-text-tertiary">
                          {formatRelativeTime(run.startedAt)}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <ChevronRight className="h-4 w-4 text-text-tertiary" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function TestsPageSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="skeleton h-8 w-32" />
          <div className="skeleton h-4 w-48 mt-2" />
        </div>
        <div className="skeleton h-10 w-28" />
      </div>

      <div className="card p-4">
        <div className="skeleton h-4 w-24 mb-3" />
        <div className="flex gap-4">
          <div className="skeleton h-10 w-40" />
          <div className="skeleton h-10 w-32" />
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-4">
          <div className="skeleton h-6 w-28" />
          <div className="skeleton h-8 w-24" />
        </div>
        <div className="card p-0">
          <div className="border-b border-border-primary">
            <div className="flex gap-4 p-4">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="skeleton h-4 w-16" />
              ))}
            </div>
          </div>
          {[...Array(5)].map((_, i) => (
            <div
              key={i}
              className="flex items-center gap-4 p-4 border-b border-border-primary last:border-0"
            >
              <div className="skeleton h-4 w-20" />
              <div className="skeleton h-4 w-16" />
              <div className="skeleton h-4 w-24" />
              <div className="skeleton h-4 w-16" />
              <div className="skeleton h-4 w-20" />
              <div className="skeleton h-4 w-4" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
