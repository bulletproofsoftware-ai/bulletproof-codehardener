'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import {
  Plus,
  Search,
  Filter,
  ScanSearch,
  CheckCircle2,
  AlertCircle,
  XCircle,
  Clock,
  Loader2,
  RefreshCw,
  Eye,
  MoreHorizontal,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatRelativeTime, getScoreLevel } from '@/lib/utils';
import { SeverityDot } from '@/components/SeverityBadge';
import { EmptyState } from '@/components/EmptyState';
import { useScans } from '@/hooks/useApi';
import { scansApi } from '@/lib/api';
import type { Scan } from '@/types';

function getScoreColor(level: string): string {
  const colors: Record<string, string> = {
    excellent: '#22c55e',
    good: '#06b6d4',
    medium: '#eab308',
    high: '#f97316',
    critical: '#ef4444',
  };
  return colors[level] ?? '#6b7280';
}

function getScanStatusInfo(scan: Scan): {
  icon: React.ReactNode;
  label: string;
  color: string;
} {
  switch (scan.status) {
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
    case 'cancelled':
      return {
        icon: <XCircle className="h-4 w-4" />,
        label: 'Cancelled',
        color: 'text-text-tertiary',
      };
    case 'completed': {
      const total = scan.findingsCount.critical + scan.findingsCount.high +
        scan.findingsCount.medium + scan.findingsCount.low;
      if (total === 0) {
        return {
          icon: <CheckCircle2 className="h-4 w-4" />,
          label: 'Clean',
          color: 'text-success',
        };
      }
      if (scan.findingsCount.critical > 0) {
        return {
          icon: <AlertCircle className="h-4 w-4" />,
          label: 'Critical',
          color: 'text-error',
        };
      }
      if (scan.findingsCount.high > 0) {
        return {
          icon: <AlertCircle className="h-4 w-4" />,
          label: 'Issues Found',
          color: 'text-warning',
        };
      }
      return {
        icon: <CheckCircle2 className="h-4 w-4" />,
        label: 'Completed',
        color: 'text-success',
      };
    }
    default:
      return {
        icon: <Clock className="h-4 w-4" />,
        label: 'Unknown',
        color: 'text-text-tertiary',
      };
  }
}

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

export default function ScansPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  // Build query params
  const queryParams = useMemo(() => {
    const params: { page: number; limit: number; status?: Scan['status'] } = {
      page,
      limit: 20,
    };
    if (statusFilter !== 'all') {
      params.status = statusFilter as Scan['status'];
    }
    return params;
  }, [page, statusFilter]);

  const { data: scansResponse, isLoading, error: scansError, refetch: refetchScans } = useScans(queryParams);
  const scans = scansResponse?.data ?? [];
  const totalPages = scansResponse?.pagination?.totalPages ?? 1;
  const error = scansError?.message ?? null;

  const handleCancel = async (id: string) => {
    try {
      setActionLoading(id);
      await scansApi.cancel(id);
      // Refresh the scan list
      await refetchScans();
      setActiveMenu(null);
    } catch (err) {
      console.error('Failed to cancel scan:', err);
      alert(err instanceof Error ? err.message : 'Failed to cancel scan');
    } finally {
      setActionLoading(null);
    }
  };

  const filteredScans = scans.filter((scan) => {
    const matchesSearch =
      scan.projectName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      scan.id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSearch;
  });

  if (isLoading && scans.length === 0) {
    return <ScansPageSkeleton />;
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-error mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load scans</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={() => refetchScans()}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Scans</h1>
          <p className="text-text-secondary mt-1">
            View and manage security scans across all projects
          </p>
        </div>
        <Link href="/scans/new" className="btn-primary">
          <Plus className="h-4 w-4" />
          New Scan
        </Link>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-tertiary" />
          <input
            type="search"
            placeholder="Search scans..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input pl-10 w-full"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(1);
          }}
          className="input w-full sm:w-40"
        >
          <option value="all">All Status</option>
          <option value="completed">Completed</option>
          <option value="running">Running</option>
          <option value="pending">Pending</option>
          <option value="failed">Failed</option>
        </select>
        <button className="btn-secondary">
          <Filter className="h-4 w-4" />
          More Filters
        </button>
      </div>

      {/* Scans Table */}
      {filteredScans.length === 0 ? (
        searchQuery || statusFilter !== 'all' ? (
          <EmptyState
            icon={Search}
            title="No scans found"
            description="Try adjusting your filters"
            secondaryAction={{
              label: 'Clear filters',
              onClick: () => {
                setSearchQuery('');
                setStatusFilter('all');
              },
            }}
          />
        ) : (
          <EmptyState
            icon={ScanSearch}
            title="No scans yet"
            description="Run your first scan to start identifying security vulnerabilities"
            action={{ label: 'Run First Scan', href: '/scans/new' }}
          />
        )
      ) : (
        <div className="card p-0">
          <table className="w-full">
            <thead>
              <tr className="text-left text-xs font-medium text-text-tertiary uppercase tracking-wide border-b border-border-primary">
                <th className="px-4 py-3">Project</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Findings</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Duration</th>
                <th className="px-4 py-3">Date</th>
                <th className="px-4 py-3 w-16">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-primary">
              {filteredScans.map((scan) => {
                const status = getScanStatusInfo(scan);
                return (
                  <tr
                    key={scan.id}
                    className="hover:bg-bg-hover cursor-pointer"
                    onClick={() => (window.location.href = `/scans/${scan.id}`)}
                  >
                    <td className="px-4 py-3">
                      <Link
                        href={`/projects/${scan.projectId}`}
                        className="font-medium text-text-primary hover:text-primary-500"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {scan.projectName}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      {scan.score !== undefined ? (
                        <span
                          className="font-semibold"
                          style={{
                            color: getScoreColor(getScoreLevel(scan.score)),
                          }}
                        >
                          {scan.score}
                        </span>
                      ) : (
                        <span className="text-text-tertiary">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn('flex items-center gap-1.5', status.color)}
                      >
                        {status.icon}
                        <span className="text-sm">{status.label}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {scan.status === 'completed' ? (
                        <div className="flex items-center gap-2 text-sm">
                          {scan.findingsCount.critical > 0 && (
                            <span className="flex items-center gap-1 text-error">
                              <SeverityDot severity="critical" size="sm" />
                              {scan.findingsCount.critical}
                            </span>
                          )}
                          {scan.findingsCount.high > 0 && (
                            <span className="flex items-center gap-1 text-orange-500">
                              <SeverityDot severity="high" size="sm" />
                              {scan.findingsCount.high}
                            </span>
                          )}
                          {scan.findingsCount.medium > 0 && (
                            <span className="flex items-center gap-1 text-warning">
                              <SeverityDot severity="medium" size="sm" />
                              {scan.findingsCount.medium}
                            </span>
                          )}
                          {scan.findingsCount.critical === 0 &&
                            scan.findingsCount.high === 0 &&
                            scan.findingsCount.medium === 0 && (
                              <span className="text-success text-sm">
                                No issues
                              </span>
                            )}
                        </div>
                      ) : (
                        <span className="text-text-tertiary">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          'text-xs px-2 py-0.5 rounded',
                          scan.scanType === 'quick'
                            ? 'bg-info/10 text-info'
                            : scan.scanType === 'comprehensive'
                            ? 'bg-accent-500/10 text-accent-500'
                            : 'bg-primary-500/10 text-primary-500'
                        )}
                      >
                        {scan.scanType.charAt(0).toUpperCase() +
                          scan.scanType.slice(1)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-text-secondary">
                        {scan.duration ? formatDuration(scan.duration) : '-'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-text-tertiary">
                        {formatRelativeTime(scan.createdAt)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div
                        className="relative"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <button
                          onClick={() =>
                            setActiveMenu(
                              activeMenu === scan.id ? null : scan.id
                            )
                          }
                          disabled={actionLoading === scan.id}
                          className="btn-icon text-text-tertiary hover:text-text-secondary"
                        >
                          {actionLoading === scan.id ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <MoreHorizontal className="h-4 w-4" />
                          )}
                        </button>

                        {activeMenu === scan.id && (
                          <>
                            <div
                              className="fixed inset-0 z-10"
                              onClick={() => setActiveMenu(null)}
                            />
                            <div className="absolute right-0 mt-1 w-40 dropdown-menu z-20">
                              <Link
                                href={`/scans/${scan.id}`}
                                className="dropdown-item"
                                onClick={() => setActiveMenu(null)}
                              >
                                <Eye className="h-4 w-4" />
                                View Details
                              </Link>
                              {scan.status === 'running' && (
                                <button
                                  className="dropdown-item w-full text-left"
                                  onClick={() => handleCancel(scan.id)}
                                >
                                  <XCircle className="h-4 w-4" />
                                  Cancel Scan
                                </button>
                              )}
                              {scan.status === 'completed' && (
                                <Link
                                  href={`/scans/new?project=${scan.projectId}`}
                                  className="dropdown-item"
                                  onClick={() => setActiveMenu(null)}
                                >
                                  <RefreshCw className="h-4 w-4" />
                                  Rescan
                                </Link>
                              )}
                            </div>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {filteredScans.length > 0 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-text-tertiary">
            Showing {filteredScans.length} scans
          </p>
          <div className="flex items-center gap-2">
            <button
              className="btn-secondary btn-sm"
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
            >
              Previous
            </button>
            <span className="px-3 py-1 text-sm text-text-secondary">
              Page {page} of {totalPages}
            </span>
            <button
              className="btn-secondary btn-sm"
              disabled={page >= totalPages}
              onClick={() => setPage(page + 1)}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function ScansPageSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="skeleton h-8 w-24" />
          <div className="skeleton h-4 w-64 mt-2" />
        </div>
        <div className="skeleton h-10 w-28" />
      </div>

      <div className="flex gap-3">
        <div className="skeleton h-10 flex-1" />
        <div className="skeleton h-10 w-40" />
        <div className="skeleton h-10 w-32" />
      </div>

      <div className="card p-0">
        <div className="border-b border-border-primary">
          <div className="flex gap-4 p-4">
            {[...Array(8)].map((_, i) => (
              <div key={i} className="skeleton h-4 w-16" />
            ))}
          </div>
        </div>
        {[...Array(5)].map((_, i) => (
          <div
            key={i}
            className="flex items-center gap-4 p-4 border-b border-border-primary last:border-0"
          >
            <div className="skeleton h-4 w-32" />
            <div className="skeleton h-4 w-12" />
            <div className="skeleton h-4 w-16" />
            <div className="skeleton h-4 w-24" />
            <div className="skeleton h-4 w-16" />
            <div className="skeleton h-4 w-12" />
            <div className="skeleton h-4 w-16" />
            <div className="skeleton h-4 w-8" />
          </div>
        ))}
      </div>
    </div>
  );
}
