'use client';

import Link from 'next/link';
import {
  Plus,
  FolderKanban,
  ScanSearch,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  XCircle,
  Clock,
  TrendingUp,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatRelativeTime, getScoreLevel } from '@/lib/utils';
import { ScoreGauge } from '@/components/ScoreGauge';
import { StatsCard, StatsCardSkeleton } from '@/components/StatsCard';
import { SeverityDot, SeverityBadge } from '@/components/SeverityBadge';
import { EmptyState } from '@/components/EmptyState';
import { useDashboardSummary, useCurrentUser } from '@/hooks/useApi';
import type { Scan, ScoreHistoryPoint } from '@/types';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';

// Check if running in dev mode (only check on client side)
const isDevMode = () => {
  if (typeof window === 'undefined') return false;
  return process.env.NEXT_PUBLIC_DEV_MODE === 'true' || window.location.hostname === 'localhost';
};

function getGreeting(): string {
  const hour = new Date().getHours();
  if (hour < 12) return 'Good morning';
  if (hour < 17) return 'Good afternoon';
  return 'Good evening';
}

function getScanStatusIcon(scan: Scan) {
  if (scan.findingsCount.critical > 0) {
    return <XCircle className="h-4 w-4 text-error" />;
  }
  if (scan.findingsCount.high > 0) {
    return <AlertCircle className="h-4 w-4 text-warning" />;
  }
  return <CheckCircle2 className="h-4 w-4 text-success" />;
}

function getScanStatusLabel(scan: Scan) {
  if (scan.findingsCount.critical > 0) return 'Failed';
  if (scan.findingsCount.high > 0) return 'Warning';
  return 'Pass';
}

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

export default function DashboardPage() {
  // In dev mode, remove any stored JWT so the X-User-Id header is used instead.
  // Must run synchronously before React Query hooks fire to prevent stale token race.
  if (typeof window !== 'undefined' && isDevMode()) {
    localStorage.removeItem('auth_token');
  }

  const { data: summary, isLoading: summaryLoading, error: summaryError, refetch: refetchSummary } = useDashboardSummary();
  const { data: user, isLoading: userLoading } = useCurrentUser();

  const isLoading = summaryLoading || userLoading;
  const error = summaryError?.message || null;

  if (isLoading) {
    return <DashboardSkeleton />;
  }

  if (error) {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="h-12 w-12 text-error mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load dashboard</h2>
          <p className="text-text-secondary mb-4">{error}</p>
          <button
            onClick={() => refetchSummary()}
            className="btn-primary"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  if (!summary) {
    return <DashboardSkeleton />;
  }

  // Extract data from summary
  const recentScans = summary.recentScans || [];
  const projects = summary.recentProjects || [];
  const criticalFindings = summary.criticalFindings || [];

  // Empty state checks
  const hasProjects = projects.length > 0 || summary.projectCount > 0;
  const hasScans = recentScans.length > 0;
  const hasCriticalFindings = criticalFindings.length > 0;

  // Get user's first name for greeting
  const firstName = user?.name?.split(' ')[0] || user?.email?.split('@')[0] || 'there';

  // No projects - welcome state
  if (!hasProjects) {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <EmptyState
          icon={FolderKanban}
          title="Welcome to Code Hardener!"
          description="Create your first project to start scanning for vulnerabilities and securing your code."
          action={{ label: 'Create Project', href: '/projects/new' }}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Welcome Section */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">
            {getGreeting()}, {firstName}
          </h1>
          <p className="text-text-secondary mt-1">
            Here&apos;s your security overview
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link href="/projects" className="btn-secondary">
            <FolderKanban className="h-4 w-4" />
            View Projects
          </Link>
          <Link href="/scans/new" className="btn-primary">
            <Plus className="h-4 w-4" />
            New Scan
          </Link>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Score Card */}
        <div className="card p-6 flex flex-col items-center justify-center">
          <span className="text-sm font-medium text-text-tertiary uppercase tracking-wide mb-4">
            Score
          </span>
          <ScoreGauge
            score={summary.qualityScore}
            size="md"
            trend={summary.scoreTrend}
          />
        </div>

        {/* Open Findings Card */}
        <StatsCard
          title="Open Findings"
          value={summary.openFindings.total}
          href="/findings"
          subtitle={
            <div className="flex items-center gap-3 flex-wrap">
              <span className="flex items-center gap-1">
                <SeverityDot severity="critical" />
                <span>{summary.openFindings.critical} Critical</span>
              </span>
              <span className="flex items-center gap-1">
                <SeverityDot severity="high" />
                <span>{summary.openFindings.high} High</span>
              </span>
              <span className="flex items-center gap-1">
                <SeverityDot severity="medium" />
                <span>{summary.openFindings.medium} Medium</span>
              </span>
              <span className="flex items-center gap-1">
                <SeverityDot severity="low" />
                <span>{summary.openFindings.low} Low</span>
              </span>
            </div>
          }
        />

        {/* Scans This Month Card */}
        <StatsCard
          title="Scans This Month"
          value={summary.scansThisMonth}
          href="/scans"
          progress={
            summary.scanLimit
              ? { current: summary.scansThisMonth, max: summary.scanLimit }
              : { current: summary.scansThisMonth, max: null }
          }
        />
      </div>

      {/* Score Trendline */}
      {summary.scoreHistory && summary.scoreHistory.length >= 2 && (
        <ScoreTrendChart data={summary.scoreHistory} />
      )}

      {/* Recent Scans & Projects Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Scans Table - spans 2 columns */}
        <div className="lg:col-span-2">
          <div className="card">
            <div className="flex items-center justify-between p-4 border-b border-border-primary">
              <h2 className="font-semibold text-text-primary">Recent Scans</h2>
              <Link
                href="/scans"
                className="text-sm text-primary-500 hover:text-primary-400 flex items-center gap-1"
              >
                View all
                <ArrowRight className="h-3 w-3" />
              </Link>
            </div>

            {!hasScans ? (
              <EmptyState
                icon={ScanSearch}
                title="No scans yet"
                description="Run your first scan to see your security score"
                action={{ label: 'Run First Scan', href: '/scans/new' }}
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-left text-xs font-medium text-text-tertiary uppercase tracking-wide">
                      <th className="px-4 py-3">Project</th>
                      <th className="px-4 py-3">Score</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Findings</th>
                      <th className="px-4 py-3">Date</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-primary">
                    {recentScans.slice(0, 5).map((scan) => (
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
                          <span
                            className={cn(
                              'font-semibold',
                              scan.score !== undefined &&
                                `text-score-${getScoreLevel(scan.score)}`
                            )}
                            style={{
                              color:
                                scan.score !== undefined
                                  ? getScoreColor(getScoreLevel(scan.score))
                                  : undefined,
                            }}
                          >
                            {scan.score ?? '-'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="flex items-center gap-1.5 text-sm">
                            {getScanStatusIcon(scan)}
                            {getScanStatusLabel(scan)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm text-text-secondary">
                            {scan.findingsCount.critical > 0 && (
                              <span className="text-error">
                                {scan.findingsCount.critical} critical
                              </span>
                            )}
                            {scan.findingsCount.critical > 0 &&
                              scan.findingsCount.high > 0 &&
                              ', '}
                            {scan.findingsCount.high > 0 && (
                              <span className="text-orange-500">
                                {scan.findingsCount.high} high
                              </span>
                            )}
                            {scan.findingsCount.critical === 0 &&
                              scan.findingsCount.high === 0 && (
                                <span className="text-success">No critical issues</span>
                              )}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm text-text-tertiary">
                            {formatRelativeTime(scan.createdAt)}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Projects Quick View */}
        <div className="card">
          <div className="flex items-center justify-between p-4 border-b border-border-primary">
            <h2 className="font-semibold text-text-primary">Projects</h2>
            <Link
              href="/projects"
              className="text-sm text-primary-500 hover:text-primary-400 flex items-center gap-1"
            >
              View all
              <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          <div className="divide-y divide-border-primary">
            {projects.slice(0, 4).map((project) => (
              <Link
                key={project.id}
                href={`/projects/${project.id}`}
                className="block p-4 hover:bg-bg-hover transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-text-primary">{project.name}</span>
                  {project.lastScore !== undefined && project.lastScore !== null && (
                    <span
                      className="text-sm font-semibold"
                      style={{ color: getScoreColor(getScoreLevel(project.lastScore)) }}
                    >
                      {project.lastScore}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 mt-1 text-xs text-text-tertiary">
                  <Clock className="h-3 w-3" />
                  {project.lastScanAt
                    ? `Last scan ${formatRelativeTime(project.lastScanAt)}`
                    : 'Never scanned'}
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>

      {/* Critical Findings Panel */}
      <div className="card">
        <div className="flex items-center justify-between p-4 border-b border-border-primary">
          <h2 className="font-semibold text-text-primary flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-error" />
            Critical Findings
            {hasCriticalFindings && (
              <span className="text-sm font-normal text-text-secondary">
                ({criticalFindings.length})
              </span>
            )}
          </h2>
          {hasCriticalFindings && (
            <Link
              href="/findings?severity=critical"
              className="text-sm text-primary-500 hover:text-primary-400 flex items-center gap-1"
            >
              View all
              <ArrowRight className="h-3 w-3" />
            </Link>
          )}
        </div>

        {!hasCriticalFindings ? (
          <div className="p-8 text-center">
            <div className="w-12 h-12 rounded-full bg-success/10 flex items-center justify-center mx-auto mb-3">
              <CheckCircle2 className="h-6 w-6 text-success" />
            </div>
            <p className="text-text-primary font-medium">No critical findings</p>
            <p className="text-sm text-text-secondary mt-1">
              Your code is looking secure!
            </p>
          </div>
        ) : (
          <div className="divide-y divide-border-primary">
            {criticalFindings.map((finding) => (
              <Link
                key={finding.id}
                href={`/findings/${finding.id}`}
                className="block p-4 hover:bg-bg-hover transition-colors"
              >
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-error flex-shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-text-primary">
                        {finding.titleSimple}
                      </span>
                      {finding.fixAvailable && (
                        <span className="text-xs bg-success/10 text-success px-1.5 py-0.5 rounded">
                          Fix Available
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-text-secondary mt-0.5">
                      {finding.filePath}:{finding.lineNumber}
                    </p>
                    <div className="flex items-center gap-2 mt-2 text-xs text-text-tertiary">
                      <span>{finding.projectName || 'Project'}</span>
                      <span>-</span>
                      <span>{finding.createdAt ? formatRelativeTime(finding.createdAt) : 'Unknown'}</span>
                    </div>
                  </div>
                  <SeverityBadge severity={finding.severity} size="sm" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ScoreTrendChart({ data }: { data: ScoreHistoryPoint[] }) {
  const chartData = data.map((point, idx) => ({
    label: `Scan ${idx + 1}`,
    score: point.score,
    date: new Date(point.date).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
    }),
    project: point.project,
  }));

  const minScore = Math.min(...data.map((d) => d.score));
  const yMin = Math.max(0, Math.floor((minScore - 50) / 100) * 100);

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-semibold text-text-primary flex items-center gap-2">
          <TrendingUp className="h-5 w-5 text-primary-500" />
          Score Trend
        </h2>
        <span className="text-xs text-text-tertiary">{data.length} scans</span>
      </div>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
            <XAxis
              dataKey="date"
              tick={{ fill: '#9ca3af', fontSize: 11 }}
              axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
              tickLine={false}
            />
            <YAxis
              domain={[yMin, 1000]}
              tick={{ fill: '#9ca3af', fontSize: 11 }}
              axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
              tickLine={false}
              width={40}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e293b',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                color: '#e2e8f0',
                fontSize: '13px',
              }}
              formatter={(value: number) => [value, 'Score']}
              labelFormatter={(label: string) => label}
            />
            <ReferenceLine
              y={900}
              stroke="#22c55e"
              strokeDasharray="3 3"
              strokeOpacity={0.4}
              label={{ value: 'Excellent', fill: '#22c55e', fontSize: 10, position: 'right' }}
            />
            <Area
              type="monotone"
              dataKey="score"
              stroke="#06b6d4"
              strokeWidth={2.5}
              fill="url(#scoreGradient)"
              dot={{ r: 4, fill: '#06b6d4', stroke: '#0e1729', strokeWidth: 2 }}
              activeDot={{ r: 6, fill: '#06b6d4', stroke: '#fff', strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      {/* Welcome skeleton */}
      <div className="flex items-center justify-between">
        <div>
          <div className="skeleton h-8 w-64" />
          <div className="skeleton h-4 w-48 mt-2" />
        </div>
        <div className="flex gap-3">
          <div className="skeleton h-10 w-32" />
          <div className="skeleton h-10 w-28" />
        </div>
      </div>

      {/* Stats cards skeleton */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatsCardSkeleton />
        <StatsCardSkeleton />
        <StatsCardSkeleton />
      </div>

      {/* Table skeleton */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 card p-0">
          <div className="p-4 border-b border-border-primary">
            <div className="skeleton h-6 w-32" />
          </div>
          <div className="p-4 space-y-4">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="flex gap-4">
                <div className="skeleton h-4 w-32" />
                <div className="skeleton h-4 w-12" />
                <div className="skeleton h-4 w-16" />
                <div className="skeleton h-4 w-24" />
                <div className="skeleton h-4 w-16" />
              </div>
            ))}
          </div>
        </div>
        <div className="card p-0">
          <div className="p-4 border-b border-border-primary">
            <div className="skeleton h-6 w-24" />
          </div>
          <div className="p-4 space-y-4">
            {[...Array(4)].map((_, i) => (
              <div key={i}>
                <div className="skeleton h-5 w-32" />
                <div className="skeleton h-3 w-24 mt-2" />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
