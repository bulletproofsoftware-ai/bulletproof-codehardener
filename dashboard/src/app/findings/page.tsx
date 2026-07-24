'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import {
  Search,
  Download,
  ChevronDown,
  Check,
  EyeOff,
  XCircle,
  MoreVertical,
  Shield,
  Filter,
  X,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { SeverityBadge } from '@/components/SeverityBadge';
import { StatusBadge } from '@/components/StatusBadge';
import { ExploitabilityBadge } from '@/components/ExploitabilityBadge';
import { EmptyState } from '@/components/EmptyState';
import { Pagination } from '@/components/Pagination';
import { useFindings, useProjects } from '@/hooks/useApi';
import { findingsApi } from '@/lib/api';
import type { Finding, FindingSeverity, FindingStatus, Exploitability } from '@/types';

interface FindingsFilters {
  severity: FindingSeverity[];
  projects: string[];
  scanners: string[];
  statuses: FindingStatus[];
  exploitability: Exploitability[];
  search: string;
}

interface FindingsSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

const severityOptions: { value: FindingSeverity; label: string }[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

const statusOptions: { value: FindingStatus; label: string }[] = [
  { value: 'open', label: 'Open' },
  { value: 'fixed', label: 'Fixed' },
  { value: 'ignored', label: 'Ignored' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'deferred', label: 'Deferred' },
];

const exploitabilityOptions: { value: Exploitability; label: string }[] = [
  { value: 'confirmed', label: 'Confirmed' },
  { value: 'likely', label: 'Likely' },
  { value: 'theoretical', label: 'Theoretical' },
  { value: 'unlikely', label: 'Unlikely' },
];

const scannerOptions = ['Opengrep', 'Gitleaks', 'Trivy', 'Bandit', 'ESLint', 'Gosec', 'Checkov', 'Nuclei'];

export default function FindingsPage() {
  const [filters, setFilters] = useState<FindingsFilters>({
    severity: [],
    projects: [],
    scanners: [],
    statuses: ['open'],
    exploitability: [],
    search: '',
  });
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [bulkMenuOpen, setBulkMenuOpen] = useState(false);
  const [openFilterDropdown, setOpenFilterDropdown] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const pageSize = 20;

  // Build query params from filters
  const queryParams = useMemo(() => {
    const params: Record<string, unknown> = { page, limit: pageSize };
    if (filters.severity.length > 0) params.severity = filters.severity;
    if (filters.projects.length > 0) params.projects = filters.projects;
    if (filters.scanners.length > 0) params.scanners = filters.scanners;
    if (filters.statuses.length > 0) params.statuses = filters.statuses;
    if (filters.exploitability.length > 0) params.exploitability = filters.exploitability;
    if (filters.search) params.search = filters.search;
    return params as Parameters<typeof findingsApi.list>[0];
  }, [page, filters]);

  // Fetch findings via React Query
  const { data: findingsResponse, isLoading, error: findingsError, refetch: refetchFindings } = useFindings(queryParams);

  const findings = findingsResponse?.data ?? [];
  const totalPages = findingsResponse?.pagination?.totalPages ?? 1;
  const summary: FindingsSummary = (findingsResponse as unknown as { summary?: FindingsSummary })?.summary ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const error = findingsError?.message ?? null;

  // Fetch projects for filter dropdown
  const { data: projectsResponse } = useProjects({ limit: 100 });
  const projects = projectsResponse?.data ?? [];

  // Project options for filter dropdown
  const projectOptions = useMemo(() => {
    return projects.map(p => ({ value: p.id, label: p.name }));
  }, [projects]);

  // Selection handlers
  const allSelected = findings.length > 0 && findings.every(f => selectedIds.includes(f.id));
  const someSelected = selectedIds.length > 0;

  const toggleAll = () => {
    if (allSelected) {
      setSelectedIds([]);
    } else {
      setSelectedIds(findings.map(f => f.id));
    }
  };

  const toggleOne = (id: string) => {
    if (selectedIds.includes(id)) {
      setSelectedIds(selectedIds.filter(i => i !== id));
    } else {
      setSelectedIds([...selectedIds, id]);
    }
  };

  // Update single finding status
  const handleUpdateStatus = async (id: string, status: FindingStatus) => {
    try {
      setActionLoading(id);
      await findingsApi.updateStatus(id, status);
      // Refresh findings list
      await refetchFindings();
    } catch (err) {
      console.error('Failed to update finding status:', err);
      alert(err instanceof Error ? err.message : 'Failed to update finding status');
    } finally {
      setActionLoading(null);
    }
  };

  // Bulk update status
  const handleBulkUpdateStatus = async (status: FindingStatus) => {
    try {
      setActionLoading('bulk');
      await findingsApi.bulkUpdateStatus(selectedIds, status);
      setSelectedIds([]);
      setBulkMenuOpen(false);
      // Refresh findings list
      await refetchFindings();
    } catch (err) {
      console.error('Failed to bulk update findings:', err);
      alert(err instanceof Error ? err.message : 'Failed to update findings');
    } finally {
      setActionLoading(null);
    }
  };

  // Export to CSV
  const exportToCSV = () => {
    const headers = ['ID', 'Severity', 'Title', 'Location', 'Scanner', 'Status', 'Project', 'CWE', 'CVE'];
    const rows = findings.map(f => [
      f.id,
      f.severity,
      f.title,
      `${f.filePath}:${f.lineNumber}`,
      f.scanner,
      f.status,
      f.projectName || '',
      f.cwe || '',
      f.cve || '',
    ]);

    const csv = [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `findings-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Check if any filters are active
  const hasActiveFilters =
    filters.severity.length > 0 ||
    filters.projects.length > 0 ||
    filters.scanners.length > 0 ||
    filters.statuses.length > 0 ||
    filters.exploitability.length > 0 ||
    filters.search !== '';

  const clearFilters = () => {
    setFilters({
      severity: [],
      projects: [],
      scanners: [],
      statuses: [],
      exploitability: [],
      search: '',
    });
    setPage(1);
  };

  if (isLoading && findings.length === 0) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    );
  }

  if (error && findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-error mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load findings</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={() => refetchFindings()}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Findings</h1>
        <p className="text-text-secondary mt-1">
          Security issues detected across all your projects
        </p>
      </div>

      {/* Summary Bar */}
      <FindingsSummaryBar summary={summary} />

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Severity Filter */}
        <FilterDropdown
          label="Severity"
          options={severityOptions}
          selected={filters.severity}
          onChange={(severity) => {
            setFilters({ ...filters, severity: severity as FindingSeverity[] });
            setPage(1);
          }}
          isOpen={openFilterDropdown === 'severity'}
          onToggle={() => setOpenFilterDropdown(openFilterDropdown === 'severity' ? null : 'severity')}
        />

        {/* Project Filter */}
        <FilterDropdown
          label="Project"
          options={projectOptions}
          selected={filters.projects}
          onChange={(projects) => {
            setFilters({ ...filters, projects });
            setPage(1);
          }}
          isOpen={openFilterDropdown === 'projects'}
          onToggle={() => setOpenFilterDropdown(openFilterDropdown === 'projects' ? null : 'projects')}
        />

        {/* Scanner Filter */}
        <FilterDropdown
          label="Scanner"
          options={scannerOptions.map(s => ({ value: s, label: s }))}
          selected={filters.scanners}
          onChange={(scanners) => {
            setFilters({ ...filters, scanners });
            setPage(1);
          }}
          isOpen={openFilterDropdown === 'scanners'}
          onToggle={() => setOpenFilterDropdown(openFilterDropdown === 'scanners' ? null : 'scanners')}
        />

        {/* Status Filter */}
        <FilterDropdown
          label="Status"
          options={statusOptions}
          selected={filters.statuses}
          onChange={(statuses) => {
            setFilters({ ...filters, statuses: statuses as FindingStatus[] });
            setPage(1);
          }}
          isOpen={openFilterDropdown === 'statuses'}
          onToggle={() => setOpenFilterDropdown(openFilterDropdown === 'statuses' ? null : 'statuses')}
        />

        {/* Exploitability Filter */}
        <FilterDropdown
          label="Exploitability"
          options={exploitabilityOptions}
          selected={filters.exploitability}
          onChange={(exploitability) => {
            setFilters({ ...filters, exploitability: exploitability as Exploitability[] });
            setPage(1);
          }}
          isOpen={openFilterDropdown === 'exploitability'}
          onToggle={() => setOpenFilterDropdown(openFilterDropdown === 'exploitability' ? null : 'exploitability')}
        />

        {/* Search */}
        <div className="flex-1 min-w-64">
          <div className="relative">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-tertiary" />
            <input
              type="text"
              value={filters.search}
              onChange={(e) => {
                setFilters({ ...filters, search: e.target.value });
                setPage(1);
              }}
              placeholder="Search findings..."
              className="w-full bg-bg-tertiary border border-border-primary rounded-lg pl-10 pr-4 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500"
            />
          </div>
        </div>

        {/* Clear Filters */}
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="text-sm text-text-secondary hover:text-text-primary flex items-center gap-1"
          >
            <X size={14} />
            Clear all
          </button>
        )}
      </div>

      {/* Table Card */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl overflow-hidden">
        {/* Actions Bar */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border-primary">
          <span className="text-sm text-text-secondary">
            {isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin inline mr-2" />
            ) : null}
            Showing {summary.total} findings
          </span>
          <div className="flex items-center gap-3">
            <button
              onClick={exportToCSV}
              className="flex items-center gap-2 px-3 py-1.5 text-sm text-text-secondary hover:text-text-primary hover:bg-bg-tertiary rounded-lg transition-colors"
            >
              <Download size={14} />
              Export CSV
            </button>
            {someSelected && (
              <div className="relative">
                <button
                  onClick={() => setBulkMenuOpen(!bulkMenuOpen)}
                  disabled={actionLoading === 'bulk'}
                  className="flex items-center gap-2 px-3 py-1.5 text-sm bg-bg-tertiary hover:bg-bg-hover text-text-primary rounded-lg transition-colors disabled:opacity-50"
                >
                  {actionLoading === 'bulk' ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : null}
                  Bulk Actions ({selectedIds.length})
                  <ChevronDown size={14} />
                </button>
                {bulkMenuOpen && (
                  <div className="absolute right-0 mt-2 w-48 bg-bg-secondary border border-border-primary rounded-lg shadow-xl z-20">
                    <button
                      onClick={() => handleBulkUpdateStatus('fixed')}
                      className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover flex items-center gap-2"
                    >
                      <Check size={14} className="text-success" />
                      Mark as Fixed
                    </button>
                    <button
                      onClick={() => handleBulkUpdateStatus('ignored')}
                      className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover flex items-center gap-2"
                    >
                      <EyeOff size={14} className="text-text-tertiary" />
                      Mark as Ignored
                    </button>
                    <button
                      onClick={() => handleBulkUpdateStatus('false_positive')}
                      className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover flex items-center gap-2"
                    >
                      <XCircle size={14} className="text-violet-400" />
                      Mark as False Positive
                    </button>
                    <button
                      onClick={() => handleBulkUpdateStatus('deferred')}
                      className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover flex items-center gap-2"
                    >
                      <Shield size={14} className="text-amber-400" />
                      Defer
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Table */}
        {findings.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-xs text-text-tertiary border-b border-border-primary uppercase tracking-wider">
                  <th className="px-4 py-3 w-10">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={toggleAll}
                      className="rounded border-border-primary bg-bg-tertiary text-primary-500 focus:ring-primary-500 focus:ring-offset-0"
                    />
                  </th>
                  <th className="px-4 py-3 w-28">Severity</th>
                  <th className="px-4 py-3">Finding</th>
                  <th className="px-4 py-3">Location</th>
                  <th className="px-4 py-3 w-24">Scanner</th>
                  <th className="px-4 py-3 w-28">Exploit</th>
                  <th className="px-4 py-3 w-28">Status</th>
                  <th className="px-4 py-3 w-10"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-primary">
                {findings.map(finding => (
                  <FindingRow
                    key={finding.id}
                    finding={finding}
                    isSelected={selectedIds.includes(finding.id)}
                    onToggle={() => toggleOne(finding.id)}
                    onUpdateStatus={handleUpdateStatus}
                    isLoading={actionLoading === finding.id}
                  />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={Shield}
            title={hasActiveFilters ? "No findings match your filters" : "No findings yet"}
            description={hasActiveFilters ? "Try adjusting your filters or search query" : "Run a security scan to detect vulnerabilities"}
            secondaryAction={hasActiveFilters ? { label: 'Clear filters', onClick: clearFilters } : undefined}
          />
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <Pagination
          currentPage={page}
          totalPages={totalPages}
          onPageChange={setPage}
        />
      )}
    </div>
  );
}

// Summary Bar Component
function FindingsSummaryBar({ summary }: { summary: FindingsSummary }) {
  const severities = [
    { key: 'critical', label: 'Critical', color: 'var(--color-error)', count: summary.critical },
    { key: 'high', label: 'High', color: '#f97316', count: summary.high },
    { key: 'medium', label: 'Medium', color: 'var(--color-warning)', count: summary.medium },
    { key: 'low', label: 'Low', color: 'var(--color-info)', count: summary.low },
    { key: 'info', label: 'Info', color: '#6b7280', count: summary.info },
  ];

  const maxCount = Math.max(...severities.map(s => s.count), 1);

  return (
    <div className="bg-bg-secondary border border-border-primary rounded-xl p-4">
      <div className="flex items-end gap-4">
        {severities.map(sev => (
          <div key={sev.key} className="flex-1">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-text-secondary">{sev.label}</span>
              <span className="font-semibold" style={{ color: sev.color }}>
                {sev.count}
              </span>
            </div>
            <div className="h-2 bg-bg-tertiary rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-300"
                style={{
                  width: `${(sev.count / maxCount) * 100}%`,
                  backgroundColor: sev.color,
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Filter Dropdown Component
function FilterDropdown({
  label,
  options,
  selected,
  onChange,
  isOpen,
  onToggle,
}: {
  label: string;
  options: { value: string; label: string }[];
  selected: string[];
  onChange: (values: string[]) => void;
  isOpen: boolean;
  onToggle: () => void;
}) {
  const toggleOption = (value: string) => {
    if (selected.includes(value)) {
      onChange(selected.filter(v => v !== value));
    } else {
      onChange([...selected, value]);
    }
  };

  return (
    <div className="relative">
      <button
        onClick={onToggle}
        className={cn(
          'flex items-center gap-2 px-3 py-2 text-sm rounded-lg border transition-colors',
          selected.length > 0
            ? 'bg-primary-500/10 border-primary-500/30 text-primary-400'
            : 'bg-bg-tertiary border-border-primary text-text-secondary hover:text-text-primary hover:border-border-secondary'
        )}
      >
        <Filter size={14} />
        {label}
        {selected.length > 0 && (
          <span className="bg-primary-500/20 px-1.5 py-0.5 rounded text-xs">
            {selected.length}
          </span>
        )}
        <ChevronDown size={14} />
      </button>

      {isOpen && (
        <div className="absolute left-0 mt-2 w-48 bg-bg-secondary border border-border-primary rounded-lg shadow-xl z-20">
          <div className="p-2 space-y-1">
            {options.map(option => (
              <label
                key={option.value}
                className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-bg-hover cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={selected.includes(option.value)}
                  onChange={() => toggleOption(option.value)}
                  className="rounded border-border-primary bg-bg-tertiary text-primary-500 focus:ring-primary-500 focus:ring-offset-0"
                />
                <span className="text-sm text-text-primary">{option.label}</span>
              </label>
            ))}
          </div>
          {selected.length > 0 && (
            <div className="border-t border-border-primary p-2">
              <button
                onClick={() => onChange([])}
                className="w-full px-2 py-1.5 text-sm text-text-secondary hover:text-text-primary text-left"
              >
                Clear selection
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Finding Row Component
function FindingRow({
  finding,
  isSelected,
  onToggle,
  onUpdateStatus,
  isLoading,
}: {
  finding: Finding;
  isSelected: boolean;
  onToggle: () => void;
  onUpdateStatus: (id: string, status: FindingStatus) => void;
  isLoading: boolean;
}) {
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <tr className={cn('hover:bg-bg-hover/50 transition-colors', isSelected && 'bg-primary-500/5')}>
      <td className="px-4 py-3">
        <input
          type="checkbox"
          checked={isSelected}
          onChange={onToggle}
          className="rounded border-border-primary bg-bg-tertiary text-primary-500 focus:ring-primary-500 focus:ring-offset-0"
        />
      </td>
      <td className="px-4 py-3">
        <SeverityBadge severity={finding.severity} />
      </td>
      <td className="px-4 py-3">
        <Link
          href={`/findings/${finding.id}`}
          className="font-medium text-text-primary hover:text-primary-400 transition-colors"
        >
          {finding.title}
        </Link>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-sm text-text-tertiary">{finding.projectName || 'Project'}</span>
          {finding.cwe && (
            <span className="text-xs text-text-tertiary bg-bg-tertiary px-1.5 py-0.5 rounded">
              {finding.cwe}
            </span>
          )}
          {finding.cve && (
            <span className="text-xs text-error/80 bg-error/10 px-1.5 py-0.5 rounded">
              {finding.cve}
            </span>
          )}
        </div>
      </td>
      <td className="px-4 py-3">
        <span className="font-mono text-sm text-text-secondary">
          {finding.filePath}:{finding.lineNumber}
        </span>
      </td>
      <td className="px-4 py-3 text-sm text-text-secondary">{finding.scanner}</td>
      <td className="px-4 py-3">
        {finding.exploitability ? (
          <ExploitabilityBadge exploitability={finding.exploitability} />
        ) : (
          <span className="text-xs text-text-tertiary">-</span>
        )}
      </td>
      <td className="px-4 py-3">
        <StatusBadge status={finding.status} />
      </td>
      <td className="px-4 py-3">
        <div className="relative">
          <button
            onClick={() => setMenuOpen(!menuOpen)}
            disabled={isLoading}
            className="p-1 rounded hover:bg-bg-tertiary transition-colors disabled:opacity-50"
          >
            {isLoading ? (
              <Loader2 size={16} className="animate-spin text-text-tertiary" />
            ) : (
              <MoreVertical size={16} className="text-text-tertiary" />
            )}
          </button>
          {menuOpen && !isLoading && (
            <div className="absolute right-0 mt-1 w-40 bg-bg-secondary border border-border-primary rounded-lg shadow-xl z-10">
              <Link
                href={`/findings/${finding.id}`}
                className="block px-4 py-2 text-sm hover:bg-bg-hover"
              >
                View details
              </Link>
              {finding.status !== 'fixed' && (
                <button
                  onClick={() => {
                    onUpdateStatus(finding.id, 'fixed');
                    setMenuOpen(false);
                  }}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover"
                >
                  Mark as fixed
                </button>
              )}
              {finding.status !== 'ignored' && (
                <button
                  onClick={() => {
                    onUpdateStatus(finding.id, 'ignored');
                    setMenuOpen(false);
                  }}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover"
                >
                  Mark as ignored
                </button>
              )}
              {finding.status !== 'false_positive' && (
                <button
                  onClick={() => {
                    onUpdateStatus(finding.id, 'false_positive');
                    setMenuOpen(false);
                  }}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover"
                >
                  Mark as false positive
                </button>
              )}
              {finding.status !== 'deferred' && (
                <button
                  onClick={() => {
                    onUpdateStatus(finding.id, 'deferred');
                    setMenuOpen(false);
                  }}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover"
                >
                  Defer
                </button>
              )}
              {finding.status !== 'open' && (
                <button
                  onClick={() => {
                    onUpdateStatus(finding.id, 'open');
                    setMenuOpen(false);
                  }}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover"
                >
                  Reopen
                </button>
              )}
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}
