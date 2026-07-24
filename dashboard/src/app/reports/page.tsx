'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  FileText,
  Download,
  Eye,
  Plus,
  X,
  ChevronDown,
  CheckCircle,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { cn, formatRelativeTime } from '@/lib/utils';
import { Pagination } from '@/components/Pagination';
import { EmptyState } from '@/components/EmptyState';
import { reportsApi, projectsApi } from '@/lib/api';
import type { Report, Project } from '@/types';

type ReportType = 'summary' | 'detailed' | 'compliance' | 'executive';

// Maps for frontend display labels
const reportTypeLabels: Record<string, string> = {
  summary: 'Summary',
  detailed: 'Detailed',
  compliance: 'Compliance',
  executive: 'Executive',
  security_summary: 'Summary',
  scan_detail: 'Detailed',
  vulnerability: 'Vulnerability',
};

const reportTypeColors: Record<string, string> = {
  summary: 'bg-violet-500/10 text-violet-400',
  detailed: 'bg-primary-500/10 text-primary-400',
  compliance: 'bg-success/10 text-success',
  executive: 'bg-warning/10 text-warning',
  security_summary: 'bg-violet-500/10 text-violet-400',
  scan_detail: 'bg-primary-500/10 text-primary-400',
  vulnerability: 'bg-error/10 text-error',
};

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [projectFilter, setProjectFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState<ReportType | 'all'>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const itemsPerPage = 10;

  useEffect(() => {
    fetchProjects();
  }, []);

  useEffect(() => {
    fetchReports();
  }, [currentPage]);

  async function fetchProjects() {
    try {
      const response = await projectsApi.list({ limit: 100 });
      setProjects(response.data);
    } catch (err) {
      console.error('Failed to fetch projects:', err);
    }
  }

  async function fetchReports() {
    try {
      setIsLoading(true);
      setError(null);

      const params: Record<string, unknown> = {
        page: currentPage,
        limit: itemsPerPage,
      };

      const response = await reportsApi.list(params);
      setReports(response.data);
      setTotalPages(response.pagination.totalPages);
    } catch (err) {
      console.error('Failed to fetch reports:', err);
      setError(err instanceof Error ? err.message : 'Failed to load reports');
    } finally {
      setIsLoading(false);
    }
  }

  // Map frontend filter type to backend reportType values
  const typeFilterMap: Record<string, string[]> = {
    summary: ['security_summary', 'summary'],
    detailed: ['scan_detail', 'detailed'],
    compliance: ['compliance'],
    executive: ['executive'],
  };

  // Filter reports client-side (could be moved to backend)
  const filteredReports = reports.filter(report => {
    if (projectFilter !== 'all') {
      if (report.projectId !== projectFilter) return false;
    }
    if (typeFilter !== 'all') {
      const validTypes = typeFilterMap[typeFilter] || [typeFilter];
      if (!validTypes.includes(report.reportType)) return false;
    }
    return true;
  });

  const getStatusIcon = (status: Report['status']) => {
    switch (status) {
      case 'completed':
        return <CheckCircle size={14} className="text-success" />;
      case 'pending':
        return <Loader2 size={14} className="text-primary-400 animate-spin" />;
      case 'failed':
        return <AlertCircle size={14} className="text-error" />;
    }
  };

  const getStatusLabel = (status: Report['status']) => {
    switch (status) {
      case 'completed':
        return <span className="text-success">Ready</span>;
      case 'pending':
        return <span className="text-primary-400">Generating...</span>;
      case 'failed':
        return <span className="text-error">Failed</span>;
    }
  };

  const handleDownload = (report: Report) => {
    if (report.fileUrl) {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000/api/v1';
      window.open(`${apiBase}/reports/${report.id}/download`, '_blank');
    }
  };

  const handleGenerateReport = async (data: {
    name: string;
    type: ReportType;
    projectIds: string[];
    dateRange: { start: string; end: string };
  }) => {
    try {
      // Map frontend report types to backend reportType enum
      const typeMap: Record<ReportType, string> = {
        summary: 'security_summary',
        detailed: 'scan_detail',
        compliance: 'compliance',
        executive: 'executive',
      };

      await reportsApi.generate({
        name: data.name,
        type: typeMap[data.type],
        projectIds: data.projectIds,
        dateRange: data.dateRange,
      });
      setShowGenerateModal(false);
      fetchReports();
    } catch (err) {
      console.error('Failed to generate report:', err);
      throw err;
    }
  };

  if (isLoading && reports.length === 0) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-error mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load reports</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={fetchReports}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  if (reports.length === 0 && !isLoading) {
    return (
      <div className="card">
        <EmptyState
          icon={FileText}
          title="No Reports Yet"
          description="Generate your first security or compliance report."
          action={{ label: 'Generate Report', onClick: () => setShowGenerateModal(true) }}
        />
        {showGenerateModal && (
          <GenerateReportModal
            projects={projects}
            onClose={() => setShowGenerateModal(false)}
            onGenerate={handleGenerateReport}
          />
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Reports</h1>
          <p className="text-text-secondary mt-1">
            Generate compliance and security reports for your projects.
          </p>
        </div>
        <button
          onClick={() => setShowGenerateModal(true)}
          className="btn-primary flex items-center gap-2"
        >
          <Plus size={16} />
          Generate Report
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="relative">
          <select
            value={projectFilter}
            onChange={e => {
              setProjectFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="input pr-10 appearance-none"
          >
            <option value="all">All Projects</option>
            {projects.map(project => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>
          <ChevronDown size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary pointer-events-none" />
        </div>

        <div className="relative">
          <select
            value={typeFilter}
            onChange={e => {
              setTypeFilter(e.target.value as ReportType | 'all');
              setCurrentPage(1);
            }}
            className="input pr-10 appearance-none"
          >
            <option value="all">All Types</option>
            <option value="summary">Summary</option>
            <option value="detailed">Detailed</option>
            <option value="compliance">Compliance</option>
            <option value="executive">Executive</option>
          </select>
          <ChevronDown size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary pointer-events-none" />
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-hidden relative">
        {isLoading && (
          <div className="absolute inset-0 bg-bg-primary/50 flex items-center justify-center z-10">
            <Loader2 className="h-6 w-6 animate-spin text-primary-500" />
          </div>
        )}
        <table className="w-full">
          <thead>
            <tr className="text-left text-xs text-text-tertiary border-b border-border-primary uppercase tracking-wider">
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Date Range</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Created</th>
              <th className="px-4 py-3 w-24">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-primary">
            {filteredReports.map(report => (
              <tr key={report.id} className="hover:bg-bg-hover/50 transition-colors">
                <td className="px-4 py-3">
                  <Link
                    href={`/reports/${report.id}`}
                    className="text-sm text-text-primary hover:text-primary-400 font-medium"
                  >
                    {report.title}
                  </Link>
                </td>
                <td className="px-4 py-3">
                  <span className={cn(
                    'text-xs px-2 py-1 rounded-full font-medium',
                    reportTypeColors[report.reportType] || 'bg-bg-tertiary text-text-secondary'
                  )}>
                    {reportTypeLabels[report.reportType] || report.reportType}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">
                  {report.generatedAt ? new Date(report.generatedAt).toLocaleDateString() : 'N/A'}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    {getStatusIcon(report.status)}
                    <span className="text-sm">{getStatusLabel(report.status)}</span>
                  </div>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">
                  {formatRelativeTime(report.createdAt)}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1">
                    <Link
                      href={`/reports/${report.id}`}
                      className="p-1.5 rounded hover:bg-bg-tertiary transition-colors"
                      title="View report"
                    >
                      <Eye size={14} className="text-text-tertiary" />
                    </Link>
                    {report.status === 'completed' && report.fileUrl && (
                      <button
                        onClick={() => handleDownload(report)}
                        className="p-1.5 rounded hover:bg-bg-tertiary transition-colors"
                        title="Download PDF"
                      >
                        <Download size={14} className="text-text-tertiary" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredReports.length === 0 && !isLoading && (
          <div className="py-12 text-center text-text-tertiary">
            No reports found matching the selected filters.
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <Pagination
          currentPage={currentPage}
          totalPages={totalPages}
          onPageChange={setCurrentPage}
        />
      )}

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <GenerateReportModal
          projects={projects}
          onClose={() => setShowGenerateModal(false)}
          onGenerate={handleGenerateReport}
        />
      )}
    </div>
  );
}

interface GenerateReportModalProps {
  projects: Project[];
  onClose: () => void;
  onGenerate: (data: {
    name: string;
    type: ReportType;
    projectIds: string[];
    dateRange: { start: string; end: string };
  }) => Promise<void>;
}

function GenerateReportModal({ projects, onClose, onGenerate }: GenerateReportModalProps) {
  const [reportType, setReportType] = useState<ReportType>('summary');
  const [reportName, setReportName] = useState('');
  const [projectScope, setProjectScope] = useState<'all' | 'specific'>('all');
  const [selectedProject, setSelectedProject] = useState('');
  const [dateRange, setDateRange] = useState('30d');
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const getDateRange = () => {
    const end = new Date();
    const start = new Date();

    switch (dateRange) {
      case '7d':
        start.setDate(start.getDate() - 7);
        break;
      case '30d':
        start.setDate(start.getDate() - 30);
        break;
      case '90d':
        start.setDate(start.getDate() - 90);
        break;
      case '365d':
        start.setDate(start.getDate() - 365);
        break;
      case 'all':
        start.setFullYear(start.getFullYear() - 10);
        break;
    }

    return {
      start: start.toISOString(),
      end: end.toISOString(),
    };
  };

  const handleGenerate = async () => {
    if (!reportName.trim()) return;
    if (projectScope === 'specific' && !selectedProject) return;

    setIsGenerating(true);
    setError(null);

    try {
      await onGenerate({
        name: reportName,
        type: reportType,
        projectIds: projectScope === 'all' ? projects.map(p => p.id) : [selectedProject],
        dateRange: getDateRange(),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report');
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary rounded-lg border border-border-primary w-full max-w-lg max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-border-primary">
          <h2 className="text-lg font-semibold text-text-primary">Generate Report</h2>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-bg-tertiary transition-colors"
          >
            <X size={20} className="text-text-tertiary" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4">
          {error && (
            <div className="p-3 bg-error/10 border border-error/20 rounded-lg text-sm text-error">
              {error}
            </div>
          )}

          {/* Report Type */}
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-1.5">
              Report Type <span className="text-error">*</span>
            </label>
            <div className="relative">
              <select
                value={reportType}
                onChange={e => setReportType(e.target.value as ReportType)}
                className="input w-full pr-10 appearance-none"
                disabled={isGenerating}
              >
                <option value="summary">Summary - High-level stats, key findings</option>
                <option value="detailed">Detailed - All findings, scores, trends</option>
                <option value="compliance">Compliance - Control mappings, evidence</option>
                <option value="executive">Executive - Business-focused overview</option>
              </select>
              <ChevronDown size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary pointer-events-none" />
            </div>
          </div>

          {/* Report Name */}
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-1.5">
              Report Name <span className="text-error">*</span>
            </label>
            <input
              type="text"
              value={reportName}
              onChange={e => setReportName(e.target.value)}
              placeholder="Q4 2025 Security Report"
              className="input w-full"
              disabled={isGenerating}
            />
          </div>

          {/* Project Scope */}
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-1.5">
              Project Scope
            </label>
            <div className="space-y-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="projectScope"
                  checked={projectScope === 'all'}
                  onChange={() => setProjectScope('all')}
                  className="text-primary-500"
                  disabled={isGenerating}
                />
                <span className="text-sm text-text-primary">All Projects</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="projectScope"
                  checked={projectScope === 'specific'}
                  onChange={() => setProjectScope('specific')}
                  className="text-primary-500"
                  disabled={isGenerating}
                />
                <span className="text-sm text-text-primary">Specific Project</span>
              </label>
              {projectScope === 'specific' && (
                <div className="relative ml-6">
                  <select
                    value={selectedProject}
                    onChange={e => setSelectedProject(e.target.value)}
                    className="input w-full pr-10 appearance-none"
                    disabled={isGenerating}
                  >
                    <option value="">Select a project...</option>
                    {projects.map(project => (
                      <option key={project.id} value={project.id}>
                        {project.name}
                      </option>
                    ))}
                  </select>
                  <ChevronDown size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary pointer-events-none" />
                </div>
              )}
            </div>
          </div>

          {/* Date Range */}
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-1.5">
              Date Range
            </label>
            <div className="relative">
              <select
                value={dateRange}
                onChange={e => setDateRange(e.target.value)}
                className="input w-full pr-10 appearance-none"
                disabled={isGenerating}
              >
                <option value="7d">Last 7 days</option>
                <option value="30d">Last 30 days</option>
                <option value="90d">Last 90 days</option>
                <option value="365d">Last year</option>
                <option value="all">All time</option>
              </select>
              <ChevronDown size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary pointer-events-none" />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 p-4 border-t border-border-primary">
          <button
            onClick={onClose}
            className="btn-secondary"
            disabled={isGenerating}
          >
            Cancel
          </button>
          <button
            onClick={handleGenerate}
            disabled={!reportName.trim() || (projectScope === 'specific' && !selectedProject) || isGenerating}
            className="btn-primary flex items-center gap-2"
          >
            {isGenerating ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <FileText size={16} />
                Generate
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
