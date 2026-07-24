'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Shield,
  Download,
  ExternalLink,
  CheckCircle,
  Clock,
  ChevronDown,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { cn, formatRelativeTime } from '@/lib/utils';
import { Pagination } from '@/components/Pagination';
import { EmptyState } from '@/components/EmptyState';
import { attestationsApi, projectsApi } from '@/lib/api';
import type { Attestation, Project } from '@/types';

export default function AttestationsPage() {
  const [attestations, setAttestations] = useState<Attestation[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [projectFilter, setProjectFilter] = useState('all');
  const [dateFilter, setDateFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const itemsPerPage = 10;

  useEffect(() => {
    fetchProjects();
  }, []);

  useEffect(() => {
    fetchAttestations();
  }, [projectFilter, dateFilter, currentPage]);

  async function fetchProjects() {
    try {
      const response = await projectsApi.list({ limit: 100 });
      setProjects(response.data);
    } catch (err) {
      console.error('Failed to fetch projects:', err);
    }
  }

  async function fetchAttestations() {
    try {
      setIsLoading(true);
      setError(null);

      const params: Record<string, unknown> = {
        page: currentPage,
        limit: itemsPerPage,
      };

      if (projectFilter !== 'all') {
        params.projectId = projectFilter;
      }

      // Note: dateFilter would need backend support for date range filtering
      // For now, we'll fetch all and could add this as a backend feature later

      const response = await attestationsApi.list(params);
      setAttestations(response.data);
      setTotalPages(response.pagination.totalPages);
    } catch (err) {
      console.error('Failed to fetch attestations:', err);
      setError(err instanceof Error ? err.message : 'Failed to load attestations');
    } finally {
      setIsLoading(false);
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 700) return 'text-success';
    if (score >= 500) return 'text-warning';
    return 'text-error';
  };

  const handleDownload = async (id: string) => {
    try {
      const attestation = await attestationsApi.get(id);
      const blob = new Blob([JSON.stringify(attestation, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `attestation-${id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to download attestation:', err);
      alert('Failed to download attestation');
    }
  };

  const handleVerify = (rekorLogId: string) => {
    window.open(`https://search.sigstore.dev/?logIndex=${rekorLogId}`, '_blank');
  };

  if (isLoading && attestations.length === 0) {
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
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load attestations</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={fetchAttestations}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  if (attestations.length === 0 && !isLoading) {
    return (
      <div className="card">
        <EmptyState
          icon={Shield}
          title="No Attestations Yet"
          description="Run a scan and generate an attestation to prove your security posture."
          action={{ label: 'Run Your First Scan', href: '/scans/new' }}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Attestations</h1>
        <p className="text-text-secondary mt-1">
          Cryptographically signed proof of your security scans.
        </p>
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
            value={dateFilter}
            onChange={e => {
              setDateFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="input pr-10 appearance-none"
          >
            <option value="all">All Time</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
          </select>
          <ChevronDown size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary pointer-events-none" />
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        {isLoading && (
          <div className="absolute inset-0 bg-bg-primary/50 flex items-center justify-center z-10">
            <Loader2 className="h-6 w-6 animate-spin text-primary-500" />
          </div>
        )}
        <table className="w-full">
          <thead>
            <tr className="text-left text-xs text-text-tertiary border-b border-border-primary uppercase tracking-wider">
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Project</th>
              <th className="px-4 py-3">Score</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Created</th>
              <th className="px-4 py-3 w-32">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-primary">
            {attestations.map(attestation => (
              <tr key={attestation.id} className="hover:bg-bg-hover/50 transition-colors">
                <td className="px-4 py-3">
                  <Link
                    href={`/attestations/${attestation.id}`}
                    className="font-mono text-sm text-primary-400 hover:text-primary-300"
                  >
                    {attestation.id}
                  </Link>
                </td>
                <td className="px-4 py-3">
                  <Link
                    href={`/projects/${attestation.projectId}`}
                    className="text-sm text-text-primary hover:text-primary-400"
                  >
                    {attestation.projectName}
                  </Link>
                </td>
                <td className="px-4 py-3">
                  <span className={cn('font-semibold', getScoreColor(attestation.score))}>
                    {attestation.score}
                  </span>
                  <span className="text-text-tertiary">/1000</span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    {attestation.rekorLogId ? (
                      <>
                        <CheckCircle size={14} className="text-success" />
                        <span className="text-sm text-success">Verified</span>
                      </>
                    ) : (
                      <>
                        <Clock size={14} className="text-warning" />
                        <span className="text-sm text-warning">Pending</span>
                      </>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">
                  {formatRelativeTime(attestation.createdAt)}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1">
                    <Link
                      href={`/attestations/${attestation.id}`}
                      className="p-1.5 rounded hover:bg-bg-tertiary transition-colors"
                      title="View attestation"
                    >
                      <Shield size={14} className="text-text-tertiary" />
                    </Link>
                    <button
                      onClick={() => handleDownload(attestation.id)}
                      className="p-1.5 rounded hover:bg-bg-tertiary transition-colors"
                      title="Download JSON"
                    >
                      <Download size={14} className="text-text-tertiary" />
                    </button>
                    {attestation.rekorLogId && (
                      <button
                        onClick={() => handleVerify(attestation.rekorLogId!)}
                        className="p-1.5 rounded hover:bg-bg-tertiary transition-colors"
                        title="Verify on Rekor"
                      >
                        <ExternalLink size={14} className="text-text-tertiary" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {attestations.length === 0 && !isLoading && (
          <div className="py-12 text-center text-text-tertiary">
            No attestations found matching the selected filters.
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
    </div>
  );
}
