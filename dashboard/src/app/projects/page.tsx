'use client';

import { useState } from 'react';
import Link from 'next/link';
import {
  Plus,
  Search,
  Filter,
  ArrowUpDown,
  FolderKanban,
  MoreHorizontal,
  Play,
  Settings,
  Trash2,
  ExternalLink,
  LayoutGrid,
  List,
  Github,
  GitlabIcon,
  Clock,
  AlertCircle,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatRelativeTime, getScoreLevel } from '@/lib/utils';
import { ScoreGauge } from '@/components/ScoreGauge';
import { EmptyState } from '@/components/EmptyState';
import { useProjects } from '@/hooks/useApi';
import { projectsApi } from '@/lib/api';
import type { Project } from '@/types';

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

function RepositoryIcon({ provider }: { provider?: string }) {
  if (provider === 'github') {
    return <Github className="h-4 w-4" />;
  }
  if (provider === 'gitlab') {
    return <GitlabIcon className="h-4 w-4" />;
  }
  return <FolderKanban className="h-4 w-4" />;
}

export default function ProjectsPage() {
  const { data: projectsResponse, isLoading, error: projectsError, refetch: refetchProjects } = useProjects();
  const projects = projectsResponse?.data ?? [];
  const error = projectsError?.message ?? null;
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [activeMenu, setActiveMenu] = useState<string | null>(null);

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
      return;
    }
    try {
      await projectsApi.delete(id);
      refetchProjects();
      setActiveMenu(null);
    } catch (err) {
      console.error('Failed to delete project:', err);
      alert(err instanceof Error ? err.message : 'Failed to delete project');
    }
  };

  const filteredProjects = projects.filter((project) =>
    project.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (isLoading) {
    return <ProjectsPageSkeleton />;
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-error mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load projects</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={() => refetchProjects()}
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
          <h1 className="text-2xl font-bold text-text-primary">Projects</h1>
          <p className="text-text-secondary mt-1">
            Manage your security scanning projects
          </p>
        </div>
        <Link href="/projects/new" className="btn-primary">
          <Plus className="h-4 w-4" />
          New Project
        </Link>
      </div>

      {/* Filters and Search */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-tertiary" />
          <input
            type="search"
            placeholder="Search projects..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input pl-10 w-full"
          />
        </div>
        <div className="flex gap-2">
          <button className="btn-secondary">
            <Filter className="h-4 w-4" />
            Filter
          </button>
          <button className="btn-secondary">
            <ArrowUpDown className="h-4 w-4" />
            Sort
          </button>
          <div className="flex border border-border-primary rounded-md overflow-hidden">
            <button
              onClick={() => setViewMode('grid')}
              className={cn(
                'p-2 transition-colors',
                viewMode === 'grid'
                  ? 'bg-bg-tertiary text-text-primary'
                  : 'text-text-tertiary hover:text-text-secondary hover:bg-bg-hover'
              )}
              aria-label="Grid view"
            >
              <LayoutGrid className="h-4 w-4" />
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={cn(
                'p-2 transition-colors',
                viewMode === 'list'
                  ? 'bg-bg-tertiary text-text-primary'
                  : 'text-text-tertiary hover:text-text-secondary hover:bg-bg-hover'
              )}
              aria-label="List view"
            >
              <List className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Projects Grid/List */}
      {filteredProjects.length === 0 ? (
        searchQuery ? (
          <EmptyState
            icon={Search}
            title="No projects found"
            description={`No projects match "${searchQuery}"`}
            secondaryAction={{
              label: 'Clear search',
              onClick: () => setSearchQuery(''),
            }}
          />
        ) : (
          <EmptyState
            icon={FolderKanban}
            title="No projects yet"
            description="Create your first project to start scanning for vulnerabilities"
            action={{ label: 'Create Project', href: '/projects/new' }}
          />
        )
      ) : viewMode === 'grid' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filteredProjects.map((project) => (
            <ProjectCard
              key={project.id}
              project={project}
              isMenuOpen={activeMenu === project.id}
              onMenuToggle={() =>
                setActiveMenu(activeMenu === project.id ? null : project.id)
              }
              onMenuClose={() => setActiveMenu(null)}
              onDelete={() => handleDelete(project.id)}
            />
          ))}
        </div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="text-left text-xs font-medium text-text-tertiary uppercase tracking-wide border-b border-border-primary">
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Repository</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Last Scan</th>
                <th className="px-4 py-3 w-24">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-primary">
              {filteredProjects.map((project) => (
                <ProjectRow
                  key={project.id}
                  project={project}
                  isMenuOpen={activeMenu === project.id}
                  onMenuToggle={() =>
                    setActiveMenu(activeMenu === project.id ? null : project.id)
                  }
                  onMenuClose={() => setActiveMenu(null)}
                  onDelete={() => handleDelete(project.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Results count */}
      {filteredProjects.length > 0 && (
        <p className="text-sm text-text-tertiary">
          Showing {filteredProjects.length} of {projects.length} projects
        </p>
      )}
    </div>
  );
}

function ProjectCard({
  project,
  isMenuOpen,
  onMenuToggle,
  onMenuClose,
  onDelete,
}: {
  project: Project;
  isMenuOpen: boolean;
  onMenuToggle: () => void;
  onMenuClose: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="card hover:border-border-secondary transition-colors">
      {/* Header */}
      <div className="flex items-start justify-between">
        <Link
          href={`/projects/${project.id}`}
          className="flex items-center gap-2 hover:text-primary-500"
        >
          <div className="w-8 h-8 rounded bg-bg-tertiary flex items-center justify-center text-text-secondary">
            <RepositoryIcon provider={project.repositoryProvider ?? undefined} />
          </div>
          <div>
            <h3 className="font-medium text-text-primary">{project.name}</h3>
            {project.repositoryUrl && (
              <p className="text-xs text-text-tertiary">
                Connected to{' '}
                {project.repositoryProvider === 'github'
                  ? 'GitHub'
                  : project.repositoryProvider === 'gitlab'
                  ? 'GitLab'
                  : 'Repository'}
              </p>
            )}
          </div>
        </Link>
        <ProjectMenu
          project={project}
          isOpen={isMenuOpen}
          onToggle={onMenuToggle}
          onClose={onMenuClose}
          onDelete={onDelete}
        />
      </div>

      {/* Score and Last Scan */}
      <div className="mt-4 grid grid-cols-2 gap-4">
        <div>
          <span className="text-xs text-text-tertiary block mb-1">Score</span>
          {project.lastScore !== undefined ? (
            <div className="flex items-center gap-2">
              <ScoreGauge score={project.lastScore} size="sm" showLabel={false} />
              <span
                className="font-semibold"
                style={{
                  color: getScoreColor(getScoreLevel(project.lastScore)),
                }}
              >
                {project.lastScore}
              </span>
            </div>
          ) : (
            <span className="text-sm text-text-tertiary">-</span>
          )}
        </div>
        <div>
          <span className="text-xs text-text-tertiary block mb-1">Last Scan</span>
          <span className="text-sm text-text-secondary">
            {project.lastScanAt ? formatRelativeTime(project.lastScanAt) : 'Never'}
          </span>
        </div>
      </div>

      {/* Actions */}
      <div className="mt-4 pt-4 border-t border-border-primary flex gap-2">
        <Link
          href={`/scans/new?project=${project.id}`}
          className="btn-primary btn-sm flex-1"
        >
          <Play className="h-3 w-3" />
          Run Scan
        </Link>
        <Link
          href={`/projects/${project.id}`}
          className="btn-secondary btn-sm flex-1"
        >
          View
        </Link>
      </div>
    </div>
  );
}

function ProjectRow({
  project,
  isMenuOpen,
  onMenuToggle,
  onMenuClose,
  onDelete,
}: {
  project: Project;
  isMenuOpen: boolean;
  onMenuToggle: () => void;
  onMenuClose: () => void;
  onDelete: () => void;
}) {
  return (
    <tr className="hover:bg-bg-hover">
      <td className="px-4 py-3">
        <Link
          href={`/projects/${project.id}`}
          className="font-medium text-text-primary hover:text-primary-500"
        >
          {project.name}
        </Link>
        {project.description && (
          <p className="text-xs text-text-tertiary mt-0.5 truncate max-w-xs">
            {project.description}
          </p>
        )}
      </td>
      <td className="px-4 py-3">
        {project.repositoryUrl ? (
          <a
            href={project.repositoryUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-sm text-text-secondary hover:text-primary-500"
          >
            <RepositoryIcon provider={project.repositoryProvider ?? undefined} />
            <span className="truncate max-w-[200px]">
              {project.repositoryUrl.replace(/^https?:\/\//, '')}
            </span>
            <ExternalLink className="h-3 w-3 flex-shrink-0" />
          </a>
        ) : (
          <span className="text-sm text-text-tertiary">No repository</span>
        )}
      </td>
      <td className="px-4 py-3">
        {project.lastScore !== undefined ? (
          <span
            className="font-semibold"
            style={{ color: getScoreColor(getScoreLevel(project.lastScore)) }}
          >
            {project.lastScore}
          </span>
        ) : (
          <span className="text-text-tertiary">-</span>
        )}
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-text-secondary flex items-center gap-1">
          <Clock className="h-3 w-3" />
          {project.lastScanAt ? formatRelativeTime(project.lastScanAt) : 'Never'}
        </span>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-1">
          <Link
            href={`/scans/new?project=${project.id}`}
            className="btn-icon text-text-tertiary hover:text-primary-500"
            title="Run Scan"
          >
            <Play className="h-4 w-4" />
          </Link>
          <ProjectMenu
            project={project}
            isOpen={isMenuOpen}
            onToggle={onMenuToggle}
            onClose={onMenuClose}
            onDelete={onDelete}
          />
        </div>
      </td>
    </tr>
  );
}

function ProjectMenu({
  project,
  isOpen,
  onToggle,
  onClose,
  onDelete,
}: {
  project: Project;
  isOpen: boolean;
  onToggle: () => void;
  onClose: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="relative">
      <button
        onClick={onToggle}
        className="btn-icon text-text-tertiary hover:text-text-secondary"
        aria-label="More actions"
      >
        <MoreHorizontal className="h-4 w-4" />
      </button>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-10" onClick={onClose} />
          <div className="absolute right-0 mt-1 w-48 dropdown-menu z-20">
            <Link
              href={`/projects/${project.id}#settings`}
              className="dropdown-item"
              onClick={onClose}
            >
              <Settings className="h-4 w-4" />
              Settings
            </Link>
            <Link
              href={`/scans?project=${project.id}`}
              className="dropdown-item"
              onClick={onClose}
            >
              <FolderKanban className="h-4 w-4" />
              View Scans
            </Link>
            <div className="border-t border-border-primary my-1" />
            <button
              className="dropdown-item-danger w-full text-left"
              onClick={() => {
                onClose();
                onDelete();
              }}
            >
              <Trash2 className="h-4 w-4" />
              Delete
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function ProjectsPageSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="skeleton h-8 w-32" />
          <div className="skeleton h-4 w-48 mt-2" />
        </div>
        <div className="skeleton h-10 w-32" />
      </div>

      <div className="flex gap-3">
        <div className="skeleton h-10 flex-1" />
        <div className="skeleton h-10 w-24" />
        <div className="skeleton h-10 w-24" />
        <div className="skeleton h-10 w-20" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="card">
            <div className="flex items-center gap-2">
              <div className="skeleton h-8 w-8 rounded" />
              <div>
                <div className="skeleton h-5 w-32" />
                <div className="skeleton h-3 w-24 mt-1" />
              </div>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-4">
              <div>
                <div className="skeleton h-3 w-12 mb-1" />
                <div className="skeleton h-8 w-16" />
              </div>
              <div>
                <div className="skeleton h-3 w-16 mb-1" />
                <div className="skeleton h-4 w-20" />
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-border-primary flex gap-2">
              <div className="skeleton h-8 flex-1" />
              <div className="skeleton h-8 flex-1" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
