'use client';

import { useState, useMemo, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowLeft,
  Play,
  Trash2,
  ExternalLink,
  CheckCircle,
  AlertTriangle,
  TrendingUp,
  ChevronRight,
  Loader2,
  AlertCircle,
  FolderOpen,
  Download,
  Globe,
  Container,
  FileCode,
  Lock,
  KeyRound,
  Save,
  Eye,
  EyeOff,
} from 'lucide-react';
import { cn, formatDateTime, formatRelativeTime } from '@/lib/utils';
import { ScoreGauge } from '@/components/ScoreGauge';
import { SeverityBadge } from '@/components/SeverityBadge';
import { Pagination } from '@/components/Pagination';
import { api, projectsApi, scansApi, findingsApi } from '@/lib/api';
import { generateComprehensivePDF } from '@/lib/generate-scan-pdf';
import type { Project, Scan, Finding } from '@/types';
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

interface ExtendedProject extends Project {
  scans: Scan[];
  findings: Finding[];
}

type TabType = 'overview' | 'scans' | 'findings' | 'settings';

export default function ProjectDetailPage() {
  const params = useParams();
  const router = useRouter();
  const projectId = params.id as string;
  const [project, setProject] = useState<ExtendedProject | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);

  useEffect(() => {
    fetchProject();
  }, [projectId]);

  async function fetchProject() {
    try {
      setIsLoading(true);
      setError(null);

      // Fetch project, scans, and findings in parallel
      const [projectData, scansResponse, findingsResponse] = await Promise.all([
        projectsApi.get(projectId),
        scansApi.list({ projectId, limit: 100 }),
        findingsApi.list({ projectId, limit: 100 }),
      ]);

      setProject({
        ...projectData,
        scans: scansResponse.data,
        findings: findingsResponse.data,
      });
    } catch (err) {
      console.error('Failed to fetch project:', err);
      setError(err instanceof Error ? err.message : 'Failed to load project');
    } finally {
      setIsLoading(false);
    }
  }

  async function handleDelete() {
    try {
      setDeleteLoading(true);
      await projectsApi.delete(projectId);
      router.push('/projects');
    } catch (err) {
      console.error('Failed to delete project:', err);
      alert(err instanceof Error ? err.message : 'Failed to delete project');
      setDeleteLoading(false);
    }
  }

  async function handleDownloadReport() {
    if (!project) return;
    const latestCompleted = project.scans.find(s => s.status === 'completed');
    if (!latestCompleted) {
      alert('No completed scan available for download');
      return;
    }
    try {
      setIsDownloading(true);
      const [scanDetail, findingsResponse, attestation] = await Promise.all([
        scansApi.get(latestCompleted.id),
        scansApi.getFindings(latestCompleted.id, { limit: 5000, status: 'all' }),
        scansApi.getAttestation(latestCompleted.id).catch(() => null),
      ]);
      generateComprehensivePDF(
        {
          id: scanDetail.id,
          projectName: scanDetail.projectName,
          branch: scanDetail.branch,
          status: scanDetail.status,
          startedAt: scanDetail.startedAt,
          completedAt: scanDetail.completedAt,
          createdAt: scanDetail.createdAt,
          duration: scanDetail.duration,
          score: scanDetail.score,
          qualityLevel: scanDetail.qualityLevel,
          scanType: scanDetail.scanType,
          findingsCount: scanDetail.findingsCount,
        },
        findingsResponse.data.map((f: Finding) => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          scanner: f.scanner,
          filePath: f.filePath || '',
          line: f.lineNumber || 0,
          cwe: f.cwe || '',
          code: f.codeSnippet || '',
          status: f.status,
          description: f.description,
          fixDescription: f.fixDescription,
          fixAvailable: f.fixAvailable,
          owaspCategory: f.owaspCategory,
          ruleId: f.ruleId,
        })),
        attestation,
      );
    } catch (err) {
      console.error('Failed to download report:', err);
      alert('Failed to generate report');
    } finally {
      setIsDownloading(false);
    }
  }

  if (isLoading) {
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
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load project</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={fetchProject}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  if (!project) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <FolderOpen className="h-12 w-12 text-text-tertiary mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Project not found</h2>
        <p className="text-text-secondary mb-4">The project you're looking for doesn't exist.</p>
        <Link href="/projects" className="btn-primary">
          Back to Projects
        </Link>
      </div>
    );
  }

  const totalScans = project.scans.length;
  const lastScanPassed = project.scans[0]?.findingsCount.critical === 0 && project.scans[0]?.findingsCount.high <= 2;

  return (
    <div className="space-y-6">
      {/* Back Navigation */}
      <Link
        href="/projects"
        className="inline-flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors"
      >
        <ArrowLeft size={16} />
        Back to Projects
      </Link>

      {/* Project Header */}
      <div className="flex items-start justify-between gap-6">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">{project.name}</h1>
          {project.repositoryUrl && (
            <a
              href={project.repositoryUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm text-primary-400 hover:underline mt-1"
            >
              {project.repositoryUrl.replace('https://', '')}
              <ExternalLink size={12} />
            </a>
          )}
          {project.description && (
            <p className="text-text-secondary mt-2">{project.description}</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadReport}
            disabled={isDownloading || !project.scans.some(s => s.status === 'completed')}
            className="flex items-center gap-2 px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors disabled:opacity-50"
          >
            {isDownloading ? <Loader2 size={16} className="animate-spin" /> : <Download size={16} />}
            {isDownloading ? 'Generating...' : 'Download Report'}
          </button>
          <Link
            href={`/scans/new?projectId=${project.id}`}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
          >
            <Play size={16} />
            Run Scan
          </Link>
          <button
            onClick={() => setDeleteModalOpen(true)}
            className="p-2 rounded-lg border border-border-primary hover:bg-bg-tertiary transition-colors"
          >
            <Trash2 size={16} className="text-text-secondary" />
          </button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-bg-secondary border border-border-primary rounded-xl p-6 flex items-center gap-4">
          <ScoreGauge score={project.lastScore ?? 0} size="md" />
          <div>
            <p className="text-sm text-text-tertiary">Score</p>
            <p className="text-2xl font-bold text-text-primary">{project.lastScore ?? 'N/A'}</p>
          </div>
        </div>
        <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
          <p className="text-sm text-text-tertiary mb-1">Total Scans</p>
          <p className="text-2xl font-bold text-text-primary">{totalScans}</p>
          {project.lastScanAt && (
            <p className="text-sm text-text-tertiary mt-1">
              Last: {formatRelativeTime(project.lastScanAt)}
            </p>
          )}
        </div>
        <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
          <p className="text-sm text-text-tertiary mb-1">Status</p>
          <div className="flex items-center gap-2">
            {lastScanPassed ? (
              <>
                <CheckCircle size={20} className="text-success" />
                <span className="text-lg font-semibold text-success">Passing</span>
              </>
            ) : (
              <>
                <AlertTriangle size={20} className="text-warning" />
                <span className="text-lg font-semibold text-warning">Warning</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-border-primary">
        <nav className="flex gap-6">
          {(['overview', 'scans', 'findings', 'settings'] as TabType[]).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={cn(
                'px-1 py-3 text-sm font-medium border-b-2 -mb-px transition-colors capitalize',
                activeTab === tab
                  ? 'border-primary-500 text-primary-400'
                  : 'border-transparent text-text-secondary hover:text-text-primary'
              )}
            >
              {tab}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && <OverviewTab project={project} />}
      {activeTab === 'scans' && <ScansTab scans={project.scans} projectId={project.id} />}
      {activeTab === 'findings' && <FindingsTab findings={project.findings} />}
      {activeTab === 'settings' && <SettingsTab project={project} onDelete={() => setDeleteModalOpen(true)} />}

      {/* Delete Modal */}
      {deleteModalOpen && (
        <DeleteProjectModal
          projectName={project.name}
          onClose={() => setDeleteModalOpen(false)}
          onDelete={handleDelete}
          isLoading={deleteLoading}
        />
      )}
    </div>
  );
}

function OverviewTab({ project }: { project: ExtendedProject }) {
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    project.findings.forEach(f => counts[f.severity]++);
    return counts;
  }, [project.findings]);

  const scoreData = useMemo(() => {
    return project.scans
      .filter(s => s.score != null && s.status === 'completed')
      .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
      .map((s, idx) => ({
        label: `Scan ${idx + 1}`,
        score: s.score!,
        date: new Date(s.createdAt).toLocaleString('en-US', {
          month: 'short',
          day: 'numeric',
          hour: 'numeric',
          minute: '2-digit',
        }),
      }));
  }, [project.scans]);

  return (
    <div className="space-y-6">
      {/* Finding Distribution */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
        <h3 className="text-lg font-semibold text-text-primary mb-4">Finding Distribution</h3>
        <div className="grid grid-cols-5 gap-4">
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => (
            <div key={sev} className="text-center">
              <p className="text-2xl font-bold text-text-primary">{severityCounts[sev]}</p>
              <p className="text-sm text-text-secondary capitalize">{sev}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Score Trend */}
      {scoreData.length >= 2 && (
        <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-text-primary flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-primary-500" />
              Score Trend
            </h3>
            <span className="text-xs text-text-tertiary">{scoreData.length} scans</span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={scoreData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="projectScoreGradient" x1="0" y1="0" x2="0" y2="1">
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
                  domain={[
                    Math.max(0, Math.floor((Math.min(...scoreData.map(d => d.score)) - 50) / 100) * 100),
                    1000,
                  ]}
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
                  fill="url(#projectScoreGradient)"
                  dot={{ r: 4, fill: '#06b6d4', stroke: '#0e1729', strokeWidth: 2 }}
                  activeDot={{ r: 6, fill: '#06b6d4', stroke: '#fff', strokeWidth: 2 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Recent Scans */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary">
          <h3 className="text-lg font-semibold text-text-primary">Recent Scans</h3>
          <Link href="#" onClick={() => {}} className="text-sm text-primary-400 hover:underline">
            View All Scans
          </Link>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-left text-xs text-text-tertiary border-b border-border-primary uppercase tracking-wider">
              <th className="px-6 py-3">Date</th>
              <th className="px-6 py-3">Score</th>
              <th className="px-6 py-3">Findings</th>
              <th className="px-6 py-3">Status</th>
              <th className="px-6 py-3 w-20"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-primary">
            {project.scans.slice(0, 5).map(scan => (
              <tr key={scan.id} className="hover:bg-bg-hover/50 transition-colors">
                <td className="px-6 py-4 text-sm text-text-primary">
                  {formatDateTime(scan.createdAt)}
                </td>
                <td className="px-6 py-4 text-sm font-medium text-text-primary">
                  {scan.score}
                </td>
                <td className="px-6 py-4">
                  <span className="text-sm text-text-secondary">
                    {scan.findingsCount.critical}/{scan.findingsCount.high}/{scan.findingsCount.medium}
                  </span>
                </td>
                <td className="px-6 py-4">
                  {scan.findingsCount.critical === 0 && scan.findingsCount.high <= 2 ? (
                    <span className="text-success text-sm">Pass</span>
                  ) : (
                    <span className="text-warning text-sm">Warning</span>
                  )}
                </td>
                <td className="px-6 py-4">
                  <Link
                    href={`/scans/${scan.id}`}
                    className="text-sm text-primary-400 hover:underline"
                  >
                    View
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ScansTab({ scans, projectId }: { scans: Scan[]; projectId: string }) {
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const totalPages = Math.ceil(scans.length / pageSize);
  const paginatedScans = scans.slice((page - 1) * pageSize, page * pageSize);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-text-primary">Scan History</h3>
        <Link
          href={`/scans/new?projectId=${projectId}`}
          className="flex items-center gap-2 px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          <Play size={16} />
          Run New Scan
        </Link>
      </div>

      <div className="bg-bg-secondary border border-border-primary rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="text-left text-xs text-text-tertiary border-b border-border-primary uppercase tracking-wider">
              <th className="px-6 py-3">Date</th>
              <th className="px-6 py-3">Type</th>
              <th className="px-6 py-3">Score</th>
              <th className="px-6 py-3">Findings</th>
              <th className="px-6 py-3">Duration</th>
              <th className="px-6 py-3 w-20"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-primary">
            {paginatedScans.map(scan => (
              <tr key={scan.id} className="hover:bg-bg-hover/50 transition-colors">
                <td className="px-6 py-4 text-sm text-text-primary">
                  {formatDateTime(scan.createdAt)}
                </td>
                <td className="px-6 py-4">
                  <span className="px-2 py-0.5 text-xs rounded bg-bg-tertiary text-text-secondary capitalize">
                    {scan.scanType}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm font-medium text-text-primary">
                  {scan.score}
                </td>
                <td className="px-6 py-4 text-sm text-text-secondary">
                  {scan.findingsCount.critical}/{scan.findingsCount.high}/{scan.findingsCount.medium}/{scan.findingsCount.low}
                </td>
                <td className="px-6 py-4 text-sm text-text-secondary">
                  {scan.duration}s
                </td>
                <td className="px-6 py-4">
                  <Link href={`/scans/${scan.id}`} className="text-sm text-primary-400 hover:underline">
                    View
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Pagination currentPage={page} totalPages={totalPages} onPageChange={setPage} />
    </div>
  );
}

function FindingsTab({ findings }: { findings: Finding[] }) {
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const grouped = useMemo(() => {
    const filtered = severityFilter === 'all' ? findings : findings.filter(f => f.severity === severityFilter);
    const groups: Record<string, Finding[]> = { critical: [], high: [], medium: [], low: [], info: [] };
    filtered.forEach(f => groups[f.severity].push(f));
    return groups;
  }, [findings, severityFilter]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-bg-tertiary border border-border-primary rounded-lg px-4 py-2 text-sm text-text-primary focus:outline-none focus:border-primary-500"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>

      <div className="space-y-4">
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map(severity => {
          const items = grouped[severity];
          if (items.length === 0) return null;

          return (
            <div key={severity} className="bg-bg-secondary border border-border-primary rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-border-primary flex items-center gap-2">
                <SeverityBadge severity={severity} />
                <span className="text-sm text-text-secondary">({items.length})</span>
              </div>
              <div className="divide-y divide-border-primary">
                {items.map(finding => (
                  <div key={finding.id} className="px-4 py-3 hover:bg-bg-hover/50 transition-colors">
                    <Link
                      href={`/findings/${finding.id}`}
                      className="font-medium text-text-primary hover:text-primary-400"
                    >
                      {finding.title}
                    </Link>
                    <p className="text-sm text-text-tertiary mt-1">
                      {finding.filePath}:{finding.lineNumber} - {finding.cwe} - {finding.scanner}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SettingsTab({ project, onDelete }: { project: ExtendedProject; onDelete: () => void }) {
  const [name, setName] = useState(project.name);
  const [description, setDescription] = useState(project.description || '');
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    try {
      setSaving(true);
      await projectsApi.update(project.id, { name, description });
    } catch (err) {
      console.error('Failed to save project:', err);
      alert(err instanceof Error ? err.message : 'Failed to save project');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-2xl">
      <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
        <h3 className="text-lg font-semibold text-text-primary mb-4">General</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">Project Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-bg-tertiary border border-border-primary rounded-lg px-4 py-2 text-sm text-text-primary focus:outline-none focus:border-primary-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full bg-bg-tertiary border border-border-primary rounded-lg px-4 py-2 text-sm text-text-primary focus:outline-none focus:border-primary-500 resize-none"
            />
          </div>
          <div className="flex justify-end">
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 disabled:opacity-50 transition-colors"
            >
              {saving ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </div>
      </div>

      {/* Scan Context Card */}
      <ScanContextCard project={project} />

      <div className="bg-bg-secondary border border-error/20 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-error mb-2">Danger Zone</h3>
        <p className="text-sm text-text-secondary mb-4">
          Delete this project and all its scan history, findings, and attestations.
        </p>
        <button
          onClick={onDelete}
          className="px-4 py-2 text-sm bg-error/10 text-error border border-error/20 rounded-lg hover:bg-error/20 transition-colors"
        >
          Delete Project
        </button>
      </div>
    </div>
  );
}

interface AuthConfig {
  loginUrl: string;
  usernameField: string;
  passwordField: string;
  username: string;
  password: string;
  csrfTokenSelector: string;
  successIndicator: string;
}

const EMPTY_AUTH: AuthConfig = {
  loginUrl: '',
  usernameField: 'username',
  passwordField: 'password',
  username: '',
  password: '',
  csrfTokenSelector: '',
  successIndicator: '',
};

function ScanContextCard({ project }: { project: ExtendedProject }) {
  const [targetUrl, setTargetUrl] = useState(project.targetUrl || '');
  const [containerImage, setContainerImage] = useState(project.containerImage || '');
  const [openapiSpecPath, setOpenapiSpecPath] = useState(project.openapiSpecPath || '');
  const [savingField, setSavingField] = useState<string | null>(null);
  const [savedField, setSavedField] = useState<string | null>(null);

  const [authExpanded, setAuthExpanded] = useState(false);
  const [authConfig, setAuthConfig] = useState<AuthConfig>(EMPTY_AUTH);
  const [authLoaded, setAuthLoaded] = useState(false);
  const [savingAuth, setSavingAuth] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // Save a project field on blur
  const saveField = async (field: string, value: string) => {
    setSavingField(field);
    setSavedField(null);
    try {
      await projectsApi.update(project.id, { [field]: value || undefined } as Partial<Project>);
      setSavedField(field);
      setTimeout(() => setSavedField(null), 2000);
    } catch (err) {
      console.error(`Failed to save ${field}:`, err);
    } finally {
      setSavingField(null);
    }
  };

  // Load auth config when section is expanded
  const handleExpandAuth = async () => {
    const next = !authExpanded;
    setAuthExpanded(next);
    if (next && !authLoaded) {
      try {
        const config = await api<AuthConfig>(`/projects/${project.id}/auth-config`);
        if (config) {
          setAuthConfig({ ...EMPTY_AUTH, ...config });
        }
      } catch {
        // No auth config exists yet -- keep defaults
      }
      setAuthLoaded(true);
    }
  };

  const saveAuthConfig = async () => {
    setSavingAuth(true);
    try {
      await api(`/projects/${project.id}/auth-config`, {
        method: 'PUT',
        body: JSON.stringify(authConfig),
      });
      setSavedField('auth');
      setTimeout(() => setSavedField(null), 2000);
    } catch (err) {
      console.error('Failed to save auth config:', err);
      alert('Failed to save authentication config');
    } finally {
      setSavingAuth(false);
    }
  };

  const clearAuthConfig = async () => {
    setSavingAuth(true);
    try {
      await api(`/projects/${project.id}/auth-config`, { method: 'DELETE' });
      setAuthConfig(EMPTY_AUTH);
      setSavedField('auth-cleared');
      setTimeout(() => setSavedField(null), 2000);
    } catch (err) {
      console.error('Failed to clear auth config:', err);
    } finally {
      setSavingAuth(false);
    }
  };

  const fieldSaveIndicator = (field: string) => {
    if (savingField === field) return <Loader2 size={14} className="animate-spin text-text-tertiary" />;
    if (savedField === field) return <CheckCircle size={14} className="text-success" />;
    return null;
  };

  const inputClass = 'w-full bg-bg-tertiary border border-border-primary rounded-lg px-4 py-2 text-sm text-text-primary focus:outline-none focus:border-primary-500';

  return (
    <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
      <div className="flex items-center gap-2 mb-1">
        <Globe size={18} className="text-primary-400" />
        <h3 className="text-lg font-semibold text-text-primary">Scan Context</h3>
      </div>
      <p className="text-sm text-text-tertiary mb-5">
        Configure targets for DAST, container, and API scanners. These values are used automatically when scanners need them.
      </p>

      <div className="space-y-4">
        {/* Application URL */}
        <div>
          <label className="block text-sm font-medium text-text-primary mb-2">
            <span className="flex items-center gap-1.5">
              <Globe size={14} className="text-text-tertiary" />
              Application URL
              {fieldSaveIndicator('targetUrl')}
            </span>
          </label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            onBlur={() => { if (targetUrl !== (project.targetUrl || '')) saveField('targetUrl', targetUrl); }}
            placeholder="https://staging.myapp.com"
            className={inputClass}
          />
          <p className="text-xs text-text-tertiary mt-1">
            Used by ZAP, Nuclei, Pa11y, Playwright, and load testing scanners
          </p>
        </div>

        {/* Container Image */}
        <div>
          <label className="block text-sm font-medium text-text-primary mb-2">
            <span className="flex items-center gap-1.5">
              <Container size={14} className="text-text-tertiary" />
              Container Image
              {fieldSaveIndicator('containerImage')}
            </span>
          </label>
          <input
            type="text"
            value={containerImage}
            onChange={(e) => setContainerImage(e.target.value)}
            onBlur={() => { if (containerImage !== (project.containerImage || '')) saveField('containerImage', containerImage); }}
            placeholder="ghcr.io/org/app:latest"
            className={inputClass}
          />
          <p className="text-xs text-text-tertiary mt-1">
            Used by Cosign, Dockle, Trivy (container mode), and Grype (container mode)
          </p>
        </div>

        {/* OpenAPI Spec */}
        <div>
          <label className="block text-sm font-medium text-text-primary mb-2">
            <span className="flex items-center gap-1.5">
              <FileCode size={14} className="text-text-tertiary" />
              OpenAPI Spec
              {fieldSaveIndicator('openapiSpecPath')}
            </span>
          </label>
          <input
            type="text"
            value={openapiSpecPath}
            onChange={(e) => setOpenapiSpecPath(e.target.value)}
            onBlur={() => { if (openapiSpecPath !== (project.openapiSpecPath || '')) saveField('openapiSpecPath', openapiSpecPath); }}
            placeholder="openapi.yaml or https://api.myapp.com/docs/openapi.json"
            className={inputClass}
          />
          <p className="text-xs text-text-tertiary mt-1">
            Used by Spectral, Schemathesis, RESTler, and Newman. Auto-detected from repo if present.
          </p>
        </div>

        {/* Authentication Section */}
        <div className="border border-border-primary rounded-lg overflow-hidden">
          <button
            type="button"
            onClick={handleExpandAuth}
            className="w-full flex items-center justify-between p-4 hover:bg-bg-hover transition-colors"
          >
            <span className="flex items-center gap-2">
              <Lock size={16} className="text-text-secondary" />
              <span className="text-sm font-medium text-text-primary">Authentication</span>
              {project.authConfigured && (
                <span className="px-2 py-0.5 text-xs rounded-full bg-success/10 text-success border border-success/20">
                  Configured
                </span>
              )}
            </span>
            <ChevronRight
              size={16}
              className={cn(
                'text-text-tertiary transition-transform',
                authExpanded && 'rotate-90'
              )}
            />
          </button>

          {authExpanded && (
            <div className="border-t border-border-primary p-4 space-y-4 bg-bg-tertiary/30">
              <p className="text-xs text-text-tertiary">
                Provide login credentials for authenticated DAST scanning (ZAP, Nuclei). Credentials are encrypted at rest.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-text-primary mb-1">Login URL</label>
                  <input
                    type="text"
                    value={authConfig.loginUrl}
                    onChange={(e) => setAuthConfig({ ...authConfig, loginUrl: e.target.value })}
                    placeholder="https://staging.myapp.com/login"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-text-primary mb-1">Success Indicator</label>
                  <input
                    type="text"
                    value={authConfig.successIndicator}
                    onChange={(e) => setAuthConfig({ ...authConfig, successIndicator: e.target.value })}
                    placeholder="URL pattern or element selector after login"
                    className={inputClass}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-text-primary mb-1">Username Field Name</label>
                  <input
                    type="text"
                    value={authConfig.usernameField}
                    onChange={(e) => setAuthConfig({ ...authConfig, usernameField: e.target.value })}
                    placeholder="username"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-text-primary mb-1">Password Field Name</label>
                  <input
                    type="text"
                    value={authConfig.passwordField}
                    onChange={(e) => setAuthConfig({ ...authConfig, passwordField: e.target.value })}
                    placeholder="password"
                    className={inputClass}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-text-primary mb-1">Username</label>
                  <input
                    type="text"
                    value={authConfig.username}
                    onChange={(e) => setAuthConfig({ ...authConfig, username: e.target.value })}
                    placeholder="test-user@example.com"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-text-primary mb-1">Password</label>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={authConfig.password}
                      onChange={(e) => setAuthConfig({ ...authConfig, password: e.target.value })}
                      placeholder="********"
                      className={inputClass}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary hover:text-text-primary"
                    >
                      {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-text-primary mb-1">
                  CSRF Token Selector <span className="text-text-tertiary">(optional)</span>
                </label>
                <input
                  type="text"
                  value={authConfig.csrfTokenSelector}
                  onChange={(e) => setAuthConfig({ ...authConfig, csrfTokenSelector: e.target.value })}
                  placeholder='input[name="_csrf"] or meta[name="csrf-token"]'
                  className={inputClass}
                />
              </div>

              <div className="flex items-center justify-between pt-2">
                <button
                  type="button"
                  onClick={clearAuthConfig}
                  disabled={savingAuth}
                  className="text-sm text-text-secondary hover:text-error transition-colors"
                >
                  Clear Auth Config
                </button>
                <div className="flex items-center gap-2">
                  {savedField === 'auth' && (
                    <span className="text-xs text-success flex items-center gap-1">
                      <CheckCircle size={12} /> Saved
                    </span>
                  )}
                  {savedField === 'auth-cleared' && (
                    <span className="text-xs text-text-tertiary flex items-center gap-1">
                      <CheckCircle size={12} /> Cleared
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={saveAuthConfig}
                    disabled={savingAuth || !authConfig.loginUrl}
                    className="flex items-center gap-2 px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 disabled:opacity-50 transition-colors"
                  >
                    {savingAuth ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                    Save Auth Config
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Registry Credentials Link */}
        <div className="flex items-center gap-2 pt-2">
          <KeyRound size={14} className="text-text-tertiary" />
          <a
            href="/settings/integrations"
            className="text-sm text-primary-400 hover:text-primary-300 transition-colors"
          >
            Manage registry credentials in Integrations settings
          </a>
        </div>
      </div>
    </div>
  );
}

function DeleteProjectModal({
  projectName,
  onClose,
  onDelete,
  isLoading,
}: {
  projectName: string;
  onClose: () => void;
  onDelete: () => void;
  isLoading?: boolean;
}) {
  const [confirm, setConfirm] = useState('');

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-md p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-error/10 flex items-center justify-center">
            <AlertTriangle size={20} className="text-error" />
          </div>
          <h2 className="text-lg font-semibold text-text-primary">Delete Project</h2>
        </div>
        <p className="text-sm text-text-secondary mb-4">
          This action cannot be undone. This will permanently delete the project, all scans, findings, and attestations.
        </p>
        <p className="text-sm text-text-secondary mb-4">
          Type <strong>{projectName}</strong> to confirm:
        </p>
        <input
          type="text"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          disabled={isLoading}
          className="w-full bg-bg-tertiary border border-border-primary rounded-lg px-4 py-2 text-sm text-text-primary focus:outline-none focus:border-primary-500 mb-4 disabled:opacity-50"
        />
        <div className="flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            disabled={isLoading}
            className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={onDelete}
            disabled={confirm !== projectName || isLoading}
            className="px-4 py-2 text-sm bg-error text-white rounded-lg hover:bg-error/90 disabled:opacity-50 transition-colors flex items-center gap-2"
          >
            {isLoading && <Loader2 size={14} className="animate-spin" />}
            Delete Project
          </button>
        </div>
      </div>
    </div>
  );
}
