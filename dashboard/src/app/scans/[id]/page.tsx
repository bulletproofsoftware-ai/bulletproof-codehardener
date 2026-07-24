'use client';

import { useState, useMemo, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  ArrowLeft,
  Download,
  RefreshCw,
  Search,
  Shield,
  Clock,
  FolderKanban,
  GitBranch,
  CheckCircle,
  XCircle,
  AlertCircle,
  Loader2,
  ExternalLink,
  Copy,
  ChevronRight,
  FileCode2,
  Check,
  ScanSearch,
  AlertTriangle,
  BarChart3,
  Info,
  Settings,
} from 'lucide-react';
import { cn, formatDate, formatRelativeTime } from '@/lib/utils';
import { ScoreGauge } from '@/components/ScoreGauge';
import { SeverityBadge } from '@/components/SeverityBadge';
import { EmptyState } from '@/components/EmptyState';
import { scansApi } from '@/lib/api';
import type { Scan, FindingSeverity } from '@/types';
import { generateComprehensivePDF } from '@/lib/generate-scan-pdf';
import type { AttestationData } from '@/lib/generate-scan-pdf';

// Extended scan interface for detailed view
interface ScannerEvidence {
  filesAnalyzed?: number;
  rulesEvaluated?: number;
  checksPerformed?: string[];
  scanScope?: string;
  toolVersion?: string;
  detectionMethod?: string;
  configuration?: string;
  targetsAnalyzed?: string[];
  methodology?: string;
  standards?: string[];
  displayName?: string;
  category?: string;
  sbomPackages?: Array<{ name: string; version: string; type: string; language: string; license: string }>;
}

interface ScannerResult {
  scanner: string;
  status: 'success' | 'error' | 'skipped';
  findingsCount: number;
  duration: number;
  filesScanned: number;
  error?: string;
  skipReason?: string;
  skipHint?: string;
  evidence?: ScannerEvidence;
}

interface ScannedFile {
  path: string;
  findingsCount: number;
  totalFindings?: number;
  openFindings?: number;
  resolvedFindings?: number;
  scanners: string[];
}

interface ScanFinding {
  id: string;
  title: string;
  severity: FindingSeverity;
  scanner: string;
  filePath: string;
  line: number;
  cwe?: string;
  code: string;
  status: string;
  description: string;
  fixDescription?: string;
  fixAvailable?: boolean;
  owaspCategory?: string;
  ruleId?: string;
}

interface ScanPhase {
  name: string;
  status: 'completed' | 'running' | 'pending';
  duration?: number;
  progress?: number;
}

interface ExtendedScan extends Scan {
  previousScore?: number;
  findingsSummary?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  scanners?: string[];
  scannerResults?: ScannerResult[];
  filesScanned?: ScannedFile[];
  fileInventory?: { totalFiles: number; breakdown: string[]; extensions: string[] };
  directories?: number;
  findings?: ScanFinding[];
  attestation?: { id: string; createdAt: string } | null;
  // PR scan properties
  scanScope?: 'full' | 'incremental';
  prScan?: {
    prNumber: number;
    prTitle: string;
    headSha: string;
    changedFiles: string[];
    diffFindingsCount: number;
  };
  // Running scan properties
  progress?: number;
  currentPhase?: string;
  phases?: ScanPhase[];
}

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ExtendedScan | null>(null);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isFindingsLoading, setIsFindingsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchScan();
  }, [scanId]);

  // Poll while scan is running/pending/queued
  useEffect(() => {
    if (!scan || !['running', 'pending', 'queued'].includes(scan.status)) return;
    const interval = setInterval(async () => {
      try {
        const scanData = await scansApi.get(scanId);
        setScan(scanData as ExtendedScan);
        if (scanData.status === 'completed' || scanData.status === 'failed' || scanData.status === 'cancelled') {
          clearInterval(interval);
          fetchFindings();
        }
      } catch (err) {
        console.error('Poll failed:', err);
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [scan?.status, scanId]);

  async function fetchScan() {
    try {
      setIsLoading(true);
      setError(null);
      const scanData = await scansApi.get(scanId);
      setScan(scanData as ExtendedScan);

      // Fetch findings separately if scan is completed
      if (scanData.status === 'completed' || scanData.status === 'failed') {
        fetchFindings();
      }
    } catch (err) {
      console.error('Failed to fetch scan:', err);
      setError(err instanceof Error ? err.message : 'Failed to load scan');
    } finally {
      setIsLoading(false);
    }
  }

  async function fetchFindings() {
    try {
      setIsFindingsLoading(true);
      const response = await scansApi.getFindings(scanId, { limit: 500 });
      // Transform findings to match expected shape
      const transformedFindings: ScanFinding[] = response.data.map((f: any) => ({
        id: f.id,
        title: f.title,
        severity: f.severity as FindingSeverity,
        scanner: f.scanner,
        filePath: f.filePath || '',
        line: f.lineNumber || 0,
        cwe: f.cwe,
        code: f.codeSnippet || '',
        status: f.status || 'open',
        description: f.description || '',
        fixDescription: f.fixDescription || undefined,
        fixAvailable: f.fixAvailable || false,
        owaspCategory: f.owaspCategory || undefined,
        ruleId: f.ruleId || undefined,
      }));
      setFindings(transformedFindings);
    } catch (err) {
      console.error('Failed to fetch findings:', err);
    } finally {
      setIsFindingsLoading(false);
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
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load scan</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={fetchScan}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <ScanSearch className="h-12 w-12 text-text-tertiary mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Scan not found</h2>
        <p className="text-text-secondary mb-4">The scan you are looking for does not exist.</p>
        <Link
          href="/scans"
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Back to Scans
        </Link>
      </div>
    );
  }

  // Show running scan view if scan is in progress
  if (scan.status === 'running' || scan.status === 'pending') {
    return <ScanInProgress scan={scan} />;
  }

  return <CompletedScanView scan={scan} findings={findings} isFindingsLoading={isFindingsLoading} />;
}

function ScanInProgress({ scan }: { scan: ExtendedScan }) {
  const [elapsedTime, setElapsedTime] = useState(
    scan.startedAt ? Date.now() - new Date(scan.startedAt).getTime() : 0
  );

  useEffect(() => {
    if (!scan.startedAt) return;
    const interval = setInterval(() => {
      setElapsedTime(Date.now() - new Date(scan.startedAt!).getTime());
    }, 1000);
    return () => clearInterval(interval);
  }, [scan.startedAt]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <Link
            href="/scans"
            className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary mb-2"
          >
            <ArrowLeft size={16} />
            Back to Scans
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">
              Scan #{scan.id.slice(0, 8)}
            </h1>
            <span className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-primary-500/10 text-primary-400 text-sm">
              <Loader2 size={14} className="animate-spin" />
              Running
            </span>
          </div>
          <div className="mt-2 flex items-center gap-4 text-sm text-text-secondary">
            <span className="flex items-center gap-1.5">
              <FolderKanban size={14} />
              {scan.projectName}
            </span>
            <span className="flex items-center gap-1.5">
              <GitBranch size={14} />
              {scan.branch || 'main'}
            </span>
            <span className="flex items-center gap-1.5">
              <Clock size={14} />
              Started {scan.startedAt ? formatRelativeTime(scan.startedAt) : 'just now'}
            </span>
          </div>
        </div>
        <button
          onClick={() => console.log('Cancel scan')}
          className="px-4 py-2 text-sm border border-error/20 text-error rounded-lg hover:bg-error/10 transition-colors"
        >
          Cancel Scan
        </button>
      </div>

      {/* Progress Card */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-lg font-semibold text-text-primary">Scan Progress</h2>
            <p className="text-sm text-text-secondary mt-1">{scan.currentPhase || 'Running scan...'}</p>
          </div>
          <div className="text-right">
            <span className="text-2xl font-bold text-primary-400">{scan.progress || 0}%</span>
            <p className="text-sm text-text-tertiary">Elapsed: {formatDuration(elapsedTime)}</p>
          </div>
        </div>

        {/* Overall Progress Bar */}
        <div className="h-3 bg-bg-tertiary rounded-full overflow-hidden mb-8">
          <div
            className="h-full bg-gradient-to-r from-primary-500 to-accent-500 transition-all duration-500"
            style={{ width: `${scan.progress || 0}%` }}
          />
        </div>

        {/* Phases */}
        <div className="space-y-3">
          {scan.phases?.map((phase, index) => (
            <div
              key={index}
              className={cn(
                'flex items-center gap-4 p-3 rounded-lg',
                phase.status === 'running' ? 'bg-primary-500/10 border border-primary-500/20' : 'bg-bg-tertiary'
              )}
            >
              <div className="flex-shrink-0">
                {phase.status === 'completed' && (
                  <CheckCircle size={20} className="text-success" />
                )}
                {phase.status === 'running' && (
                  <Loader2 size={20} className="text-primary-400 animate-spin" />
                )}
                {phase.status === 'pending' && (
                  <div className="w-5 h-5 rounded-full border-2 border-text-tertiary" />
                )}
              </div>
              <div className="flex-1">
                <span
                  className={cn(
                    'text-sm font-medium',
                    phase.status === 'completed'
                      ? 'text-text-secondary'
                      : phase.status === 'running'
                      ? 'text-primary-400'
                      : 'text-text-tertiary'
                  )}
                >
                  {phase.name}
                </span>
              </div>
              <div className="text-sm text-text-tertiary">
                {phase.duration && formatDuration(phase.duration)}
                {phase.status === 'running' && phase.progress !== undefined && (
                  <span className="text-primary-400">{phase.progress}%</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function CompletedScanView({ scan, findings, isFindingsLoading }: {
  scan: ExtendedScan;
  findings: ScanFinding[];
  isFindingsLoading: boolean;
}) {
  const [activeTab, setActiveTab] = useState('findings');
  const [isDownloading, setIsDownloading] = useState(false);
  const trendDiff = scan.previousScore && scan.score ? scan.score - scan.previousScore : 0;
  const trend: 'up' | 'down' | 'stable' | undefined = trendDiff > 20 ? 'up' : trendDiff < -20 ? 'down' : trendDiff !== 0 ? 'stable' : undefined;

  async function handleDownloadReport() {
    setIsDownloading(true);
    try {
      // Fetch ALL findings (not just open) for the comprehensive report
      const allFindingsResponse = await scansApi.getFindings(scan.id, { limit: 5000, status: 'all' });
      const allFindings: ScanFinding[] = allFindingsResponse.data.map((f: any) => ({
        id: f.id,
        title: f.title,
        severity: f.severity as FindingSeverity,
        scanner: f.scanner,
        filePath: f.filePath || '',
        line: f.lineNumber || 0,
        cwe: f.cwe,
        code: f.codeSnippet || '',
        status: f.status || 'open',
        description: f.description || '',
        fixDescription: f.fixDescription || undefined,
        fixAvailable: f.fixAvailable || false,
        owaspCategory: f.owaspCategory || undefined,
        ruleId: f.ruleId || undefined,
      }));

      let attestation: AttestationData | null = null;
      try {
        attestation = await scansApi.getAttestation(scan.id) as AttestationData;
      } catch {
        // No attestation exists for this scan — that's fine
      }
      generateComprehensivePDF(scan, allFindings, attestation);
    } catch (err) {
      console.error('Failed to generate report:', err);
      alert('Failed to generate PDF report');
    } finally {
      setIsDownloading(false);
    }
  }

  const findingsCount = scan.findingsCount
    ? Object.values(scan.findingsCount).reduce((a, b) => a + b, 0)
    : findings.length;

  const tabs = [
    { id: 'findings', label: 'Findings', count: findingsCount },
    { id: 'scanners', label: 'Scanner Results' },
    { id: 'files', label: 'Codebase Coverage' },
    { id: 'attestation', label: 'Attestation' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <Link
            href="/scans"
            className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary mb-2"
          >
            <ArrowLeft size={16} />
            Back to Scans
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">
              Scan #{scan.id.slice(0, 8)}
            </h1>
            <span className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-success/10 text-success text-sm">
              <CheckCircle size={14} />
              Completed
            </span>
            {scan.scanScope === 'incremental' && (
              <span className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-primary-500/10 text-primary-400 text-sm">
                <GitBranch size={14} />
                PR #{scan.prScan?.prNumber || '?'}
              </span>
            )}
          </div>
          {scan.prScan && (
            <div className="mt-2 flex items-center gap-3 text-sm">
              <span className="text-text-secondary">{scan.prScan.prTitle}</span>
              <span className="text-text-tertiary">{scan.prScan.changedFiles?.length || 0} files changed</span>
              <span className="text-text-tertiary">{scan.prScan.diffFindingsCount} diff findings</span>
            </div>
          )}
          <div className="mt-2 flex items-center gap-4 text-sm text-text-secondary">
            <span className="flex items-center gap-1.5">
              <FolderKanban size={14} />
              <Link href={`/projects/${scan.projectId}`} className="hover:text-primary-400">
                {scan.projectName}
              </Link>
              <span className="text-text-tertiary">/</span>
              <span>{scan.branch || 'main'}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <Clock size={14} />
              {scan.startedAt ? formatDate(scan.startedAt) : 'N/A'}
            </span>
            <span>Duration: {formatDuration(scan.duration || 0)}</span>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleDownloadReport}
            disabled={isDownloading}
            className="flex items-center gap-2 px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-hover transition-colors disabled:opacity-50"
          >
            {isDownloading ? <Loader2 size={16} className="animate-spin" /> : <Download size={16} />}
            {isDownloading ? 'Generating...' : 'Download Report'}
          </button>
          <button
            onClick={() => {
              if (!scan) return;
              scansApi.create({
                projectId: scan.projectId,
                scanType: scan.scanType || 'standard',
                branch: scan.branch || undefined,
              }).then(() => {
                window.location.href = '/scans';
              }).catch((err: unknown) => {
                console.error('Failed to re-run scan:', err);
                alert('Failed to start new scan');
              });
            }}
            className="btn-primary"
          >
            <RefreshCw size={16} />
            Re-run Scan
          </button>
        </div>
      </div>

      {/* Score Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Score Gauge */}
        <div className="card flex items-center justify-center py-8">
          <ScoreGauge score={scan.score ?? 0} scoreRaw={scan.scoreRaw} size="lg" trend={trend} />
        </div>

        {/* Findings Breakdown */}
        <div className="card lg:col-span-2 p-6">
          <h3 className="text-lg font-semibold text-text-primary mb-4">Findings by Severity</h3>
          {scan.findingsCount ? (
            <FindingsBarChart findings={scan.findingsCount} />
          ) : (
            <p className="text-text-secondary">No findings summary available.</p>
          )}

          {/* Attestation CTA */}
          <div className="mt-6 pt-4 border-t border-border-primary">
            <Link
              href={`/attestations/new?scanId=${scan.id}`}
              className="btn-primary inline-flex"
            >
              <Shield size={16} />
              Create Attestation
            </Link>
          </div>
        </div>
      </div>

      {/* Scanner Coverage */}
      {scan.scannerResults && scan.scannerResults.length > 0 && (
        <ScannerCoverageBar scannerResults={scan.scannerResults} projectId={scan.projectId} />
      )}

      {/* Tabs */}
      <div className="card p-0">
        {/* Tab Headers */}
        <div className="border-b border-border-primary">
          <nav className="flex gap-0">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'px-6 py-4 text-sm font-medium border-b-2 -mb-px transition-colors',
                  activeTab === tab.id
                    ? 'border-primary-500 text-primary-400'
                    : 'border-transparent text-text-secondary hover:text-text-primary'
                )}
              >
                {tab.label}
                {tab.count !== undefined && (
                  <span className="ml-2 px-2 py-0.5 text-xs rounded-full bg-bg-tertiary">
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="p-6">
          {activeTab === 'findings' && <FindingsTab scan={scan} findings={findings} isLoading={isFindingsLoading} />}
          {activeTab === 'scanners' && <ScannersTab scan={scan} findings={findings} />}
          {activeTab === 'files' && <FilesTab scan={scan} />}
          {activeTab === 'attestation' && <AttestationTab scan={scan} />}
        </div>
      </div>
    </div>
  );
}

// Human-readable labels for skip reasons
const SKIP_REASON_LABELS: Record<string, { label: string; hint: string; icon: typeof AlertTriangle }> = {
  no_target_url: {
    label: 'No Target URL',
    hint: 'Add an Application URL in Project Settings to enable these scanners',
    icon: AlertCircle,
  },
  no_container_image: {
    label: 'No Container Image',
    hint: 'Add a Container Image in Project Settings to enable these scanners',
    icon: AlertCircle,
  },
  no_api_spec: {
    label: 'No API Spec',
    hint: 'Add an OpenAPI spec or Postman collection in Project Settings',
    icon: AlertCircle,
  },
  language_mismatch: {
    label: 'Language Not Detected',
    hint: 'These scanners require specific languages not found in this project',
    icon: Info,
  },
  no_applicable_files: {
    label: 'No Applicable Files',
    hint: 'No files matching the scanner criteria were found in this project',
    icon: Info,
  },
};

function ScannerCoverageBar({ scannerResults, projectId }: { scannerResults: ScannerResult[]; projectId: string }) {
  const [showSkipped, setShowSkipped] = useState(false);

  const totalScanners = scannerResults.length;
  const runningScanners = scannerResults.filter(r => r.status !== 'skipped').length;
  const skippedScanners = scannerResults.filter(r => r.status === 'skipped');
  const coveragePct = totalScanners > 0 ? Math.round((runningScanners / totalScanners) * 100) : 0;

  // Group skipped scanners by reason
  const skippedGroups = useMemo(() => {
    const groups: Record<string, ScannerResult[]> = {};
    for (const s of skippedScanners) {
      const reason = s.skipReason || 'no_applicable_files';
      if (!groups[reason]) groups[reason] = [];
      groups[reason].push(s);
    }
    return groups;
  }, [skippedScanners]);

  if (totalScanners === 0) return null;

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <BarChart3 size={18} className="text-primary-400" />
          <h3 className="text-lg font-semibold text-text-primary">Scanner Coverage</h3>
        </div>
        <span className="text-sm text-text-secondary">
          {runningScanners}/{totalScanners} scanners ran ({coveragePct}%)
        </span>
      </div>

      {/* Progress Bar */}
      <div className="h-3 bg-bg-tertiary rounded-full overflow-hidden mb-2">
        <div
          className={cn(
            'h-full rounded-full transition-all duration-500',
            coveragePct === 100 ? 'bg-success' : coveragePct >= 70 ? 'bg-primary-500' : 'bg-warning'
          )}
          style={{ width: `${coveragePct}%` }}
        />
      </div>

      {/* Mini legend */}
      <div className="flex items-center gap-4 text-xs text-text-tertiary">
        <span className="flex items-center gap-1.5">
          <CheckCircle size={12} className="text-success" />
          {scannerResults.filter(r => r.status === 'success' && r.findingsCount === 0).length} passed
        </span>
        <span className="flex items-center gap-1.5">
          <XCircle size={12} className="text-error" />
          {scannerResults.filter(r => r.status === 'success' && r.findingsCount > 0).length} findings
        </span>
        {scannerResults.filter(r => r.status === 'error').length > 0 && (
          <span className="flex items-center gap-1.5">
            <AlertCircle size={12} className="text-orange-400" />
            {scannerResults.filter(r => r.status === 'error').length} errors
          </span>
        )}
        {skippedScanners.length > 0 && (
          <button
            onClick={() => setShowSkipped(!showSkipped)}
            className="flex items-center gap-1.5 hover:text-text-primary transition-colors"
          >
            <AlertCircle size={12} className="text-text-tertiary" />
            {skippedScanners.length} skipped
            <ChevronRight size={12} className={cn('transition-transform', showSkipped && 'rotate-90')} />
          </button>
        )}
      </div>

      {/* Skipped Scanners Section */}
      {showSkipped && Object.keys(skippedGroups).length > 0 && (
        <div className="mt-4 pt-4 border-t border-border-primary space-y-3">
          <h4 className="text-sm font-medium text-text-primary">Skipped Scanners</h4>
          {Object.entries(skippedGroups).map(([reason, results]) => {
            const meta = SKIP_REASON_LABELS[reason] || {
              label: reason.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
              hint: '',
              icon: Info,
            };
            const ReasonIcon = meta.icon;

            return (
              <div key={reason} className="rounded-lg bg-bg-tertiary border border-border-primary p-3">
                <div className="flex items-start gap-2 mb-2">
                  <ReasonIcon size={16} className="text-warning mt-0.5 flex-shrink-0" />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-text-primary">{meta.label}</span>
                      <span className="text-xs text-text-tertiary">({results.length} scanner{results.length > 1 ? 's' : ''})</span>
                    </div>
                    <p className="text-xs text-text-tertiary mt-0.5">
                      {results.map(r => {
                        const scannerMeta = SCANNER_META[r.scanner];
                        return scannerMeta?.category ? r.scanner : r.scanner;
                      }).join(', ')}
                    </p>
                  </div>
                </div>
                {meta.hint && (
                  <div className="flex items-center gap-2 ml-6">
                    <Settings size={12} className="text-primary-400 flex-shrink-0" />
                    <Link
                      href={`/projects/${projectId}`}
                      className="text-xs text-primary-400 hover:text-primary-300"
                    >
                      {meta.hint}
                    </Link>
                  </div>
                )}
                {/* Show individual skip hints if different from group hint */}
                {results.some(r => r.skipHint && r.skipHint !== meta.hint) && (
                  <div className="ml-6 mt-1 space-y-0.5">
                    {results.filter(r => r.skipHint && r.skipHint !== meta.hint).map(r => (
                      <p key={r.scanner} className="text-xs text-text-tertiary">
                        {r.scanner}: {r.skipHint}
                      </p>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

interface FindingsSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

function FindingsBarChart({ findings }: { findings: FindingsSummary }) {
  const total = Object.values(findings).reduce((a, b) => a + b, 0);
  const maxCount = Math.max(...Object.values(findings));

  const severities: { key: keyof FindingsSummary; label: string; color: string }[] = [
    { key: 'critical', label: 'Critical', color: 'bg-error' },
    { key: 'high', label: 'High', color: 'bg-orange-500' },
    { key: 'medium', label: 'Medium', color: 'bg-warning' },
    { key: 'low', label: 'Low', color: 'bg-info' },
    { key: 'info', label: 'Info', color: 'bg-text-tertiary' },
  ];

  return (
    <div className="space-y-3">
      {severities.map(({ key, label, color }) => (
        <div key={key} className="flex items-center gap-4">
          <div className="w-16 text-sm text-text-secondary">{label}</div>
          <div className="flex-1 h-6 bg-bg-tertiary rounded-full overflow-hidden">
            <div
              className={cn('h-full rounded-full transition-all duration-500', color)}
              style={{ width: maxCount > 0 ? `${(findings[key] / maxCount) * 100}%` : '0%' }}
            />
          </div>
          <div className="w-8 text-sm font-medium text-text-primary text-right">
            {findings[key]}
          </div>
        </div>
      ))}
      <div className="text-sm text-text-tertiary pt-2">
        {total} total findings
      </div>
    </div>
  );
}

function FindingsTab({ scan: _scan, findings, isLoading }: {
  scan: ExtendedScan;
  findings: ScanFinding[];
  isLoading: boolean;
}) {
  const [severity, setSeverity] = useState<string>('all');
  const [scanner, setScanner] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Get unique scanners from findings
  const scanners = useMemo(() => {
    const unique = new Set(findings.map(f => f.scanner));
    return Array.from(unique);
  }, [findings]);

  const filteredFindings = useMemo(() => {
    return findings.filter(finding => {
      if (severity !== 'all' && finding.severity !== severity) return false;
      if (scanner !== 'all' && finding.scanner !== scanner) return false;
      if (search && !finding.title.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [findings, severity, scanner, search]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
        <span className="ml-3 text-text-secondary">Loading findings...</span>
      </div>
    );
  }

  const copyCode = (id: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
        <select
          value={severity}
          onChange={e => setSeverity(e.target.value)}
          className="input w-full sm:w-40"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        <select
          value={scanner}
          onChange={e => setScanner(e.target.value)}
          className="input w-full sm:w-40"
        >
          <option value="all">All Scanners</option>
          {scanners.map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <div className="flex-1 relative w-full">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-tertiary" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search findings..."
            className="input pl-10 w-full"
          />
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {filteredFindings.map(finding => (
          <div
            key={finding.id}
            className="p-4 rounded-lg bg-bg-tertiary border border-border-primary hover:border-border-secondary transition-colors"
          >
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-start gap-3">
                <SeverityBadge severity={finding.severity} size="sm" />
                <div>
                  <h4 className="font-medium text-text-primary">{finding.title}</h4>
                  <div className="flex items-center gap-3 mt-1 text-sm text-text-tertiary">
                    <span className="font-mono">{finding.filePath}:{finding.line}</span>
                    <span>{finding.scanner}</span>
                    {finding.cwe && <span>{finding.cwe}</span>}
                  </div>
                </div>
              </div>
            </div>

            {/* Code Snippet */}
            <div className="relative bg-bg-secondary rounded-lg p-3 font-mono text-sm">
              <pre className="text-text-secondary overflow-x-auto">
                <span className="text-text-tertiary mr-4">{finding.line}</span>
                <span className="text-error">{finding.code}</span>
              </pre>
              <button
                onClick={() => copyCode(finding.id, finding.code)}
                className="absolute top-2 right-2 p-1.5 rounded hover:bg-bg-tertiary transition-colors"
                title="Copy code"
              >
                {copiedId === finding.id ? (
                  <Check size={14} className="text-success" />
                ) : (
                  <Copy size={14} className="text-text-tertiary" />
                )}
              </button>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-between mt-3">
              <Link
                href={`/findings/${finding.id}`}
                className="text-sm text-primary-400 hover:text-primary-300 flex items-center gap-1"
              >
                View Details
                <ChevronRight size={14} />
              </Link>
              <button
                disabled
                title="Coming soon — requires scan artifact storage"
                className="text-sm text-text-secondary flex items-center gap-1 opacity-50 cursor-not-allowed"
              >
                Apply Fix
                <ExternalLink size={14} />
              </button>
            </div>
          </div>
        ))}

        {filteredFindings.length === 0 && (
          <EmptyState
            icon={CheckCircle}
            title="No findings match your filters"
            description="Try adjusting your filters or search query"
          />
        )}
      </div>
    </div>
  );
}

// Scanner metadata: category, description, and what each tool checks
const SCANNER_META: Record<string, { category: string; description: string }> = {
  // SAST
  opengrep: { category: 'SAST', description: 'Multi-language static analysis for security vulnerabilities' },
  bandit: { category: 'SAST', description: 'Python-specific security linter for common vulnerabilities' },
  gosec: { category: 'SAST', description: 'Go source code security analyzer' },
  'eslint-security': { category: 'SAST', description: 'JavaScript/TypeScript security linting rules' },
  pmd: { category: 'SAST', description: 'Multi-language static analysis for code quality and security' },
  // DAST
  nuclei: { category: 'DAST', description: 'Dynamic application security testing with vulnerability templates' },
  zap: { category: 'DAST', description: 'OWASP ZAP dynamic application security testing' },
  // SCA
  trivy: { category: 'SCA', description: 'Container image and filesystem vulnerability scanner' },
  grype: { category: 'SCA', description: 'Dependency vulnerability scanner for containers and filesystems' },
  // Secrets
  gitleaks: { category: 'Secrets', description: 'Detects hardcoded secrets and credentials in git repos' },
  // IaC
  checkov: { category: 'IaC', description: 'Infrastructure-as-code security scanner for Dockerfiles, Terraform, K8s' },
  // Load Testing
  locust: { category: 'Load Testing', description: 'Python-based load testing framework' },
  artillery: { category: 'Load Testing', description: 'Modern load testing and performance measurement' },
  k6: { category: 'Load Testing', description: 'Modern load testing tool for engineering teams' },
  // API Testing
  newman: { category: 'API Testing', description: 'Postman collection runner for API testing' },
  pact: { category: 'API Testing', description: 'Consumer-driven contract testing' },
  restler: { category: 'API Testing', description: 'Stateful REST API fuzzing tool' },
  schemathesis: { category: 'API Testing', description: 'Schema-driven API testing and validation' },
  // Browser/Visual/Accessibility
  playwright: { category: 'Browser Testing', description: 'End-to-end browser testing framework' },
  backstop: { category: 'Visual Testing', description: 'Visual regression testing for web UIs' },
  pa11y: { category: 'Accessibility', description: 'Automated accessibility testing (WCAG 2.1)' },
  // Supply Chain
  syft: { category: 'SBOM', description: 'Software bill of materials generator for supply chain visibility' },
  cosign: { category: 'Supply Chain', description: 'Container image signing and verification' },
  // Container
  dockle: { category: 'Container', description: 'Container image linter for CIS Docker benchmarks' },
  // Policy & Reporting
  opa: { category: 'Policy', description: 'Open Policy Agent policy evaluation engine' },
  conftest: { category: 'Policy', description: 'Policy testing for structured configuration data' },
  // Runtime/Chaos
  toxiproxy: { category: 'Chaos Testing', description: 'Chaos/resilience testing configuration analysis' },
  // AI Code Quality
  'llm-guard': { category: 'AI Security', description: 'Input/output guardrails for LLM applications' },
  'package-validator': { category: 'AI Code Quality', description: 'Detects hallucinated packages in dependency files' },
  stryker: { category: 'AI Code Quality', description: 'JavaScript/TypeScript mutation testing' },
  mutmut: { category: 'AI Code Quality', description: 'Python mutation testing for test quality' },
  pitest: { category: 'AI Code Quality', description: 'Java/JVM mutation testing for test quality' },
  scancode: { category: 'AI Code Quality', description: 'Snippet-level license detection for copyleft contamination' },
  aflpp: { category: 'AI Code Quality', description: 'Coverage-guided fuzz testing for C/C++ memory safety' },
  keploy: { category: 'API Testing', description: 'Record-replay API test coverage analysis' },
  deepeval: { category: 'AI Code Quality', description: 'LLM-as-Judge heuristic code analysis' },
  threatmodel: { category: 'Threat Modeling', description: 'STRIDE automated threat modeling' },
  jest: { category: 'Test Runners', description: 'JavaScript/TypeScript test execution and coverage' },
  pytest: { category: 'Test Runners', description: 'Python test execution and coverage' },
  // v2 additions
  lychee: { category: 'Code Quality', description: 'Broken link detection in documentation and HTML files' },
  'axe-core': { category: 'DAST', description: 'WCAG 2.1 accessibility compliance testing via axe-core' },
  c8: { category: 'Test Runners', description: 'Code coverage measurement and threshold enforcement' },
  'fast-check': { category: 'Test Runners', description: 'JavaScript/TypeScript property-based testing' },
  hypothesis: { category: 'Test Runners', description: 'Python property-based testing with automatic shrinking' },
  sqlmap: { category: 'DAST', description: 'SQL injection detection and exploitation testing' },
  dalfox: { category: 'DAST', description: 'Cross-site scripting (XSS) vulnerability scanning' },
  ffuf: { category: 'DAST', description: 'Web endpoint discovery and directory fuzzing' },
  socket: { category: 'SCA', description: 'Supply chain attack detection for npm/PyPI packages' },
  giskard: { category: 'AI Code Quality', description: 'LLM prompt injection and data leakage testing' },
  // Pre-v2 scanners missing from metadata
  spectral: { category: 'API Testing', description: 'OpenAPI/AsyncAPI specification linting' },
  'dotenv-linter': { category: 'Code Quality', description: '.env file format and security validation' },
  libyear: { category: 'SCA', description: 'Dependency freshness scoring (majors behind)' },
  'cargo-audit': { category: 'SCA', description: 'Rust dependency vulnerability audit' },
  'license-finder': { category: 'Compliance', description: 'Dependency license compliance checker' },
  'kube-linter': { category: 'IaC', description: 'Kubernetes manifest security linting' },
  kubeconform: { category: 'IaC', description: 'Kubernetes manifest schema validation' },
  poutine: { category: 'CI/CD Security', description: 'CI/CD pipeline security analysis' },
  'selenium-gen': { category: 'Test Runners', description: 'Selenium WebDriver test code generator' },
};

function getScannerOutcome(result: ScannerResult): 'pass' | 'fail' | 'skipped' | 'error' {
  if (result.status === 'skipped') return 'skipped';
  if (result.status === 'error') return 'error';
  return result.findingsCount === 0 ? 'pass' : 'fail';
}

function OutcomeBadge({ outcome }: { outcome: 'pass' | 'fail' | 'skipped' | 'error' }) {
  const styles = {
    pass: 'bg-success/10 text-success border-success/20',
    fail: 'bg-error/10 text-error border-error/20',
    skipped: 'bg-text-tertiary/10 text-text-tertiary border-text-tertiary/20',
    error: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  };
  const icons = {
    pass: <CheckCircle size={14} />,
    fail: <XCircle size={14} />,
    skipped: <AlertCircle size={14} />,
    error: <AlertCircle size={14} />,
  };
  const labels = { pass: 'Pass', fail: 'Fail', skipped: 'Not Applicable - Skipped', error: 'Error' };

  return (
    <span className={cn('flex items-center gap-1.5 px-3 py-1 rounded-full border text-sm font-medium', styles[outcome])}>
      {icons[outcome]}
      {labels[outcome]}
    </span>
  );
}

// Badge showing finding resolution status
function FindingStatusBadge({ status }: { status: string }) {
  const config: Record<string, { label: string; className: string; icon: typeof CheckCircle }> = {
    open: { label: 'Open', className: 'text-error bg-error/10', icon: XCircle },
    fixed: { label: 'Fixed', className: 'text-success bg-success/10', icon: CheckCircle },
    false_positive: { label: 'False Positive', className: 'text-text-tertiary bg-bg-secondary', icon: AlertCircle },
    ignored: { label: 'Ignored', className: 'text-text-tertiary bg-bg-secondary', icon: AlertCircle },
    accepted: { label: 'Accepted', className: 'text-info bg-info/10', icon: CheckCircle },
    wont_fix: { label: "Won't Fix", className: 'text-text-tertiary bg-bg-secondary', icon: AlertCircle },
  };
  const c = config[status] || config.open;
  const Icon = c.icon;
  return (
    <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap', c.className)}>
      <Icon size={12} />
      {c.label}
    </span>
  );
}

function ScannersTab({ scan, findings: _initialFindings }: { scan: ExtendedScan; findings: ScanFinding[] }) {
  const [expandedScanner, setExpandedScanner] = useState<string | null>(null);
  const [scannerFindingsCache, setScannerFindingsCache] = useState<Record<string, ScanFinding[]>>({});
  const [loadingScanner, setLoadingScanner] = useState<string | null>(null);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  if (!scan.scannerResults || scan.scannerResults.length === 0) {
    return (
      <EmptyState
        icon={FileCode2}
        title="No scanner results"
        description="Scanner results are not available for this scan."
      />
    );
  }

  async function toggleScanner(scannerName: string) {
    if (expandedScanner === scannerName) {
      setExpandedScanner(null);
      return;
    }
    setExpandedScanner(scannerName);
    setExpandedFinding(null);

    // Fetch scanner-specific findings if not already cached
    if (!scannerFindingsCache[scannerName]) {
      setLoadingScanner(scannerName);
      try {
        const response = await scansApi.getFindings(scan.id, { scanner: scannerName, limit: 200 });
        const transformed: ScanFinding[] = response.data.map((f: any) => ({
          id: f.id,
          title: f.title,
          severity: f.severity as FindingSeverity,
          scanner: f.scanner,
          filePath: f.filePath || '',
          line: f.lineNumber || 0,
          cwe: f.cwe,
          code: f.codeSnippet || '',
          status: f.status || 'open',
          description: f.description || '',
          fixDescription: f.fixDescription || undefined,
          fixAvailable: f.fixAvailable || false,
          owaspCategory: f.owaspCategory || undefined,
          ruleId: f.ruleId || undefined,
        }));
        setScannerFindingsCache(prev => ({ ...prev, [scannerName]: transformed }));
      } catch (err) {
        console.error('Failed to fetch findings for scanner: %s %o', scannerName, err);
        setScannerFindingsCache(prev => ({ ...prev, [scannerName]: [] }));
      } finally {
        setLoadingScanner(null);
      }
    }
  }

  // Summary counts
  const passCount = scan.scannerResults.filter(r => getScannerOutcome(r) === 'pass').length;
  const failCount = scan.scannerResults.filter(r => getScannerOutcome(r) === 'fail').length;
  const skippedCount = scan.scannerResults.filter(r => getScannerOutcome(r) === 'skipped').length;
  const errorCount = scan.scannerResults.filter(r => getScannerOutcome(r) === 'error').length;

  return (
    <div className="space-y-4">
      {/* Summary Bar */}
      <div className="flex items-center gap-6 p-4 rounded-lg bg-bg-tertiary border border-border-primary">
        <span className="text-sm font-medium text-text-primary">
          {scan.scannerResults.length} tools executed
        </span>
        <div className="flex items-center gap-4 text-sm">
          <span className="flex items-center gap-1.5 text-success">
            <CheckCircle size={14} />
            {passCount} passed
          </span>
          <span className="flex items-center gap-1.5 text-error">
            <XCircle size={14} />
            {failCount} failed
          </span>
          {skippedCount > 0 && (
            <span className="flex items-center gap-1.5 text-text-tertiary">
              <AlertCircle size={14} />
              {skippedCount} skipped
            </span>
          )}
          {errorCount > 0 && (
            <span className="flex items-center gap-1.5 text-orange-400">
              <AlertCircle size={14} />
              {errorCount} error{errorCount > 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      {/* Scanner Cards */}
      {scan.scannerResults.map(result => {
        const outcome = getScannerOutcome(result);
        const meta = SCANNER_META[result.scanner] || { category: 'Other', description: 'Security scanner' };
        const isExpanded = expandedScanner === result.scanner;
        const cachedFindings = scannerFindingsCache[result.scanner];
        const isLoading = loadingScanner === result.scanner;

        // Compute status breakdown from cached findings
        const statusCounts = cachedFindings
          ? cachedFindings.reduce((acc, f) => {
              acc[f.status] = (acc[f.status] || 0) + 1;
              return acc;
            }, {} as Record<string, number>)
          : null;

        return (
          <div
            key={result.scanner}
            className={cn(
              'rounded-lg border transition-colors',
              isExpanded
                ? 'border-primary-500/30 bg-bg-tertiary'
                : 'border-border-primary bg-bg-tertiary hover:border-border-secondary'
            )}
          >
            {/* Scanner Header */}
            <div className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={cn(
                    'w-10 h-10 rounded-lg flex items-center justify-center text-xs font-bold',
                    outcome === 'pass' ? 'bg-success/10 text-success' :
                    outcome === 'fail' ? 'bg-error/10 text-error' :
                    'bg-bg-secondary text-text-tertiary'
                  )}>
                    <FileCode2 size={20} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="font-medium text-text-primary">{result.scanner}</h4>
                      <span className="px-2 py-0.5 text-xs rounded bg-bg-secondary text-text-tertiary">
                        {meta.category}
                      </span>
                    </div>
                    <p className="text-sm text-text-tertiary">{meta.description}</p>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <OutcomeBadge outcome={outcome} />
                  {(
                    <button
                      onClick={() => toggleScanner(result.scanner)}
                      className={cn(
                        'px-3 py-1.5 text-sm rounded-lg border transition-colors flex items-center gap-1.5',
                        isExpanded
                          ? 'bg-primary-500/10 border-primary-500/30 text-primary-400'
                          : 'border-border-primary text-text-secondary hover:text-text-primary hover:bg-bg-hover'
                      )}
                    >
                      {isExpanded ? 'Hide' : 'View'}
                      <ChevronRight size={14} className={cn('transition-transform', isExpanded && 'rotate-90')} />
                    </button>
                  )}
                </div>
              </div>

              {/* Stats Row */}
              <div className="flex items-center gap-6 mt-3 text-sm text-text-secondary">
                <span className="flex items-center gap-1.5">
                  <Clock size={14} />
                  {formatDuration(result.duration)}
                </span>
                <span>
                  {result.findingsCount} finding{result.findingsCount !== 1 ? 's' : ''}
                </span>
                {result.filesScanned > 0 && (
                  <span>{result.filesScanned} files scanned</span>
                )}
              </div>

              {result.status === 'error' && result.error && (
                <div className="mt-3 p-3 rounded bg-error/10 border border-error/20 text-sm text-error">
                  {result.error}
                </div>
              )}
            </div>

            {/* Expanded Detail Panel */}
            {isExpanded && (
              <div className="border-t border-border-primary">
                {/* Loading State */}
                {isLoading && (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 size={20} className="animate-spin text-primary-500 mr-2" />
                    <span className="text-sm text-text-secondary">Loading test results...</span>
                  </div>
                )}

                {/* Skipped Scanner — Why it was skipped + what it would check */}
                {!isLoading && result.status === 'skipped' && (
                  <div className="p-5">
                    <div className="flex items-center gap-3 mb-4 pb-3 border-b border-border-primary">
                      <div className="p-2 rounded-lg bg-text-tertiary/10">
                        <AlertCircle size={20} className="text-text-tertiary" />
                      </div>
                      <div>
                        <p className="text-text-primary font-medium">Scanner skipped — no applicable targets found</p>
                        <p className="text-sm text-text-tertiary">
                          {result.evidence?.displayName || result.scanner} did not find files or configurations matching its scan criteria
                        </p>
                      </div>
                    </div>

                    {result.evidence?.scanScope && (
                      <div className="mb-3">
                        <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-1">What This Scanner Checks</h5>
                        <p className="text-sm text-text-secondary">{result.evidence.scanScope}</p>
                      </div>
                    )}

                    {result.evidence?.checksPerformed && result.evidence.checksPerformed.length > 0 && (
                      <div className="mb-3">
                        <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-2">Checks That Would Be Performed</h5>
                        <ul className="space-y-1">
                          {result.evidence.checksPerformed.map((check, i) => (
                            <li key={i} className="flex items-start gap-2 text-sm text-text-tertiary">
                              <span className="mt-0.5 flex-shrink-0">-</span>
                              {check}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {result.evidence?.methodology && (
                      <div className="mt-3 pt-3 border-t border-border-primary">
                        <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-1">Methodology</h5>
                        <p className="text-sm text-text-tertiary leading-relaxed">{result.evidence.methodology}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Pass Scanner — Audit Evidence Detail */}
                {!isLoading && result.status !== 'skipped' && result.findingsCount === 0 && (
                  <div className="p-5">
                    {/* Pass Header */}
                    <div className="flex items-center gap-3 mb-4 pb-3 border-b border-border-primary">
                      <div className="p-2 rounded-lg bg-success/10">
                        <CheckCircle size={20} className="text-success" />
                      </div>
                      <div>
                        <p className="text-text-primary font-medium">All checks passed — no vulnerabilities detected</p>
                        <p className="text-sm text-text-tertiary">
                          {result.evidence?.displayName || result.scanner} completed in {formatDuration(result.duration)}
                        </p>
                      </div>
                    </div>

                    {/* Audit Evidence Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Checks Performed */}
                      {result.evidence?.checksPerformed && result.evidence.checksPerformed.length > 0 && (
                        <div>
                          <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-2">Checks Performed</h5>
                          <ul className="space-y-1">
                            {result.evidence.checksPerformed.map((check, i) => (
                              <li key={i} className="flex items-start gap-2 text-sm text-text-secondary">
                                <Check size={14} className="text-success mt-0.5 flex-shrink-0" />
                                {check}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Scan Details */}
                      <div className="space-y-3">
                        {/* Scan Scope */}
                        {result.evidence?.scanScope && (
                          <div>
                            <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-1">Scan Scope</h5>
                            <p className="text-sm text-text-secondary">{result.evidence.scanScope}</p>
                          </div>
                        )}

                        {/* Metrics */}
                        <div className="flex flex-wrap gap-4">
                          {(result.evidence?.filesAnalyzed ?? 0) > 0 && (
                            <div>
                              <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-1">Files Analyzed</h5>
                              <p className="text-lg font-semibold text-text-primary">{result.evidence!.filesAnalyzed}</p>
                            </div>
                          )}
                          {result.evidence?.rulesEvaluated && (
                            <div>
                              <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-1">Rules Checked</h5>
                              <p className="text-lg font-semibold text-text-primary">{result.evidence.rulesEvaluated}</p>
                            </div>
                          )}
                        </div>

                        {/* Detection Method */}
                        {result.evidence?.detectionMethod && (
                          <div>
                            <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-1">Detection Method</h5>
                            <p className="text-sm text-text-secondary">{result.evidence.detectionMethod}</p>
                          </div>
                        )}

                        {/* Configuration */}
                        {result.evidence?.configuration && (
                          <div>
                            <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-1">Configuration</h5>
                            <p className="text-sm text-text-secondary font-mono">{result.evidence.configuration}</p>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Methodology & Standards */}
                    {(result.evidence?.methodology || result.evidence?.standards) && (
                      <div className="mt-4 pt-3 border-t border-border-primary grid grid-cols-1 md:grid-cols-2 gap-4">
                        {result.evidence?.methodology && (
                          <div>
                            <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-1">Methodology</h5>
                            <p className="text-sm text-text-tertiary leading-relaxed">{result.evidence.methodology}</p>
                          </div>
                        )}
                        {result.evidence?.standards && result.evidence.standards.length > 0 && (
                          <div>
                            <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-1">Standards & Frameworks</h5>
                            <div className="flex flex-wrap gap-1.5">
                              {result.evidence.standards.map((standard, i) => (
                                <span key={i} className="px-2 py-0.5 text-xs rounded bg-primary-500/10 text-primary-400 border border-primary-500/20">
                                  {standard}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Targets Analyzed */}
                    {result.evidence?.targetsAnalyzed && result.evidence.targetsAnalyzed.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-border-primary">
                        <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-2">Targets Analyzed</h5>
                        <div className="max-h-32 overflow-y-auto">
                          <div className="flex flex-wrap gap-1.5">
                            {result.evidence.targetsAnalyzed.map((target, i) => (
                              <span key={i} className="px-2 py-0.5 text-xs rounded bg-bg-secondary text-text-secondary font-mono">
                                {target}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Fail Scanner — Test Results Table */}
                {!isLoading && result.findingsCount > 0 && cachedFindings && (
                  <div className="p-4">
                    {/* Status Summary */}
                    <div className="flex items-center justify-between mb-4">
                      <div className="text-sm font-medium text-text-primary">
                        Tests Run ({result.findingsCount} checks)
                      </div>
                      {statusCounts && (
                        <div className="flex items-center gap-3 text-xs">
                          {statusCounts.open && statusCounts.open > 0 && (
                            <span className="text-error">{statusCounts.open} open</span>
                          )}
                          {statusCounts.fixed && statusCounts.fixed > 0 && (
                            <span className="text-success">{statusCounts.fixed} fixed</span>
                          )}
                          {statusCounts.false_positive && statusCounts.false_positive > 0 && (
                            <span className="text-text-tertiary">{statusCounts.false_positive} false positive</span>
                          )}
                          {statusCounts.ignored && statusCounts.ignored > 0 && (
                            <span className="text-text-tertiary">{statusCounts.ignored} ignored</span>
                          )}
                          {statusCounts.accepted && statusCounts.accepted > 0 && (
                            <span className="text-info">{statusCounts.accepted} accepted</span>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Table Header */}
                    <div className="grid grid-cols-[90px_1fr_80px_minmax(0,240px)_60px] gap-2 px-3 py-2 text-xs font-medium text-text-tertiary uppercase tracking-wider border-b border-border-primary">
                      <div>Status</div>
                      <div>Check</div>
                      <div>Severity</div>
                      <div>File</div>
                      <div></div>
                    </div>

                    {/* Test Result Rows */}
                    <div className="max-h-[500px] overflow-y-auto divide-y divide-border-primary">
                      {cachedFindings.map(finding => {
                        const isDetailOpen = expandedFinding === finding.id;
                        return (
                          <div key={finding.id}>
                            <div
                              className="grid grid-cols-[90px_1fr_80px_minmax(0,240px)_60px] gap-2 px-3 py-2.5 items-center hover:bg-bg-hover/50 cursor-pointer transition-colors"
                              onClick={() => setExpandedFinding(isDetailOpen ? null : finding.id)}
                            >
                              <div>
                                <FindingStatusBadge status={finding.status} />
                              </div>
                              <div className="min-w-0">
                                <p className="text-sm text-text-primary truncate">{finding.title}</p>
                              </div>
                              <div>
                                <SeverityBadge severity={finding.severity} size="sm" />
                              </div>
                              <div className="min-w-0">
                                <p className="text-xs text-text-tertiary font-mono truncate">
                                  {finding.filePath}{finding.line > 0 ? `:${finding.line}` : ''}
                                </p>
                              </div>
                              <div className="flex items-center justify-end gap-1">
                                <ChevronRight size={14} className={cn(
                                  'text-text-tertiary transition-transform',
                                  isDetailOpen && 'rotate-90'
                                )} />
                              </div>
                            </div>

                            {/* Expandable Detail Row */}
                            {isDetailOpen && (
                              <div className="px-3 pb-3 pt-1 bg-bg-secondary/50 border-l-2 border-primary-500/30 ml-3 mr-3 mb-1 rounded-b space-y-3">
                                {finding.description && (
                                  <p className="text-sm text-text-secondary">{finding.description}</p>
                                )}

                                {/* Code Snippet */}
                                {finding.code && (
                                  <div className="bg-bg-secondary rounded-lg p-3 font-mono text-xs overflow-x-auto">
                                    <pre className="text-text-secondary whitespace-pre-wrap">
                                      {finding.line > 0 && <span className="text-text-tertiary mr-3 select-none">{finding.line}</span>}
                                      <span className="text-error">{finding.code}</span>
                                    </pre>
                                  </div>
                                )}

                                {/* Fix Description */}
                                {finding.fixDescription && (
                                  <div className="bg-success/5 border border-success/20 rounded-lg p-3">
                                    <div className="flex items-center gap-1.5 text-xs font-medium text-success mb-1">
                                      <CheckCircle size={12} />
                                      Recommended Fix
                                    </div>
                                    <p className="text-sm text-text-secondary">{finding.fixDescription}</p>
                                  </div>
                                )}

                                {/* Metadata Tags */}
                                <div className="flex flex-wrap items-center gap-3 text-xs text-text-tertiary">
                                  {finding.cwe && (
                                    <span className="px-2 py-0.5 rounded bg-bg-tertiary">{finding.cwe}</span>
                                  )}
                                  {finding.owaspCategory && (
                                    <span className="px-2 py-0.5 rounded bg-bg-tertiary">{finding.owaspCategory}</span>
                                  )}
                                  {finding.ruleId && (
                                    <span className="px-2 py-0.5 rounded bg-bg-tertiary font-mono">{finding.ruleId}</span>
                                  )}
                                  <span>Scanner: {finding.scanner}</span>
                                  {finding.filePath && (
                                    <span className="font-mono">{finding.filePath}{finding.line > 0 ? `:${finding.line}` : ''}</span>
                                  )}
                                </div>

                                <div>
                                  <Link
                                    href={`/findings/${finding.id}`}
                                    className="text-xs text-primary-400 hover:text-primary-300 flex items-center gap-1"
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    View full details
                                    <ExternalLink size={12} />
                                  </Link>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>

                    {/* Pagination note if findings exceed API limit */}
                    {result.findingsCount > cachedFindings.length && (
                      <div className="px-3 py-2 text-xs text-text-tertiary border-t border-border-primary">
                        Showing {cachedFindings.length} of {result.findingsCount} checks.{' '}
                        <Link
                          href={`/findings?scanId=${scan.id}&scanner=${result.scanner}`}
                          className="text-primary-400 hover:text-primary-300"
                        >
                          View all
                        </Link>
                      </div>
                    )}

                    {/* Audit Evidence Footer for Fail Scanners */}
                    {result.evidence && (
                      <div className="px-4 py-3 border-t border-border-primary bg-bg-secondary/30">
                        <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs text-text-tertiary">
                          {(result.evidence.filesAnalyzed ?? 0) > 0 && (
                            <span>{result.evidence.filesAnalyzed} files analyzed</span>
                          )}
                          {result.evidence.rulesEvaluated && (
                            <span>{result.evidence.rulesEvaluated} rules checked</span>
                          )}
                          {result.evidence.configuration && (
                            <span>Config: {result.evidence.configuration}</span>
                          )}
                          {result.evidence.standards && result.evidence.standards.length > 0 && (
                            <span>Standards: {result.evidence.standards.join(', ')}</span>
                          )}
                        </div>
                        {result.evidence.methodology && (
                          <p className="text-xs text-text-tertiary mt-1.5 leading-relaxed">{result.evidence.methodology}</p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function FilesTab({ scan }: { scan: ExtendedScan }) {
  const hasFilesWithFindings = scan.filesScanned && scan.filesScanned.length > 0;
  const hasInventory = scan.fileInventory && scan.fileInventory.totalFiles > 0;

  if (!hasFilesWithFindings && !hasInventory) {
    return (
      <EmptyState
        icon={FileCode2}
        title="No file data available"
        description="File analysis details will be available after the next scan."
      />
    );
  }

  const totalOpen = scan.filesScanned?.reduce((sum, f) => sum + (f.openFindings || 0), 0) || 0;
  const totalResolved = scan.filesScanned?.reduce((sum, f) => sum + (f.resolvedFindings || 0), 0) || 0;
  const totalFound = scan.filesScanned?.reduce((sum, f) => sum + (f.totalFindings || f.findingsCount || 0), 0) || 0;

  // Calculate total files analyzed from inventory or scanner evidence
  const totalFromInventory = scan.fileInventory?.totalFiles || 0;
  const totalFromScanners = scan.scannerResults
    ? Math.max(...scan.scannerResults.map(r => r.evidence?.filesAnalyzed || r.filesScanned || 0), 0)
    : 0;
  const totalFilesAnalyzed = totalFromInventory || totalFromScanners || (scan.filesScanned?.length || 0);

  return (
    <div className="space-y-6">
      {/* Codebase Coverage Summary */}
      <div className="p-4 rounded-lg bg-bg-tertiary border border-border-primary">
        <h3 className="text-sm font-semibold text-text-primary mb-3">Codebase Coverage</h3>
        <div className="flex items-center gap-6">
          <span className="text-2xl font-bold text-primary-400">{totalFilesAnalyzed.toLocaleString()}</span>
          <span className="text-sm text-text-secondary">total files analyzed</span>
          <span className="text-sm text-text-tertiary">|</span>
          <span className="text-sm text-text-secondary">{scan.scannerResults?.filter(r => r.status === 'success').length || 0} scanners</span>
        </div>

        {/* Language breakdown */}
        {scan.fileInventory && scan.fileInventory.breakdown.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-2">
            {scan.fileInventory.breakdown.map(item => (
              <span key={item} className="px-2 py-1 text-xs rounded bg-bg-secondary text-text-secondary border border-border-primary">
                {item}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Files with Findings */}
      {hasFilesWithFindings && (
        <div>
          <h3 className="text-sm font-semibold text-text-primary mb-3">
            Files with Findings ({scan.filesScanned!.length})
          </h3>
          <div className="flex items-center gap-6 p-3 rounded-lg bg-bg-tertiary border border-border-primary mb-3">
            <span className="text-sm text-text-primary">
              {scan.filesScanned!.length} files with findings
            </span>
        <div className="flex items-center gap-4 text-sm">
          <span className="text-text-secondary">{totalFound} findings detected</span>
          {totalOpen > 0 && (
            <span className="text-error">{totalOpen} open</span>
          )}
          <span className="text-success">{totalResolved} resolved</span>
        </div>
      </div>

      <div className="max-h-96 overflow-y-auto">
        <table className="w-full">
          <thead className="sticky top-0 bg-bg-secondary">
            <tr className="text-left text-xs text-text-tertiary uppercase tracking-wider">
              <th className="pb-3 pr-4">File Path</th>
              <th className="pb-3 pr-4 text-right">Detected</th>
              <th className="pb-3 pr-4 text-right">Open</th>
              <th className="pb-3 pr-4 text-right">Resolved</th>
              <th className="pb-3 pr-4 text-center">Status</th>
              <th className="pb-3">Scanners</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-primary">
            {scan.filesScanned!.map(file => {
              const total = file.totalFindings || file.findingsCount || 0;
              const open = file.openFindings || 0;
              const resolved = file.resolvedFindings || 0;
              const allClear = total > 0 && open === 0;

              return (
                <tr key={file.path} className="hover:bg-bg-hover/50">
                  <td className="py-3 pr-4">
                    <span className="font-mono text-sm text-text-primary">{file.path}</span>
                  </td>
                  <td className="py-3 pr-4 text-right">
                    <span className="text-text-secondary text-sm">{total}</span>
                  </td>
                  <td className="py-3 pr-4 text-right">
                    {open > 0 ? (
                      <span className="text-error font-medium text-sm">{open}</span>
                    ) : (
                      <span className="text-text-tertiary text-sm">0</span>
                    )}
                  </td>
                  <td className="py-3 pr-4 text-right">
                    {resolved > 0 ? (
                      <span className="text-success text-sm">{resolved}</span>
                    ) : (
                      <span className="text-text-tertiary text-sm">0</span>
                    )}
                  </td>
                  <td className="py-3 pr-4 text-center">
                    {allClear ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-full bg-success/10 text-success border border-success/20">
                        <CheckCircle size={12} /> Clear
                      </span>
                    ) : open > 0 ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-full bg-error/10 text-error border border-error/20">
                        <AlertTriangle size={12} /> Open
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-full bg-success/10 text-success border border-success/20">
                        <CheckCircle size={12} /> Clean
                      </span>
                    )}
                  </td>
                  <td className="py-3">
                    <div className="flex flex-wrap gap-1">
                      {file.scanners.map(s => (
                        <span key={s} className="px-2 py-0.5 text-xs rounded bg-bg-tertiary text-text-secondary">
                          {s}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
        </div>
      )}
    </div>
  );
}

function AttestationTab({ scan }: { scan: ExtendedScan }) {
  if (scan.attestation) {
    return (
      <div className="space-y-4">
        <div className="p-4 rounded-lg bg-success/10 border border-success/20">
          <div className="flex items-center gap-3">
            <CheckCircle className="text-success" size={24} />
            <div>
              <h4 className="font-medium text-success">Attestation Created</h4>
              <p className="text-sm text-text-secondary">
                Created on {formatDate(scan.attestation.createdAt)}
              </p>
            </div>
          </div>
        </div>

        <Link
          href={`/attestations/${scan.attestation.id}`}
          className="btn-primary inline-flex"
        >
          View Attestation
        </Link>
      </div>
    );
  }

  return (
    <div className="text-center py-12">
      <Shield size={48} className="mx-auto text-text-tertiary mb-4" />
      <h3 className="text-lg font-semibold text-text-primary mb-2">No Attestation Yet</h3>
      <p className="text-text-secondary mb-6 max-w-md mx-auto">
        Create an attestation to cryptographically sign and share your scan results with stakeholders.
      </p>
      <Link
        href={`/attestations/new?scanId=${scan.id}`}
        className="btn-primary inline-flex"
      >
        <Shield size={16} />
        Create Attestation
      </Link>
    </div>
  );
}
