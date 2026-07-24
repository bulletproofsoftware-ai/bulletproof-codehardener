'use client';

import { useState, useRef, useCallback, useMemo } from 'react';
import { useParams } from 'next/navigation';
import DOMPurify from 'dompurify';
import Link from 'next/link';
import {
  ArrowLeft,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  AlertTriangle,
  FileCode,
  Lightbulb,
  Info,
  X,
  Shield,
  Clock,
  FolderGit2,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import { cn, formatDateTime } from '@/lib/utils';
import { SeverityBadge } from '@/components/SeverityBadge';
import { StatusBadge } from '@/components/StatusBadge';
import { ExploitabilityBadge } from '@/components/ExploitabilityBadge';
import { useFinding } from '@/hooks/useApi';
import { findingsApi } from '@/lib/api';
import type { Finding, FindingStatus, Exploitability, DataflowMatch } from '@/types';

// Extended finding type for detail view
interface ExtendedFinding extends Finding {
  plainLanguage?: string;
  impact?: string;
  fixExplanation?: string;
  fixSuggestion?: string;
  cvssScore?: number;
  cvssVector?: string;
  packageName?: string;
  packageVersion?: string;
  packageType?: string;
  references?: string[];
  ruleId?: string;
  owaspCategory?: string;
  exploitability?: Exploitability;
  reachable?: boolean;
  dataflowMatch?: DataflowMatch;
  llmVerified?: boolean;
}

export default function FindingDetailPage() {
  const params = useParams();
  const findingId = params.id as string;

  const { data: findingData, isLoading, error: findingError, refetch: refetchFinding } = useFinding(findingId);
  const finding = (findingData as ExtendedFinding) ?? null;
  const error = findingError?.message ?? null;

  const [copied, setCopied] = useState(false);
  const [technicalExpanded, setTechnicalExpanded] = useState(true);
  const [dismissModalOpen, setDismissModalOpen] = useState(false);
  const technicalRef = useRef<HTMLDivElement>(null);

  const toggleTechnical = useCallback(() => {
    setTechnicalExpanded(prev => {
      if (!prev) {
        // Scroll into view after React renders the expanded content
        setTimeout(() => technicalRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50);
      }
      return !prev;
    });
  }, []);

  const copyToClipboard = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-error mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load finding</h2>
        <p className="text-text-secondary mb-4">{error || 'Finding not found'}</p>
        <button
          onClick={() => refetchFinding()}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  // Sanitize scanner-sourced text to strip any embedded HTML/script content.
  // DOMPurify requires a browser environment; guard for SSR hydration.
  const sanitize = useMemo(() => {
    if (typeof window === 'undefined') return (s: string) => s;
    return (s: string) => DOMPurify.sanitize(s, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
  }, []);

  // Build comprehensive, agent-actionable explanation from all available data
  const descriptionText = sanitize(finding.descriptionSimple || finding.description || '');
  const cveId = finding.ruleId?.startsWith('CVE-') ? finding.ruleId : finding.title?.match(/^(CVE-[\d-]+)/)?.[1];

  // "What is this?" — full context an agent needs to understand the vulnerability
  const plainLanguageParts: string[] = [];
  if (descriptionText) plainLanguageParts.push(descriptionText);
  if (finding.packageName && finding.packageVersion) {
    plainLanguageParts.push(`Affected package: ${finding.packageName}@${finding.packageVersion} (${finding.packageType || 'unknown'} ecosystem).`);
  }
  if (finding.filePath) {
    plainLanguageParts.push(`Found in: ${finding.filePath}${finding.lineNumber ? `:${finding.lineNumber}` : ''}`);
  }
  if (finding.cvssScore != null) {
    const cvssLabel = finding.cvssScore >= 9.0 ? 'Critical' : finding.cvssScore >= 7.0 ? 'High' : finding.cvssScore >= 4.0 ? 'Medium' : 'Low';
    plainLanguageParts.push(`CVSS ${finding.cvssScore}/10 (${cvssLabel}).${finding.cvssVector ? ` Vector: ${finding.cvssVector}` : ''}`);
  }
  if (cveId) {
    plainLanguageParts.push(`Reference: ${cveId}`);
  }
  if (finding.cwe) {
    plainLanguageParts.push(`Weakness: ${finding.cwe}`);
  }
  const plainLanguage = plainLanguageParts.length > 0
    ? plainLanguageParts.join(' ')
    : 'No description available for this finding.';

  // "What this means:" — specific impact and remediation context for agents
  const impactParts: string[] = [];
  if (finding.cvssScore != null && finding.cvssScore >= 9.0) {
    impactParts.push(`This vulnerability has a CVSS score of ${finding.cvssScore}/10, indicating critical exploitability. It may allow remote code execution, privilege escalation, or complete system compromise without authentication.`);
  } else if (finding.cvssScore != null && finding.cvssScore >= 7.0) {
    impactParts.push(`This vulnerability has a CVSS score of ${finding.cvssScore}/10, indicating high exploitability. It could lead to significant data exposure or service disruption.`);
  } else if (finding.severity === 'critical') {
    impactParts.push('This is a critical severity finding that requires immediate attention. It could allow unauthorized access, data exfiltration, or system compromise.');
  } else if (finding.severity === 'high') {
    impactParts.push('This is a high severity finding that should be prioritized. Exploitation could cause significant damage or data leakage.');
  } else if (finding.severity === 'medium') {
    impactParts.push('This is a medium severity finding. It may be exploitable under certain conditions and should be addressed during regular maintenance.');
  } else if (finding.severity === 'low') {
    impactParts.push('This is a low severity finding representing a best-practice recommendation.');
  } else {
    impactParts.push('This is an informational finding for awareness.');
  }
  if (finding.fixAvailable && finding.fixDescription) {
    impactParts.push(`Remediation: ${sanitize(finding.fixDescription)}`);
  } else if (finding.packageName && finding.packageVersion) {
    impactParts.push(`Check for a patched version of ${finding.packageName} and update the dependency.`);
  }
  const impact = finding.impact || impactParts.join(' ');

  const fixExplanation = sanitize(finding.fixExplanation || finding.fixDescription || (finding.fixAvailable
    ? 'A fix is available. Apply the suggested remediation below.'
    : 'Review the finding details and apply appropriate security measures.'));
  const references = finding.references || [];
  const ruleId = finding.ruleId || finding.scanner;

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Back Navigation */}
      <Link
        href="/findings"
        className="inline-flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors"
      >
        <ArrowLeft size={16} />
        Back to Findings
      </Link>

      {/* Finding Header */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-3">
              <SeverityBadge severity={finding.severity} />
              <StatusBadge status={finding.status} />
              {finding.exploitability && (
                <ExploitabilityBadge exploitability={finding.exploitability} />
              )}
            </div>
            <h1 className="text-2xl font-bold text-text-primary mb-4">{finding.title}</h1>
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-text-secondary">
              <Link
                href={`/projects/${finding.projectId}`}
                className="flex items-center gap-2 hover:text-primary-400 transition-colors"
              >
                <FolderGit2 size={14} />
                {finding.projectName || 'Project'}
              </Link>
              <Link
                href={`/scans/${finding.scanId}`}
                className="flex items-center gap-2 hover:text-primary-400 transition-colors"
              >
                <Clock size={14} />
                Scan: {finding.createdAt ? formatDateTime(finding.createdAt) : 'Unknown'}
              </Link>
              <span className="flex items-center gap-2">
                <Shield size={14} />
                {finding.scanner}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setDismissModalOpen(true)}
              className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors"
            >
              Dismiss
            </button>
            <button className="px-4 py-2 text-sm bg-success/10 text-success border border-success/20 rounded-lg hover:bg-success/20 transition-colors">
              Mark as Fixed
            </button>
          </div>
        </div>
      </div>

      {/* Plain Language Explanation */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-lg bg-warning/10 flex items-center justify-center flex-shrink-0">
            <AlertTriangle size={20} className="text-warning" />
          </div>
          <div className="flex-1">
            <h2 className="text-lg font-semibold text-text-primary mb-2">What is this?</h2>
            <p className="text-text-secondary mb-4">{plainLanguage}</p>
            <div className="bg-bg-tertiary rounded-lg p-4">
              <h3 className="text-sm font-medium text-text-primary mb-2">What this means:</h3>
              <p className="text-sm text-text-secondary">{impact}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Code Context */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary-500/10 flex items-center justify-center">
              <FileCode size={20} className="text-primary-400" />
            </div>
            <div>
              <h2 className="font-semibold text-text-primary">Code Context</h2>
              <p className="text-sm text-text-secondary font-mono">
                {finding.filePath}:{finding.lineNumber}
              </p>
            </div>
          </div>
          <button
            onClick={() => copyToClipboard(finding.codeSnippet || '')}
            className="flex items-center gap-2 px-3 py-1.5 text-sm text-text-secondary hover:text-text-primary hover:bg-bg-tertiary rounded-lg transition-colors"
          >
            {copied ? <Check size={14} className="text-success" /> : <Copy size={14} />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
        <div className="p-4 bg-[#0d1117] overflow-x-auto">
          <pre className="text-sm font-mono">
            <code className="text-gray-300">
              {(finding.codeSnippet || '').split('\n').map((line, i) => (
                <div
                  key={i}
                  className={cn(
                    'px-4 py-0.5',
                    line.includes('VULNERABLE') && 'bg-error/20 border-l-2 border-error'
                  )}
                >
                  <span className="text-gray-500 select-none mr-4">{45 + i}</span>
                  {line.includes('VULNERABLE') ? (
                    <span className="text-error">{line.replace('  // VULNERABLE', '')}</span>
                  ) : (
                    line
                  )}
                </div>
              ))}
            </code>
          </pre>
        </div>
      </div>

      {/* Fix Suggestion */}
      {finding.fixAvailable && (
        <div className="bg-bg-secondary border border-success/20 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary bg-success/5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-success/10 flex items-center justify-center">
                <Lightbulb size={20} className="text-success" />
              </div>
              <div>
                <h2 className="font-semibold text-text-primary">Fix Suggestion</h2>
                <p className="text-sm text-text-secondary">{fixExplanation}</p>
              </div>
            </div>
          </div>
          <div className="p-4 bg-[#0d1117] overflow-x-auto">
            <pre className="text-sm font-mono">
              <code className="text-gray-300">
                {(finding.fixSuggestion || finding.fixDescription || '').split('\n').map((line: string, i: number) => (
                  <div key={i} className="px-4 py-0.5">
                    <span className="text-gray-500 select-none mr-4">{i + 1}</span>
                    {line}
                  </div>
                ))}
              </code>
            </pre>
          </div>
          <div className="flex items-center gap-3 px-6 py-4 border-t border-border-primary bg-success/5">
            <button
              disabled
              title="Coming soon — requires scan artifact storage"
              className="flex items-center gap-2 px-4 py-2 text-sm bg-success text-bg-primary font-medium rounded-lg transition-colors opacity-50 cursor-not-allowed"
            >
              <Copy size={14} />
              Copy Fix
            </button>
            <button
              disabled
              title="Coming soon — requires scan artifact storage"
              className="px-4 py-2 text-sm border border-border-primary rounded-lg transition-colors opacity-50 cursor-not-allowed"
            >
              Download Patch
            </button>
          </div>
        </div>
      )}

      {/* Analysis Context (enrichment data) */}
      {(finding.exploitability || finding.reachable !== undefined || finding.dataflowMatch || finding.llmVerified !== undefined) && (
        <AnalysisContextSection finding={finding} />
      )}

      {/* Technical Details */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl overflow-hidden">
        <button
          onClick={toggleTechnical}
          className="w-full flex items-center justify-between px-6 py-4 hover:bg-bg-tertiary/50 transition-colors"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-info/10 flex items-center justify-center">
              <Info size={20} className="text-info" />
            </div>
            <h2 className="font-semibold text-text-primary">Technical Details</h2>
          </div>
          {technicalExpanded ? (
            <ChevronUp size={20} className="text-text-tertiary" />
          ) : (
            <ChevronDown size={20} className="text-text-tertiary" />
          )}
        </button>
        {technicalExpanded && (
          <div ref={technicalRef} className="px-6 pb-6 pt-2 border-t border-border-primary">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              {finding.cwe && (
                <div className="bg-bg-tertiary rounded-lg p-4">
                  <p className="text-xs text-text-tertiary uppercase tracking-wider mb-1">CWE</p>
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary-400 hover:underline flex items-center gap-1"
                  >
                    {finding.cwe}
                    <ExternalLink size={12} />
                  </a>
                </div>
              )}
              {finding.cvssScore != null && (
                <div className="bg-bg-tertiary rounded-lg p-4">
                  <p className="text-xs text-text-tertiary uppercase tracking-wider mb-1">CVSS Score</p>
                  <p className={cn('font-semibold', finding.cvssScore >= 9 ? 'text-error' : finding.cvssScore >= 7 ? 'text-orange-400' : finding.cvssScore >= 4 ? 'text-warning' : 'text-text-primary')}>
                    {finding.cvssScore} / 10
                  </p>
                  {finding.cvssVector && (
                    <p className="text-xs text-text-tertiary font-mono mt-1 break-all">{finding.cvssVector}</p>
                  )}
                </div>
              )}
              <div className="bg-bg-tertiary rounded-lg p-4">
                <p className="text-xs text-text-tertiary uppercase tracking-wider mb-1">Scanner</p>
                <p className="text-text-primary">{finding.scanner}</p>
              </div>
              {ruleId && (
                <div className="bg-bg-tertiary rounded-lg p-4">
                  <p className="text-xs text-text-tertiary uppercase tracking-wider mb-1">Rule ID</p>
                  <p className="text-text-primary font-mono text-sm">{ruleId}</p>
                </div>
              )}
              {finding.owaspCategory && (
                <div className="bg-bg-tertiary rounded-lg p-4">
                  <p className="text-xs text-text-tertiary uppercase tracking-wider mb-1">OWASP</p>
                  <p className="text-text-primary text-sm">{finding.owaspCategory}</p>
                </div>
              )}
              {finding.packageName && (
                <div className="bg-bg-tertiary rounded-lg p-4">
                  <p className="text-xs text-text-tertiary uppercase tracking-wider mb-1">Package</p>
                  <p className="text-text-primary font-mono text-sm">{finding.packageName}@{finding.packageVersion}</p>
                  {finding.packageType && (
                    <p className="text-xs text-text-tertiary mt-1">{finding.packageType}</p>
                  )}
                </div>
              )}
            </div>

            {references.length > 0 && (
              <>
                <h3 className="text-sm font-medium text-text-primary mb-3">References</h3>
                <ul className="space-y-2">
                  {references.map((ref, i) => (
                    <li key={i}>
                      <a
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary-400 hover:underline flex items-center gap-2"
                      >
                        <ExternalLink size={12} />
                        {ref}
                      </a>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
      </div>

      {/* Dismiss Modal */}
      {dismissModalOpen && (
        <DismissModal
          findingId={finding.id}
          onClose={() => setDismissModalOpen(false)}
          onDismiss={async (reason, comment) => {
            try {
              // Map reason to finding status
              const statusMap: Record<string, FindingStatus> = {
                false_positive: 'false_positive',
                accepted_risk: 'deferred',
                wont_fix: 'ignored',
                duplicate: 'ignored',
              };
              const status = statusMap[reason] || 'ignored';
              await findingsApi.updateStatus(finding.id, status, reason, comment);
              await refetchFinding();
              setDismissModalOpen(false);
            } catch (err) {
              console.error('Failed to dismiss finding:', err);
            }
          }}
        />
      )}
    </div>
  );
}

function AnalysisContextSection({ finding }: { finding: ExtendedFinding }) {
  const enrichment = (finding.metadata as Record<string, unknown>)?.enrichment as Record<string, unknown> | undefined;

  return (
    <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
      <div className="flex items-start gap-4">
        <div className="w-10 h-10 rounded-lg bg-primary-500/10 flex items-center justify-center flex-shrink-0">
          <Shield size={20} className="text-primary-400" />
        </div>
        <div className="flex-1">
          <h2 className="text-lg font-semibold text-text-primary mb-4">Analysis Context</h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Exploitability */}
            {finding.exploitability && (
              <div className="bg-bg-tertiary rounded-lg p-4">
                <p className="text-xs text-text-tertiary uppercase tracking-wider mb-2">Exploitability</p>
                <div className="flex items-center gap-2">
                  <ExploitabilityBadge exploitability={finding.exploitability} />
                  <span className="text-sm text-text-secondary">
                    {finding.exploitability === 'confirmed' && 'Code analysis confirms an exploitable path exists'}
                    {finding.exploitability === 'likely' && 'Conditions suggest this is likely exploitable'}
                    {finding.exploitability === 'theoretical' && 'Vulnerability exists but exploitation is uncertain'}
                    {finding.exploitability === 'unlikely' && 'Analysis suggests this is not practically exploitable'}
                  </span>
                </div>
              </div>
            )}

            {/* Reachability */}
            {finding.reachable !== undefined && (
              <div className="bg-bg-tertiary rounded-lg p-4">
                <p className="text-xs text-text-tertiary uppercase tracking-wider mb-2">Reachability</p>
                <div className="flex items-center gap-2">
                  <span className={cn(
                    'inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full border',
                    finding.reachable
                      ? 'bg-orange-500/10 text-orange-400 border-orange-500/20'
                      : 'bg-green-500/10 text-green-400 border-green-500/20'
                  )}>
                    {finding.reachable ? 'Reachable' : 'Unreachable'}
                  </span>
                  {typeof enrichment?.reachableFrom === 'string' && (
                    <span className="text-sm text-text-secondary">
                      via {enrichment.reachableFrom}
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* Dataflow Analysis */}
            {finding.dataflowMatch && (
              <div className="bg-bg-tertiary rounded-lg p-4">
                <p className="text-xs text-text-tertiary uppercase tracking-wider mb-2">Dataflow Analysis</p>
                <div>
                  <span className={cn(
                    'inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full border',
                    finding.dataflowMatch === 'confirmed'
                      ? 'bg-red-500/10 text-red-400 border-red-500/20'
                      : finding.dataflowMatch === 'sanitized'
                        ? 'bg-green-500/10 text-green-400 border-green-500/20'
                        : 'bg-gray-500/10 text-gray-400 border-gray-500/20'
                  )}>
                    {finding.dataflowMatch === 'confirmed' && 'Unsanitized Flow'}
                    {finding.dataflowMatch === 'sanitized' && 'Sanitized'}
                    {finding.dataflowMatch === 'no_match' && 'No Dataflow Match'}
                  </span>
                  {typeof enrichment?.sanitizationEvidence === 'string' && (
                    <p className="text-sm text-text-secondary mt-2">
                      {enrichment.sanitizationEvidence}
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* LLM Verification */}
            {finding.llmVerified !== undefined && (
              <div className="bg-bg-tertiary rounded-lg p-4">
                <p className="text-xs text-text-tertiary uppercase tracking-wider mb-2">LLM Verification</p>
                <div className="flex items-center gap-2">
                  <span className={cn(
                    'inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full border',
                    finding.llmVerified
                      ? 'bg-red-500/10 text-red-400 border-red-500/20'
                      : 'bg-green-500/10 text-green-400 border-green-500/20'
                  )}>
                    {finding.llmVerified ? 'Exploit Verified' : 'Not Exploitable'}
                  </span>
                </div>
                {(() => {
                  const llmData = (finding.metadata as Record<string, unknown>)?.llmVerification as Record<string, unknown> | undefined;
                  if (!llmData) return null;
                  return (
                    <div className="mt-2">
                      <p className="text-sm text-text-secondary">{llmData.reasoning as string}</p>
                      {llmData.confidence != null && (
                        <p className="text-xs text-text-tertiary mt-1">
                          Confidence: {Math.round((llmData.confidence as number) * 100)}%
                        </p>
                      )}
                    </div>
                  );
                })()}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function DismissModal({
  findingId: _findingId,
  onClose,
  onDismiss,
}: {
  findingId: string;
  onClose: () => void;
  onDismiss: (reason: string, comment: string) => void;
}) {
  const [reason, setReason] = useState('');
  const [comment, setComment] = useState('');

  const reasons = [
    { value: 'false_positive', label: 'False Positive', description: 'This is not actually a vulnerability' },
    { value: 'wont_fix', label: "Won't Fix", description: 'Known issue that will not be addressed' },
    { value: 'deferred', label: 'Deferred', description: 'Acknowledged and deferred for later' },
    { value: 'duplicate', label: 'Duplicate', description: 'This finding is a duplicate of another' },
  ];

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-lg">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary">
          <h2 className="text-lg font-semibold text-text-primary">Dismiss Finding</h2>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-bg-tertiary transition-colors"
          >
            <X size={20} className="text-text-tertiary" />
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">
              Reason for dismissal
            </label>
            <div className="space-y-2">
              {reasons.map(r => (
                <label
                  key={r.value}
                  className={cn(
                    'flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors',
                    reason === r.value
                      ? 'border-primary-500 bg-primary-500/5'
                      : 'border-border-primary hover:border-border-secondary'
                  )}
                >
                  <input
                    type="radio"
                    name="reason"
                    value={r.value}
                    checked={reason === r.value}
                    onChange={(e) => setReason(e.target.value)}
                    className="mt-0.5"
                  />
                  <div>
                    <p className="font-medium text-text-primary">{r.label}</p>
                    <p className="text-sm text-text-secondary">{r.description}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">
              Comment (optional)
            </label>
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Add any additional context..."
              rows={3}
              className="w-full bg-bg-tertiary border border-border-primary rounded-lg px-4 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500 resize-none"
            />
          </div>
        </div>
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-border-primary">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => onDismiss(reason, comment)}
            disabled={!reason}
            className="px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Dismiss Finding
          </button>
        </div>
      </div>
    </div>
  );
}
