'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  ArrowLeft,
  ArrowRight,
  CheckCircle,
  XCircle,
  Download,
  Image,
  Code,
  Share2,
  Copy,
  Check,
  Clock,
  GitCommit,
  FolderKanban,
  X,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import { cn, formatDateTime, formatDate } from '@/lib/utils';
import { ScoreGauge } from '@/components/ScoreGauge';
import { attestationsApi } from '@/lib/api';
import type { Attestation as ApiAttestation } from '@/types';

interface Attestation extends ApiAttestation {
  type?: 'security_scan';
  version?: string;
  branch?: string;
  commit?: string;
  signature?: string;
  scan?: {
    id: string;
    findingsSummary: { critical: number; high: number; medium: number; low: number; info: number };
    scanners: string[];
    filesCount: number;
    duration: number;
  };
  expiresAt?: string;
}

interface Verification {
  isValid: boolean;
  signature: string;
  signatureAlgorithm?: string;
  verifiedAt: string;
  error?: string;
  unsigned?: boolean;
}

function formatDuration(seconds: number): string {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
}

export default function AttestationDetailPage() {
  const params = useParams();
  const attestationId = params.id as string;

  const [attestation, setAttestation] = useState<Attestation | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showEmbedModal, setShowEmbedModal] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);

  useEffect(() => {
    fetchAttestation();
  }, [attestationId]);

  async function fetchAttestation() {
    try {
      setIsLoading(true);
      setError(null);
      const data = await attestationsApi.get(attestationId);
      setAttestation(data as Attestation);
      // Auto-verify when loaded
      verifyAttestation();
    } catch (err) {
      console.error('Failed to fetch attestation:', err);
      setError(err instanceof Error ? err.message : 'Failed to load attestation');
    } finally {
      setIsLoading(false);
    }
  }

  async function verifyAttestation() {
    try {
      setIsVerifying(true);
      const result = await attestationsApi.verify(attestationId) as any;
      setVerification({
        isValid: result.valid,
        signature: attestation?.signature || 'sha256:verified',
        signatureAlgorithm: result.signatureAlgorithm || null,
        verifiedAt: new Date().toISOString(),
        error: result.valid ? undefined : (result.message || result.error),
        unsigned: result.unsigned || false,
      });
    } catch (err) {
      console.error('Failed to verify attestation:', err);
      setVerification({
        isValid: false,
        signature: '',
        verifiedAt: new Date().toISOString(),
        error: err instanceof Error ? err.message : 'Verification failed',
      });
    } finally {
      setIsVerifying(false);
    }
  }

  const handleCopy = async (text: string, field: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    );
  }

  if (error || !attestation) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-error mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load attestation</h2>
        <p className="text-text-secondary mb-4">{error || 'Attestation not found'}</p>
        <button
          onClick={fetchAttestation}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  const attestationData = {
    type: attestation.type || 'security_scan',
    version: attestation.version || '1.0',
    project: attestation.projectName,
    branch: attestation.branch || 'main',
    commit: attestation.commit || 'unknown',
    score: attestation.score,
    findings: attestation.scan?.findingsSummary || { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    scanners: attestation.scan?.scanners || [],
    createdAt: attestation.createdAt,
    signature: attestation.signature || '',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link
          href="/attestations"
          className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary mb-4"
        >
          <ArrowLeft size={16} />
          Back to Attestations
        </Link>

        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-text-primary">
            Attestation #{attestationId.slice(0, 12)}
          </h1>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-primary-500/10 text-primary-400">
            {(attestation.type || 'security_scan').replace('_', ' ')}
          </span>
        </div>

        <div className="flex items-center gap-4 text-sm text-text-secondary">
          <span className="flex items-center gap-1.5">
            <FolderKanban size={14} />
            {attestation.projectName} / {attestation.branch || 'main'}
          </span>
          <span className="flex items-center gap-1.5">
            <Clock size={14} />
            Created: {formatDate(attestation.createdAt)}
          </span>
          <span className="flex items-center gap-1.5">
            <GitCommit size={14} />
            {(attestation.commit || 'unknown').slice(0, 7)}
          </span>
        </div>
      </div>

      {/* Verification Status */}
      {isVerifying ? (
        <div className="card border-2 p-6 border-border-primary">
          <div className="flex items-center gap-4">
            <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
            <div>
              <h3 className="text-lg font-semibold text-text-primary">Verifying...</h3>
              <p className="text-text-secondary">Checking attestation signature</p>
            </div>
          </div>
        </div>
      ) : verification ? (
        verification.unsigned ? (
          <div className="card border-2 p-6 border-warning bg-warning/5">
            <div className="flex items-start gap-4">
              <AlertCircle className="text-warning flex-shrink-0" size={32} />
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-warning">UNSIGNED ATTESTATION</h3>
                <p className="text-text-secondary mt-1">
                  {verification.error || 'This attestation was created without a cryptographic signature. Sigstore/cosign signing is not configured in this environment.'}
                </p>
                <p className="text-text-tertiary text-sm mt-2">
                  The attestation data is valid and integrity-checked, but has not been signed with Sigstore. Configure cosign for cryptographic verification.
                </p>
              </div>
            </div>
          </div>
        ) : (
          <div className={cn(
            'card border-2 p-6',
            verification.isValid
              ? 'border-success bg-success/5'
              : 'border-error bg-error/5'
          )}>
            <div className="flex items-start gap-4">
              {verification.isValid ? (
                <CheckCircle className="text-success flex-shrink-0" size={32} />
              ) : (
                <XCircle className="text-error flex-shrink-0" size={32} />
              )}

              <div className="flex-1">
                <h3 className={cn(
                  'text-lg font-semibold',
                  verification.isValid ? 'text-success' : 'text-error'
                )}>
                  {verification.isValid ? 'VERIFIED' : 'VERIFICATION FAILED'}
                </h3>

                <p className="text-text-secondary mt-1">
                  {verification.isValid
                    ? 'This attestation has been cryptographically verified and has not been tampered with since creation.'
                    : verification.error || 'The attestation signature could not be verified.'}
                </p>

                {verification.isValid && verification.signature && (
                  <div className="mt-4 space-y-2 text-sm">
                    <div className="flex items-center gap-2">
                      <span className="text-text-tertiary">Signature:</span>
                      <code className="font-mono text-text-secondary">
                        {verification.signature.slice(0, 32)}...
                      </code>
                      <button
                        onClick={() => handleCopy(verification.signature, 'signature')}
                        className="p-1 hover:bg-bg-tertiary rounded transition-colors"
                      >
                        {copiedField === 'signature' ? (
                          <Check size={14} className="text-success" />
                        ) : (
                          <Copy size={14} className="text-text-tertiary" />
                        )}
                      </button>
                    </div>
                    {verification.signatureAlgorithm && (
                      <div className="flex items-center gap-2">
                        <span className="text-text-tertiary">Algorithm:</span>
                        <span className="text-text-secondary font-mono">
                          {verification.signatureAlgorithm === 'ed25519-local'
                            ? 'Ed25519 (local key)'
                            : verification.signatureAlgorithm === 'sigstore-cosign'
                            ? 'Sigstore / Cosign'
                            : verification.signatureAlgorithm}
                        </span>
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      <span className="text-text-tertiary">Verified:</span>
                      <span className="text-text-secondary">
                        {formatDateTime(verification.verifiedAt)}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )
      ) : null}

      {/* Actions */}
      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={async () => {
            if (!attestation) return;
            try {
              const token = localStorage.getItem('auth_token');
              const headers: Record<string, string> = {};
              if (token) headers['Authorization'] = `Bearer ${token}`;
              const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000/api/v1';
              const resp = await fetch(`${apiBase}/attestations/${attestation.id}/bundle`, { headers });
              if (!resp.ok) throw new Error(resp.statusText);
              const blob = await resp.blob();
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `attestation-${attestation.id.slice(0, 8)}.json`;
              a.click();
              URL.revokeObjectURL(url);
            } catch (err) {
              console.error('Download failed:', err);
              alert('Failed to download attestation bundle');
            }
          }}
          className="btn-secondary"
        >
          <Download size={16} />
          Download JSON
        </button>

        <button
          onClick={() => {
            if (!attestation) return;
            const isVerified = verification?.isValid;
            const score = attestation.score ?? 0;
            const label = 'AI HARDENER';
            const message = isVerified ? `VERIFIED  ${score}/1000` : 'UNVERIFIED';
            const bgColor = isVerified
              ? (score >= 800 ? '#22c55e' : score >= 500 ? '#eab308' : '#ef4444')
              : '#6b7280';

            // Render to canvas at 2x for crisp PNG
            const scale = 2;
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d')!;

            // Measure text to size the badge correctly
            const font = `bold ${11 * scale}px Verdana, Geneva, sans-serif`;
            ctx.font = font;
            const labelPad = 12 * scale;
            const msgPad = 12 * scale;
            const labelTextW = ctx.measureText(label).width;
            const msgTextW = ctx.measureText(message).width;
            const labelWidth = labelTextW + labelPad * 2;
            const msgWidth = msgTextW + msgPad * 2;
            const totalWidth = labelWidth + msgWidth;
            const height = 20 * scale;
            const radius = 3 * scale;

            canvas.width = totalWidth;
            canvas.height = height;

            // Label background (dark gray)
            ctx.beginPath();
            ctx.moveTo(radius, 0);
            ctx.lineTo(labelWidth, 0);
            ctx.lineTo(labelWidth, height);
            ctx.lineTo(radius, height);
            ctx.arcTo(0, height, 0, 0, radius);
            ctx.lineTo(0, radius);
            ctx.arcTo(0, 0, radius, 0, radius);
            ctx.closePath();
            ctx.fillStyle = '#555';
            ctx.fill();

            // Message background (colored)
            ctx.beginPath();
            ctx.moveTo(labelWidth, 0);
            ctx.lineTo(totalWidth - radius, 0);
            ctx.arcTo(totalWidth, 0, totalWidth, radius, radius);
            ctx.lineTo(totalWidth, height - radius);
            ctx.arcTo(totalWidth, height, totalWidth - radius, height, radius);
            ctx.lineTo(labelWidth, height);
            ctx.closePath();
            ctx.fillStyle = bgColor;
            ctx.fill();

            // Text
            ctx.font = font;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';

            // Shadow
            ctx.fillStyle = 'rgba(0,0,0,0.2)';
            ctx.fillText(label, labelWidth / 2, height / 2 + 1 * scale);
            ctx.fillText(message, labelWidth + msgWidth / 2, height / 2 + 1 * scale);

            // White text
            ctx.fillStyle = '#fff';
            ctx.fillText(label, labelWidth / 2, height / 2);
            ctx.fillText(message, labelWidth + msgWidth / 2, height / 2);

            canvas.toBlob((blob) => {
              if (!blob) return;
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `attestation-badge-${attestation.id.slice(0, 8)}.png`;
              a.click();
              URL.revokeObjectURL(url);
            }, 'image/png');
          }}
          className="btn-secondary"
        >
          <Image size={16} />
          Download Badge
        </button>

        <button
          onClick={() => setShowEmbedModal(true)}
          className="btn-secondary"
        >
          <Code size={16} />
          Copy Embed Code
        </button>

        <button
          onClick={() => setShowShareModal(true)}
          className="btn-primary"
        >
          <Share2 size={16} />
          Share Link
        </button>
      </div>

      {/* Score Card */}
      <div className="card p-6">
        <h3 className="text-lg font-semibold text-text-primary mb-4">Security Score</h3>
        <div className="flex justify-center py-4">
          <ScoreGauge score={attestation.score} size="lg" />
        </div>
      </div>

      {/* Scan Summary */}
      <div className="card p-6">
        <h3 className="text-lg font-semibold text-text-primary mb-4">Scan Summary</h3>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-6">
          <div>
            <p className="text-sm text-text-tertiary mb-1">Findings</p>
            <div className="flex flex-wrap items-center gap-2">
              {(attestation.scan?.findingsSummary?.critical || 0) > 0 && (
                <span className="text-error font-semibold">
                  {attestation.scan?.findingsSummary?.critical} Critical
                </span>
              )}
              {(attestation.scan?.findingsSummary?.high || 0) > 0 && (
                <span className="text-orange-500 font-semibold">
                  {attestation.scan?.findingsSummary?.high} High
                </span>
              )}
              {(attestation.scan?.findingsSummary?.medium || 0) > 0 && (
                <span className="text-warning font-semibold">
                  {attestation.scan?.findingsSummary?.medium} Medium
                </span>
              )}
              {(attestation.scan?.findingsSummary?.low || 0) > 0 && (
                <span className="text-info font-semibold">
                  {attestation.scan?.findingsSummary?.low} Low
                </span>
              )}
              {!attestation.scan?.findingsSummary && (
                <span className="text-text-tertiary">No findings data</span>
              )}
            </div>
          </div>

          <div>
            <p className="text-sm text-text-tertiary mb-1">Scanners</p>
            <p className="font-medium text-text-primary">
              {attestation.scan?.scanners?.join(', ') || 'N/A'}
            </p>
          </div>

          <div>
            <p className="text-sm text-text-tertiary mb-1">Files Scanned</p>
            <p className="font-medium text-text-primary">
              {attestation.scan?.filesCount?.toLocaleString() || 'N/A'}
            </p>
          </div>

          <div>
            <p className="text-sm text-text-tertiary mb-1">Duration</p>
            <p className="font-medium text-text-primary">
              {attestation.scan?.duration ? formatDuration(attestation.scan.duration) : 'N/A'}
            </p>
          </div>
        </div>

        {attestation.scanId && (
          <Link
            href={`/scans/${attestation.scanId}`}
            className="text-primary-400 hover:text-primary-300 text-sm font-medium inline-flex items-center gap-1"
          >
            View Full Scan Results
            <ArrowRight size={14} />
          </Link>
        )}
      </div>

      {/* Attestation Data */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-text-primary">Attestation Data</h3>
          <button
            onClick={() => handleCopy(JSON.stringify(attestationData, null, 2), 'json')}
            className="text-sm text-text-secondary hover:text-text-primary flex items-center gap-1"
          >
            {copiedField === 'json' ? (
              <>
                <Check size={14} className="text-success" />
                Copied
              </>
            ) : (
              <>
                <Copy size={14} />
                Copy
              </>
            )}
          </button>
        </div>

        <pre className="bg-bg-tertiary rounded-lg p-4 overflow-auto max-h-80 text-sm text-text-secondary font-mono">
          {JSON.stringify(attestationData, null, 2)}
        </pre>
      </div>

      {/* Embed Modal */}
      {showEmbedModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-lg">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary">
              <h2 className="text-lg font-semibold text-text-primary">Embed Badge</h2>
              <button
                onClick={() => setShowEmbedModal(false)}
                className="p-1 rounded hover:bg-bg-tertiary transition-colors"
              >
                <X size={20} className="text-text-tertiary" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              {/* Preview */}
              <div className="p-4 bg-bg-tertiary rounded-lg text-center">
                <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-success/20 text-success text-sm">
                  <CheckCircle size={14} />
                  Security Score: {attestation.score}/1000
                </div>
              </div>

              {/* Markdown */}
              <div>
                <label className="block text-sm font-medium text-text-primary mb-2">Markdown</label>
                <div className="relative">
                  <input
                    type="text"
                    value={`[![Security Score](${window.location.origin}/api/v1/badges/${attestationId})](${window.location.origin}/verify/${attestationId})`}
                    readOnly
                    className="input w-full pr-10 font-mono text-sm"
                  />
                  <button
                    onClick={() => handleCopy(`[![Security Score](${window.location.origin}/api/v1/badges/${attestationId})](${window.location.origin}/verify/${attestationId})`, 'markdown')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-1 hover:bg-bg-hover rounded"
                  >
                    {copiedField === 'markdown' ? (
                      <Check size={14} className="text-success" />
                    ) : (
                      <Copy size={14} className="text-text-tertiary" />
                    )}
                  </button>
                </div>
              </div>

              {/* HTML */}
              <div>
                <label className="block text-sm font-medium text-text-primary mb-2">HTML</label>
                <div className="relative">
                  <input
                    type="text"
                    value={`<a href="${window.location.origin}/verify/${attestationId}"><img src="${window.location.origin}/api/v1/badges/${attestationId}" alt="Security Score" /></a>`}
                    readOnly
                    className="input w-full pr-10 font-mono text-sm"
                  />
                  <button
                    onClick={() => handleCopy(`<a href="${window.location.origin}/verify/${attestationId}"><img src="${window.location.origin}/api/v1/badges/${attestationId}" alt="Security Score" /></a>`, 'html')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-1 hover:bg-bg-hover rounded"
                  >
                    {copiedField === 'html' ? (
                      <Check size={14} className="text-success" />
                    ) : (
                      <Copy size={14} className="text-text-tertiary" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex justify-end px-6 py-4 border-t border-border-primary">
              <button onClick={() => setShowEmbedModal(false)} className="btn-secondary">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Share Modal */}
      {showShareModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-lg">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary">
              <h2 className="text-lg font-semibold text-text-primary">Share Attestation</h2>
              <button
                onClick={() => setShowShareModal(false)}
                className="p-1 rounded hover:bg-bg-tertiary transition-colors"
              >
                <X size={20} className="text-text-tertiary" />
              </button>
            </div>

            <div className="p-6">
              <p className="text-text-secondary mb-4">
                Share this link to allow others to verify your security attestation.
              </p>

              <div className="relative mb-6">
                <input
                  type="text"
                  value={`${window.location.origin}/verify/${attestationId}`}
                  readOnly
                  className="input w-full pr-20 font-mono"
                />
                <button
                  onClick={() => handleCopy(`${window.location.origin}/verify/${attestationId}`, 'shareUrl')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 px-3 py-1 text-sm bg-primary-500 text-white rounded hover:bg-primary-600"
                >
                  {copiedField === 'shareUrl' ? 'Copied!' : 'Copy'}
                </button>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => window.open(`https://twitter.com/intent/tweet?text=Check out our security attestation&url=${encodeURIComponent(`${window.location.origin}/verify/${attestationId}`)}`, '_blank')}
                  className="btn-secondary flex-1"
                >
                  Twitter
                </button>
                <button
                  onClick={() => window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(`${window.location.origin}/verify/${attestationId}`)}`, '_blank')}
                  className="btn-secondary flex-1"
                >
                  LinkedIn
                </button>
              </div>
            </div>

            <div className="flex justify-end px-6 py-4 border-t border-border-primary">
              <button onClick={() => setShowShareModal(false)} className="btn-secondary">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
