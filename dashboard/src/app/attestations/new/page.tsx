'use client';

import { useState, useEffect } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { Loader2, AlertCircle, CheckCircle } from 'lucide-react';
import { attestationsApi } from '@/lib/api';

export default function NewAttestationPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const scanId = searchParams.get('scanId');

  const [status, setStatus] = useState<'loading' | 'generating' | 'success' | 'error'>('loading');
  const [error, setError] = useState<string | null>(null);
  const [, setAttestationId] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) {
      setStatus('error');
      setError('No scan ID provided. Navigate to a completed scan to generate an attestation.');
      return;
    }
    generateAttestation(scanId);
  }, [scanId]);

  async function generateAttestation(scanId: string) {
    try {
      setStatus('generating');
      setError(null);
      const result = await attestationsApi.generate(scanId);
      setAttestationId(result.id);
      setStatus('success');
      // Redirect to the attestation detail page after a short delay
      setTimeout(() => {
        router.push(`/attestations/${result.id}`);
      }, 1500);
    } catch (err) {
      console.error('Failed to generate attestation:', err);
      setError(err instanceof Error ? err.message : 'Failed to generate attestation');
      setStatus('error');
    }
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
      {status === 'loading' || status === 'generating' ? (
        <>
          <Loader2 className="h-12 w-12 animate-spin text-primary-500 mb-4" />
          <h2 className="text-xl font-semibold text-text-primary mb-2">Generating Attestation</h2>
          <p className="text-text-secondary">
            Creating a cryptographic attestation for your scan results...
          </p>
        </>
      ) : status === 'success' ? (
        <>
          <CheckCircle className="h-12 w-12 text-success mb-4" />
          <h2 className="text-xl font-semibold text-text-primary mb-2">Attestation Generated</h2>
          <p className="text-text-secondary mb-4">Redirecting to attestation details...</p>
        </>
      ) : (
        <>
          <AlertCircle className="h-12 w-12 text-error mb-4" />
          <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to Generate Attestation</h2>
          <p className="text-text-secondary mb-4">{error}</p>
          <div className="flex gap-3">
            {scanId && (
              <button
                onClick={() => generateAttestation(scanId)}
                className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
              >
                Try Again
              </button>
            )}
            <button
              onClick={() => router.push('/attestations')}
              className="px-4 py-2 bg-bg-tertiary text-text-primary rounded-lg hover:bg-bg-hover transition-colors"
            >
              Back to Attestations
            </button>
          </div>
        </>
      )}
    </div>
  );
}
