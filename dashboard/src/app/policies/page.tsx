'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Plus,
  FileCode,
  MoreVertical,
  Edit,
  Trash2,
  Copy,
  ToggleLeft,
  ToggleRight,
  CheckCircle,
  Circle,
  Shield,
  Info,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { formatRelativeTime } from '@/lib/utils';
import { EmptyState } from '@/components/EmptyState';
import { policiesApi } from '@/lib/api';
import type { Policy } from '@/types';

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  useEffect(() => {
    fetchPolicies();
  }, []);

  async function fetchPolicies() {
    try {
      setIsLoading(true);
      setError(null);
      const response = await policiesApi.list({ limit: 100 });
      setPolicies(response.data);
    } catch (err) {
      console.error('Failed to fetch policies:', err);
      setError(err instanceof Error ? err.message : 'Failed to load policies');
    } finally {
      setIsLoading(false);
    }
  }

  const togglePolicyStatus = async (id: string) => {
    const policy = policies.find(p => p.id === id);
    if (!policy) return;

    try {
      setActionLoading(id);
      const updatedPolicy = await policiesApi.update(id, {
        isActive: !policy.isActive,
      });
      setPolicies(policies.map(p =>
        p.id === id ? updatedPolicy : p
      ));
    } catch (err) {
      console.error('Failed to toggle policy status:', err);
      alert(err instanceof Error ? err.message : 'Failed to update policy');
    } finally {
      setActionLoading(null);
      setMenuOpen(null);
    }
  };

  const duplicatePolicy = async (id: string) => {
    const original = policies.find(p => p.id === id);
    if (!original) return;

    try {
      setActionLoading(id);
      const newPolicy = await policiesApi.create({
        name: `${original.name} (Copy)`,
        description: original.description,
        isActive: false,
        rules: original.rules,
        appliedToProjects: [],
      });
      setPolicies([...policies, newPolicy]);
    } catch (err) {
      console.error('Failed to duplicate policy:', err);
      alert(err instanceof Error ? err.message : 'Failed to duplicate policy');
    } finally {
      setActionLoading(null);
      setMenuOpen(null);
    }
  };

  const deletePolicy = async (id: string) => {
    if (!confirm('Are you sure you want to delete this policy?')) {
      setMenuOpen(null);
      return;
    }

    try {
      setActionLoading(id);
      await policiesApi.delete(id);
      setPolicies(policies.filter(p => p.id !== id));
    } catch (err) {
      console.error('Failed to delete policy:', err);
      alert(err instanceof Error ? err.message : 'Failed to delete policy');
    } finally {
      setActionLoading(null);
      setMenuOpen(null);
    }
  };

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
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load policies</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={fetchPolicies}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  if (policies.length === 0) {
    return (
      <div className="card">
        <EmptyState
          icon={Shield}
          title="No Policies Yet"
          description="Create security policies to define quality gates for your scans."
          action={{ label: 'Create Policy', href: '/policies/new' }}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Policies</h1>
          <p className="text-text-secondary mt-1">
            Define custom security policies for your projects.
          </p>
        </div>
        <Link href="/policies/new" className="btn-primary">
          <Plus size={16} />
          New Policy
        </Link>
      </div>

      {/* Policies Table */}
      <div className="card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="text-left text-xs text-text-tertiary border-b border-border-primary uppercase tracking-wider">
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Rules</th>
              <th className="px-4 py-3">Projects</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Updated</th>
              <th className="px-4 py-3 w-20">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-primary">
            {policies.map(policy => (
              <tr key={policy.id} className="hover:bg-bg-hover/50 transition-colors">
                <td className="px-4 py-3">
                  <Link
                    href={`/policies/${policy.id}`}
                    className="block hover:text-primary-400 transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <FileCode size={16} className="text-text-tertiary" />
                      <span className="font-medium text-text-primary">{policy.name}</span>
                    </div>
                    {policy.description && (
                      <p className="text-xs text-text-tertiary mt-0.5 ml-6">{policy.description}</p>
                    )}
                  </Link>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">
                  {policy.rules.length} rule{policy.rules.length !== 1 ? 's' : ''}
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">
                  {policy.appliedToProjects.length === 0 ? (
                    <span className="text-text-tertiary">None</span>
                  ) : (
                    <span>{policy.appliedToProjects.length} project{policy.appliedToProjects.length !== 1 ? 's' : ''}</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    {policy.isActive ? (
                      <>
                        <CheckCircle size={14} className="text-success" />
                        <span className="text-sm text-success">Active</span>
                      </>
                    ) : (
                      <>
                        <Circle size={14} className="text-text-tertiary" />
                        <span className="text-sm text-text-tertiary">Inactive</span>
                      </>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">
                  {formatRelativeTime(policy.updatedAt)}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1">
                    <Link
                      href={`/policies/${policy.id}`}
                      className="p-1.5 rounded hover:bg-bg-tertiary transition-colors"
                      title="Edit policy"
                    >
                      <Edit size={14} className="text-text-tertiary" />
                    </Link>
                    <div className="relative">
                      <button
                        onClick={() => setMenuOpen(menuOpen === policy.id ? null : policy.id)}
                        className="p-1.5 rounded hover:bg-bg-tertiary transition-colors"
                        disabled={actionLoading === policy.id}
                      >
                        {actionLoading === policy.id ? (
                          <Loader2 size={14} className="animate-spin text-text-tertiary" />
                        ) : (
                          <MoreVertical size={14} className="text-text-tertiary" />
                        )}
                      </button>
                      {menuOpen === policy.id && (
                        <div className="absolute right-0 mt-1 w-44 bg-bg-secondary border border-border-primary rounded-lg shadow-xl z-10">
                          <button
                            onClick={() => togglePolicyStatus(policy.id)}
                            className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover flex items-center gap-2"
                          >
                            {policy.isActive ? (
                              <>
                                <ToggleLeft size={14} />
                                Deactivate
                              </>
                            ) : (
                              <>
                                <ToggleRight size={14} />
                                Activate
                              </>
                            )}
                          </button>
                          <button
                            onClick={() => duplicatePolicy(policy.id)}
                            className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover flex items-center gap-2"
                          >
                            <Copy size={14} />
                            Duplicate
                          </button>
                          <button
                            onClick={() => deletePolicy(policy.id)}
                            className="w-full px-4 py-2 text-left text-sm text-error hover:bg-bg-hover flex items-center gap-2"
                          >
                            <Trash2 size={14} />
                            Delete
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Info Card */}
      <div className="card bg-primary-500/5 border-primary-500/20">
        <div className="flex items-start gap-3">
          <Info size={20} className="text-primary-400 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-medium text-text-primary">About Policies</h3>
            <p className="text-sm text-text-secondary mt-1">
              Policies define quality gates that must pass before a scan is considered successful.
              You can create policies with severity thresholds, required scanners, or minimum score requirements.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
