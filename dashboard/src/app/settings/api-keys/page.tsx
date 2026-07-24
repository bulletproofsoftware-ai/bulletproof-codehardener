'use client';

import { useState, useEffect } from 'react';
import {
  Key,
  Plus,
  Copy,
  Check,
  MoreVertical,
  Trash2,
  AlertTriangle,
  AlertCircle,
  Loader2,
  X,
} from 'lucide-react';
import { cn, formatDate, formatRelativeTime } from '@/lib/utils';
import { EmptyState } from '@/components/EmptyState';
import { apiKeysApi } from '@/lib/api';
import type { ApiKey } from '@/types';

export default function ApiKeysSettingsPage() {
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [successModalOpen, setSuccessModalOpen] = useState(false);
  const [newKey, setNewKey] = useState('');
  const [deleteModalOpen, setDeleteModalOpen] = useState<string | null>(null);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  useEffect(() => {
    fetchApiKeys();
  }, []);

  async function fetchApiKeys() {
    try {
      setIsLoading(true);
      setError(null);
      const data = await apiKeysApi.list();
      setApiKeys(data);
    } catch (err) {
      console.error('Failed to fetch API keys:', err);
      setError(err instanceof Error ? err.message : 'Failed to load API keys');
    } finally {
      setIsLoading(false);
    }
  }

  const handleCreate = async (name: string, expiresAt?: string) => {
    try {
      setActionLoading('create');
      const result = await apiKeysApi.create(name, expiresAt);
      setApiKeys([result, ...apiKeys]);
      setNewKey(result.key);
      setCreateModalOpen(false);
      setSuccessModalOpen(true);
    } catch (err) {
      console.error('Failed to create API key:', err);
      alert(err instanceof Error ? err.message : 'Failed to create API key');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      setActionLoading(id);
      await apiKeysApi.delete(id);
      setApiKeys(apiKeys.filter(k => k.id !== id));
      setDeleteModalOpen(null);
    } catch (err) {
      console.error('Failed to delete API key:', err);
      alert(err instanceof Error ? err.message : 'Failed to delete API key');
    } finally {
      setActionLoading(null);
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
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load API keys</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={fetchApiKeys}
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
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-text-primary">API Keys</h2>
          <p className="text-sm text-text-secondary mt-1">
            Create API keys to access Code Hardener programmatically.
          </p>
        </div>
        <button
          onClick={() => setCreateModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          <Plus size={16} />
          Create New Key
        </button>
      </div>

      {/* API Keys Table */}
      {apiKeys.length > 0 ? (
        <div className="bg-bg-secondary border border-border-primary rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="text-left text-xs text-text-tertiary border-b border-border-primary uppercase tracking-wider">
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Prefix</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3">Last Used</th>
                <th className="px-4 py-3 w-10"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-primary">
              {apiKeys.map(key => (
                <tr key={key.id} className="hover:bg-bg-hover/50 transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-primary-500/10 flex items-center justify-center">
                        <Key size={14} className="text-primary-400" />
                      </div>
                      <span className="font-medium text-text-primary">{key.name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <code className="text-sm text-text-secondary font-mono bg-bg-tertiary px-2 py-1 rounded">
                      {key.prefix}
                    </code>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={cn(
                        'px-2 py-0.5 text-xs font-medium rounded',
                        key.type === 'live'
                          ? 'bg-success/10 text-success'
                          : 'bg-warning/10 text-warning'
                      )}
                    >
                      {key.type === 'live' ? 'Live' : 'Test'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-text-secondary">
                    {formatDate(key.createdAt)}
                  </td>
                  <td className="px-4 py-3 text-sm text-text-secondary">
                    {key.lastUsedAt ? formatRelativeTime(key.lastUsedAt) : 'Never'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="relative">
                      <button
                        onClick={() => setMenuOpen(menuOpen === key.id ? null : key.id)}
                        disabled={actionLoading === key.id}
                        className="p-1 rounded hover:bg-bg-tertiary transition-colors disabled:opacity-50"
                      >
                        {actionLoading === key.id ? (
                          <Loader2 size={16} className="animate-spin text-text-tertiary" />
                        ) : (
                          <MoreVertical size={16} className="text-text-tertiary" />
                        )}
                      </button>
                      {menuOpen === key.id && (
                        <div className="absolute right-0 mt-1 w-32 bg-bg-secondary border border-border-primary rounded-lg shadow-xl z-10">
                          <button
                            onClick={() => {
                              setDeleteModalOpen(key.id);
                              setMenuOpen(null);
                            }}
                            className="w-full px-4 py-2 text-left text-sm text-error hover:bg-bg-hover flex items-center gap-2"
                          >
                            <Trash2 size={14} />
                            Revoke
                          </button>
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          icon={Key}
          title="No API keys yet"
          description="Create an API key to access Code Hardener programmatically."
          action={{
            label: 'Create New Key',
            onClick: () => setCreateModalOpen(true),
          }}
        />
      )}

      {/* Note */}
      <p className="text-sm text-text-tertiary">
        Note: API keys are only shown once when created. Keep them secure.
      </p>

      {/* Create Modal */}
      {createModalOpen && (
        <CreateKeyModal
          onClose={() => setCreateModalOpen(false)}
          onCreate={handleCreate}
          isLoading={actionLoading === 'create'}
        />
      )}

      {/* Success Modal */}
      {successModalOpen && (
        <KeyCreatedModal
          apiKey={newKey}
          onClose={() => {
            setSuccessModalOpen(false);
            setNewKey('');
          }}
        />
      )}

      {/* Delete Confirmation Modal */}
      {deleteModalOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-md p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-error/10 flex items-center justify-center">
                <AlertTriangle size={20} className="text-error" />
              </div>
              <h2 className="text-lg font-semibold text-text-primary">Revoke API Key</h2>
            </div>
            <p className="text-sm text-text-secondary mb-6">
              Are you sure you want to revoke this API key? Any applications using this key will no longer be able to authenticate.
            </p>
            <div className="flex items-center justify-end gap-3">
              <button
                onClick={() => setDeleteModalOpen(null)}
                disabled={actionLoading === deleteModalOpen}
                className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteModalOpen)}
                disabled={actionLoading === deleteModalOpen}
                className="px-4 py-2 text-sm bg-error text-white rounded-lg hover:bg-error/90 transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {actionLoading === deleteModalOpen && <Loader2 size={14} className="animate-spin" />}
                Revoke Key
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function CreateKeyModal({
  onClose,
  onCreate,
  isLoading,
}: {
  onClose: () => void;
  onCreate: (name: string, expiresAt?: string) => void;
  isLoading: boolean;
}) {
  const [name, setName] = useState('');
  const [expiration, setExpiration] = useState('never');

  const getExpiresAt = () => {
    if (expiration === 'never') return undefined;
    const days = parseInt(expiration);
    const date = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    return date.toISOString();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary">
          <h2 className="text-lg font-semibold text-text-primary">Create API Key</h2>
          <button
            onClick={onClose}
            disabled={isLoading}
            className="p-1 rounded hover:bg-bg-tertiary transition-colors disabled:opacity-50"
          >
            <X size={20} className="text-text-tertiary" />
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">
              Key Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Production API"
              disabled={isLoading}
              className="w-full bg-bg-tertiary border border-border-primary rounded-lg px-4 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500 disabled:opacity-50"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">
              Expiration (optional)
            </label>
            <select
              value={expiration}
              onChange={(e) => setExpiration(e.target.value)}
              disabled={isLoading}
              className="w-full bg-bg-tertiary border border-border-primary rounded-lg px-4 py-2 text-sm text-text-primary focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500 disabled:opacity-50"
            >
              <option value="never">Never</option>
              <option value="30">30 days</option>
              <option value="60">60 days</option>
              <option value="90">90 days</option>
              <option value="365">1 year</option>
            </select>
          </div>
        </div>
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-border-primary">
          <button
            onClick={onClose}
            disabled={isLoading}
            className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={() => onCreate(name, getExpiresAt())}
            disabled={!name || isLoading}
            className="px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 disabled:opacity-50 transition-colors flex items-center gap-2"
          >
            {isLoading && <Loader2 size={14} className="animate-spin" />}
            Create Key
          </button>
        </div>
      </div>
    </div>
  );
}

function KeyCreatedModal({
  apiKey,
  onClose,
}: {
  apiKey: string;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(apiKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary">
          <h2 className="text-lg font-semibold text-text-primary">API Key Created</h2>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-bg-tertiary transition-colors"
          >
            <X size={20} className="text-text-tertiary" />
          </button>
        </div>
        <div className="p-6">
          <div className="flex items-start gap-3 p-3 bg-warning/10 border border-warning/20 rounded-lg mb-4">
            <AlertTriangle size={20} className="text-warning flex-shrink-0 mt-0.5" />
            <p className="text-sm text-text-primary">
              Copy your API key now. You won't be able to see it again!
            </p>
          </div>

          <div className="flex items-center gap-2 p-3 bg-bg-tertiary rounded-lg">
            <code className="flex-1 text-sm font-mono text-text-primary break-all">
              {apiKey}
            </code>
            <button
              onClick={copyToClipboard}
              className="p-2 rounded hover:bg-bg-hover transition-colors flex-shrink-0"
            >
              {copied ? (
                <Check size={16} className="text-success" />
              ) : (
                <Copy size={16} className="text-text-tertiary" />
              )}
            </button>
          </div>
        </div>
        <div className="flex items-center justify-end px-6 py-4 border-t border-border-primary">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
