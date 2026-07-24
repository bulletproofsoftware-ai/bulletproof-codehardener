'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft,
  Save,
  Trash2,
  Play,
  CheckCircle,
  XCircle,
  Loader2,
  AlertTriangle,
  X,
  AlertCircle,
  FileCode,
} from 'lucide-react';
import { cn, formatRelativeTime } from '@/lib/utils';
import { policiesApi, projectsApi, scansApi } from '@/lib/api';
import type { Policy as BasePolicy, Project, Scan } from '@/types';

interface PolicyProject {
  id: string;
  name: string;
  selected: boolean;
}

interface ExtendedPolicy extends BasePolicy {
  type?: 'yaml' | 'rego';
  status?: 'active' | 'draft';
  content?: string;
  projects?: PolicyProject[];
  applyToNewProjects?: boolean;
}

interface TestResult {
  passed: boolean;
  scanName: string;
  gates: { name: string; passed: boolean; expected: string; actual: string }[];
}

export default function PolicyEditorPage() {
  const params = useParams();
  const router = useRouter();
  const policyId = params.id as string;

  const [policy, setPolicy] = useState<ExtendedPolicy | null>(null);
  const [allProjects, setAllProjects] = useState<Project[]>([]);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'yaml' | 'rego' | 'preview'>('yaml');
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [isTesting, setIsTesting] = useState(false);

  useEffect(() => {
    fetchPolicy();
    fetchProjects();
    fetchRecentScans();
  }, [policyId]);

  async function fetchPolicy() {
    try {
      setIsLoading(true);
      setError(null);
      const policyData = await policiesApi.get(policyId);

      // Transform to ExtendedPolicy with project assignments
      const extendedPolicy: ExtendedPolicy = {
        ...policyData,
        type: (policyData as ExtendedPolicy).type || 'yaml',
        status: policyData.isActive ? 'active' : 'draft',
        content: (policyData as ExtendedPolicy).content || generateDefaultContent(policyData),
        applyToNewProjects: (policyData as ExtendedPolicy).applyToNewProjects || false,
      };

      setPolicy(extendedPolicy);
    } catch (err) {
      console.error('Failed to fetch policy:', err);
      setError(err instanceof Error ? err.message : 'Failed to load policy');
    } finally {
      setIsLoading(false);
    }
  }

  async function fetchProjects() {
    try {
      const response = await projectsApi.list({ limit: 100 });
      setAllProjects(response.data);
    } catch (err) {
      console.error('Failed to fetch projects:', err);
    }
  }

  async function fetchRecentScans() {
    try {
      const response = await scansApi.list({ limit: 10, status: 'completed' });
      setRecentScans(response.data);
      if (response.data.length > 0) {
        setSelectedScanId(response.data[0].id);
      }
    } catch (err) {
      console.error('Failed to fetch recent scans:', err);
    }
  }

  // Generate default YAML content from policy rules
  function generateDefaultContent(policyData: BasePolicy): string {
    const rules = policyData.rules || [];
    const yamlLines = [
      '# Security Policy Configuration',
      `name: ${policyData.name}`,
      '',
      'gates:',
    ];

    rules.forEach(rule => {
      yamlLines.push(`  - name: ${rule.name || 'unnamed_rule'}`);
      yamlLines.push(`    type: ${rule.type || 'threshold'}`);
      if (rule.severity) {
        yamlLines.push(`    severity: ${rule.severity}`);
      }
      if (rule.threshold !== undefined) {
        yamlLines.push(`    threshold: ${rule.threshold}`);
      }
    });

    return yamlLines.join('\n');
  }

  // Merge projects list with policy assignments
  const policyProjects: PolicyProject[] = allProjects.map(project => ({
    id: project.id,
    name: project.name,
    selected: policy?.appliedToProjects?.includes(project.id) || false,
  }));

  const handleSave = async () => {
    if (!policy) return;

    setIsSaving(true);
    try {
      const selectedProjectIds = policyProjects
        .filter(p => p.selected)
        .map(p => p.id);

      await policiesApi.update(policyId, {
        name: policy.name,
        description: policy.description,
        isActive: policy.status === 'active',
        rules: policy.rules,
        appliedToProjects: selectedProjectIds,
      });

      setHasChanges(false);
    } catch (err) {
      console.error('Failed to save policy:', err);
      alert(err instanceof Error ? err.message : 'Failed to save policy');
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    setIsDeleting(true);
    try {
      await policiesApi.delete(policyId);
      router.push('/policies');
    } catch (err) {
      console.error('Failed to delete policy:', err);
      alert(err instanceof Error ? err.message : 'Failed to delete policy');
      setIsDeleting(false);
      setShowDeleteModal(false);
    }
  };

  const [testError, setTestError] = useState<string | null>(null);

  const handleTest = async () => {
    if (!selectedScanId) return;

    setIsTesting(true);
    setTestError(null);
    try {
      // Call the policy test endpoint
      const result = await policiesApi.test(policyId, selectedScanId);

      const selectedScan = recentScans.find(s => s.id === selectedScanId);
      setTestResult({
        passed: result.passed,
        scanName: selectedScan ? `${selectedScan.projectName} - ${formatRelativeTime(selectedScan.createdAt)}` : 'Unknown Scan',
        gates: result.gates || [],
      });
    } catch (err) {
      console.error('Failed to test policy:', err);
      setTestError(err instanceof Error ? err.message : 'Failed to test policy. Please try again.');
    } finally {
      setIsTesting(false);
    }
  };

  const updateContent = (content: string) => {
    if (!policy) return;
    setPolicy({ ...policy, content });
    setHasChanges(true);
  };

  const toggleProjectSelection = (projectId: string) => {
    if (!policy) return;
    const currentApplied = policy.appliedToProjects || [];
    const isCurrentlyApplied = currentApplied.includes(projectId);

    setPolicy({
      ...policy,
      appliedToProjects: isCurrentlyApplied
        ? currentApplied.filter(id => id !== projectId)
        : [...currentApplied, projectId],
    });
    setHasChanges(true);
  };

  const toggleStatus = () => {
    if (!policy) return;
    setPolicy({
      ...policy,
      status: policy.status === 'active' ? 'draft' : 'active',
      isActive: policy.status !== 'active',
    });
    setHasChanges(true);
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-error mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load policy</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <div className="flex gap-3">
          <Link
            href="/policies"
            className="px-4 py-2 border border-border-primary rounded-lg hover:bg-bg-hover transition-colors"
          >
            Back to Policies
          </Link>
          <button
            onClick={fetchPolicy}
            className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  // Not found state
  if (!policy) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <FileCode className="h-12 w-12 text-text-tertiary mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Policy not found</h2>
        <p className="text-text-secondary mb-4">The policy you're looking for doesn't exist.</p>
        <Link
          href="/policies"
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Back to Policies
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link
            href="/policies"
            className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary mb-4"
          >
            <ArrowLeft size={16} />
            Back to Policies
          </Link>

          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">{policy.name}</h1>
            <span className={cn(
              'text-xs font-mono px-2 py-0.5 rounded',
              policy.type === 'yaml'
                ? 'bg-primary-500/10 text-primary-400'
                : 'bg-violet-500/10 text-violet-400'
            )}>
              {(policy.type || 'yaml').toUpperCase()}
            </span>
          </div>
          <p className="text-sm text-text-tertiary mt-1">
            Last saved: {formatRelativeTime(policy.updatedAt)}
            {hasChanges && <span className="text-warning ml-2">(unsaved changes)</span>}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowDeleteModal(true)}
            className="p-2 text-error hover:bg-error/10 rounded-lg transition-colors"
            title="Delete policy"
          >
            <Trash2 size={18} />
          </button>
          <button
            onClick={() => setShowTestModal(true)}
            className="btn-secondary"
          >
            <Play size={16} />
            Test Policy
          </button>
          <button
            onClick={handleSave}
            disabled={isSaving || !hasChanges}
            className="btn-primary"
          >
            {isSaving ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Save size={16} />
            )}
            Save Changes
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Editor */}
        <div className="lg:col-span-2 space-y-4">
          {/* Metadata */}
          <div className="card p-4 space-y-4">
            <div>
              <label className="block text-sm font-medium text-text-primary mb-2">
                Policy Name
              </label>
              <input
                type="text"
                value={policy.name}
                onChange={e => {
                  setPolicy({ ...policy, name: e.target.value });
                  setHasChanges(true);
                }}
                className="input w-full"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-text-primary mb-2">
                Description
              </label>
              <input
                type="text"
                value={policy.description || ''}
                onChange={e => {
                  setPolicy({ ...policy, description: e.target.value });
                  setHasChanges(true);
                }}
                placeholder="Brief description of this policy"
                className="input w-full"
              />
            </div>
          </div>

          {/* Tabs */}
          <div className="card overflow-hidden">
            <div className="flex border-b border-border-primary">
              {(['yaml', 'rego', 'preview'] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={cn(
                    'px-4 py-2.5 text-sm font-medium transition-colors',
                    activeTab === tab
                      ? 'text-primary-400 border-b-2 border-primary-400 -mb-px'
                      : 'text-text-secondary hover:text-text-primary'
                  )}
                >
                  {tab === 'yaml' && 'YAML'}
                  {tab === 'rego' && 'Rego'}
                  {tab === 'preview' && 'Preview'}
                </button>
              ))}
            </div>

            <div className="p-4">
              {activeTab === 'yaml' && (
                <textarea
                  value={policy.content || ''}
                  onChange={e => updateContent(e.target.value)}
                  className="w-full h-80 font-mono text-sm bg-bg-tertiary rounded-lg p-4 text-text-primary border border-border-primary focus:outline-none focus:border-primary-500 resize-none"
                  spellCheck={false}
                />
              )}
              {activeTab === 'rego' && (
                <div className="h-80 flex items-center justify-center text-text-tertiary">
                  <p>Rego editor coming soon. Convert your YAML policy for advanced logic.</p>
                </div>
              )}
              {activeTab === 'preview' && (
                <div className="h-80 overflow-auto">
                  <pre className="text-sm text-text-secondary whitespace-pre-wrap">
                    {policy.content || ''}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Status */}
          <div className="card p-4">
            <h3 className="text-sm font-medium text-text-tertiary uppercase tracking-wider mb-3">
              Status
            </h3>
            <div className="space-y-2">
              <label className="flex items-center gap-3 p-3 rounded-lg border border-border-primary hover:border-border-secondary cursor-pointer">
                <input
                  type="radio"
                  name="status"
                  checked={policy.status === 'active'}
                  onChange={() => toggleStatus()}
                />
                <div>
                  <p className="font-medium text-text-primary">Active</p>
                  <p className="text-xs text-text-secondary">Policy is enforced on scans</p>
                </div>
              </label>
              <label className="flex items-center gap-3 p-3 rounded-lg border border-border-primary hover:border-border-secondary cursor-pointer">
                <input
                  type="radio"
                  name="status"
                  checked={policy.status === 'draft'}
                  onChange={() => toggleStatus()}
                />
                <div>
                  <p className="font-medium text-text-primary">Draft</p>
                  <p className="text-xs text-text-secondary">Policy is saved but not enforced</p>
                </div>
              </label>
            </div>
          </div>

          {/* Applied To */}
          <div className="card p-4">
            <h3 className="text-sm font-medium text-text-tertiary uppercase tracking-wider mb-3">
              Applied To
            </h3>
            <div className="space-y-2">
              {policyProjects.length === 0 ? (
                <p className="text-sm text-text-tertiary">No projects available</p>
              ) : (
                policyProjects.map(project => (
                  <label
                    key={project.id}
                    className="flex items-center gap-2 p-2 rounded hover:bg-bg-hover cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={project.selected}
                      onChange={() => toggleProjectSelection(project.id)}
                    />
                    <span className="text-sm text-text-primary">{project.name}</span>
                  </label>
                ))
              )}
              <div className="pt-2 border-t border-border-primary mt-2">
                <label className="flex items-center gap-2 p-2 rounded hover:bg-bg-hover cursor-pointer">
                  <input
                    type="checkbox"
                    checked={policy.applyToNewProjects || false}
                    onChange={() => {
                      setPolicy({ ...policy, applyToNewProjects: !policy.applyToNewProjects });
                      setHasChanges(true);
                    }}
                  />
                  <span className="text-sm text-text-primary">Apply to all new projects</span>
                </label>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Test Modal */}
      {showTestModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-md">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary">
              <h2 className="text-lg font-semibold text-text-primary">
                {testResult ? 'Test Results' : 'Test Policy'}
              </h2>
              <button
                onClick={() => {
                  setShowTestModal(false);
                  setTestResult(null);
                }}
                className="p-1 rounded hover:bg-bg-tertiary transition-colors"
              >
                <X size={20} className="text-text-tertiary" />
              </button>
            </div>

            <div className="p-6">
              {testError ? (
                <>
                  <div className="p-4 rounded-lg bg-error/10 mb-4">
                    <div className="flex items-center gap-2">
                      <AlertCircle className="text-error" size={24} />
                      <div>
                        <p className="font-semibold text-error">Test Failed</p>
                        <p className="text-sm text-text-secondary">{testError}</p>
                      </div>
                    </div>
                  </div>
                  <div className="flex justify-end gap-3">
                    <button
                      onClick={() => {
                        setTestError(null);
                      }}
                      className="btn-secondary"
                    >
                      Try Again
                    </button>
                    <button
                      onClick={() => {
                        setShowTestModal(false);
                        setTestError(null);
                      }}
                      className="btn-primary"
                    >
                      Close
                    </button>
                  </div>
                </>
              ) : !testResult ? (
                <>
                  <p className="text-sm text-text-secondary mb-4">
                    Select a recent scan to test this policy against:
                  </p>
                  <div className="space-y-2 mb-6">
                    {recentScans.length === 0 ? (
                      <p className="text-sm text-text-tertiary">No completed scans available</p>
                    ) : (
                      recentScans.slice(0, 5).map(scan => (
                        <label
                          key={scan.id}
                          className="flex items-center gap-3 p-3 rounded-lg border border-border-primary hover:border-border-secondary cursor-pointer"
                        >
                          <input
                            type="radio"
                            name="scan"
                            checked={selectedScanId === scan.id}
                            onChange={() => setSelectedScanId(scan.id)}
                          />
                          <span className="text-sm text-text-primary">
                            {scan.projectName} - {formatRelativeTime(scan.createdAt)} (Score: {scan.score})
                          </span>
                        </label>
                      ))
                    )}
                  </div>
                  <div className="flex justify-end gap-3">
                    <button
                      onClick={() => setShowTestModal(false)}
                      className="btn-secondary"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleTest}
                      disabled={!selectedScanId || isTesting}
                      className="btn-primary"
                    >
                      {isTesting ? (
                        <>
                          <Loader2 size={16} className="animate-spin" />
                          Testing...
                        </>
                      ) : (
                        'Run Test'
                      )}
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <div className={cn(
                    'p-4 rounded-lg mb-4',
                    testResult.passed ? 'bg-success/10' : 'bg-error/10'
                  )}>
                    <div className="flex items-center gap-2">
                      {testResult.passed ? (
                        <CheckCircle className="text-success" size={24} />
                      ) : (
                        <XCircle className="text-error" size={24} />
                      )}
                      <div>
                        <p className={cn(
                          'font-semibold',
                          testResult.passed ? 'text-success' : 'text-error'
                        )}>
                          {testResult.passed ? 'PASSED' : 'FAILED'}
                        </p>
                        <p className="text-sm text-text-secondary">{testResult.scanName}</p>
                      </div>
                    </div>
                  </div>

                  <h4 className="text-sm font-medium text-text-primary mb-2">Gates Evaluated:</h4>
                  <div className="space-y-2">
                    {testResult.gates.map((gate, i) => (
                      <div key={i} className="flex items-center gap-2 text-sm">
                        {gate.passed ? (
                          <CheckCircle size={14} className="text-success" />
                        ) : (
                          <XCircle size={14} className="text-error" />
                        )}
                        <span className="text-text-primary">{gate.name}:</span>
                        <span className="text-text-secondary">
                          {gate.expected} (found: {gate.actual})
                        </span>
                      </div>
                    ))}
                  </div>

                  {!testResult.passed && (
                    <p className="text-sm text-text-secondary mt-4 p-3 bg-bg-tertiary rounded-lg">
                      This scan would be blocked from production deployment.
                    </p>
                  )}

                  <div className="flex justify-end gap-3 mt-6">
                    <button
                      onClick={() => {
                        setShowTestModal(false);
                        setTestResult(null);
                      }}
                      className="btn-secondary"
                    >
                      Close
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Delete Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-md p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-error/10 flex items-center justify-center">
                <AlertTriangle size={20} className="text-error" />
              </div>
              <h2 className="text-lg font-semibold text-text-primary">Delete Policy</h2>
            </div>
            <p className="text-sm text-text-secondary mb-6">
              Are you sure you want to delete <strong>{policy.name}</strong>? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowDeleteModal(false)}
                className="btn-secondary"
                disabled={isDeleting}
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={isDeleting}
                className="px-4 py-2 text-sm bg-error text-white rounded-lg hover:bg-error/90 transition-colors flex items-center gap-2"
              >
                {isDeleting ? (
                  <>
                    <Loader2 size={16} className="animate-spin" />
                    Deleting...
                  </>
                ) : (
                  'Delete Policy'
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
