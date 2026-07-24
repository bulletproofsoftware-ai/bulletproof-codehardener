'use client';

import { useState, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ArrowLeft,
  Save,
  Plus,
  Trash2,
  Loader2,
  AlertTriangle,
  Info,
  Shield,
  BarChart3,
  Search,
  Code,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { policiesApi } from '@/lib/api';
import type { PolicyRule } from '@/types';

interface PolicyDraft {
  name: string;
  description: string;
  rules: PolicyRule[];
  appliedToProjects: string[];
  isActive: boolean;
}

const TEMPLATES: Record<string, PolicyDraft> = {
  production: {
    name: 'Production Deploy Policy',
    description: 'Zero tolerance for critical and high findings',
    rules: [
      { id: '1', type: 'severity_threshold', condition: 'max_critical', value: 0 },
      { id: '2', type: 'severity_threshold', condition: 'max_high', value: 0 },
      { id: '3', type: 'severity_threshold', condition: 'max_medium', value: 10 },
      { id: '4', type: 'scanner_required', condition: 'require', value: 'attestation' },
      { id: '5', type: 'scanner_required', condition: 'require', value: 'sbom' },
    ],
    appliedToProjects: [],
    isActive: true,
  },
  staging: {
    name: 'Staging Rules',
    description: 'Balanced rules for staging environment',
    rules: [
      { id: '1', type: 'severity_threshold', condition: 'max_critical', value: 0 },
      { id: '2', type: 'severity_threshold', condition: 'max_high', value: 5 },
      { id: '3', type: 'severity_threshold', condition: 'max_medium', value: 20 },
    ],
    appliedToProjects: [],
    isActive: true,
  },
  soc2: {
    name: 'SOC 2 Compliance',
    description: 'Full SOC 2 compliance requirements',
    rules: [
      { id: '1', type: 'severity_threshold', condition: 'max_critical', value: 0 },
      { id: '2', type: 'scanner_required', condition: 'require', value: 'sbom' },
      { id: '3', type: 'scanner_required', condition: 'require', value: 'attestation' },
      { id: '4', type: 'scanner_required', condition: 'require', value: 'secrets_scan' },
      { id: '5', type: 'scanner_required', condition: 'require', value: 'dependency_scan' },
    ],
    appliedToProjects: [],
    isActive: true,
  },
};

const BLANK_POLICY: PolicyDraft = {
  name: '',
  description: '',
  rules: [],
  appliedToProjects: [],
  isActive: true,
};

const RULE_TYPES = [
  { value: 'severity_threshold', label: 'Severity Threshold', icon: Shield },
  { value: 'scanner_required', label: 'Required Scanner', icon: Search },
  { value: 'score_minimum', label: 'Minimum Score', icon: BarChart3 },
  { value: 'custom', label: 'Custom Rule', icon: Code },
] as const;

const SEVERITY_CONDITIONS = [
  { value: 'max_critical', label: 'Maximum Critical Findings' },
  { value: 'max_high', label: 'Maximum High Findings' },
  { value: 'max_medium', label: 'Maximum Medium Findings' },
  { value: 'max_low', label: 'Maximum Low Findings' },
];

const REQUIRED_SCANNERS = [
  { value: 'sbom', label: 'SBOM Generation' },
  { value: 'attestation', label: 'Attestation Signing' },
  { value: 'secrets_scan', label: 'Secrets Scanning' },
  { value: 'dependency_scan', label: 'Dependency Scanning' },
  { value: 'sast', label: 'Static Analysis (SAST)' },
  { value: 'container_scan', label: 'Container Scanning' },
];

export default function NewPolicyDraftPage() {
  return (
    <Suspense fallback={<PolicyEditorSkeleton />}>
      <PolicyEditorContent />
    </Suspense>
  );
}

function PolicyEditorSkeleton() {
  return (
    <div className="max-w-3xl mx-auto">
      <div className="mb-8">
        <div className="h-4 w-24 bg-bg-tertiary rounded animate-pulse mb-4" />
        <div className="h-8 w-48 bg-bg-tertiary rounded animate-pulse" />
        <div className="h-4 w-64 bg-bg-tertiary rounded animate-pulse mt-2" />
      </div>
      <div className="card p-6 space-y-4">
        <div className="h-6 w-32 bg-bg-tertiary rounded animate-pulse" />
        <div className="h-10 w-full bg-bg-tertiary rounded animate-pulse" />
        <div className="h-24 w-full bg-bg-tertiary rounded animate-pulse" />
      </div>
    </div>
  );
}

function PolicyEditorContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const templateId = searchParams.get('template');

  const [policy, setPolicy] = useState<PolicyDraft>(() => {
    if (templateId && TEMPLATES[templateId]) {
      return { ...TEMPLATES[templateId] };
    }
    return { ...BLANK_POLICY };
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});

  // Generate unique ID for new rules
  const generateRuleId = () => `rule-${Date.now()}-${crypto.randomUUID().slice(0, 9)}`;

  const addRule = () => {
    const newRule: PolicyRule = {
      id: generateRuleId(),
      type: 'severity_threshold',
      condition: 'max_critical',
      value: 0,
    };
    setPolicy({ ...policy, rules: [...policy.rules, newRule] });
  };

  const updateRule = (ruleId: string, updates: Partial<PolicyRule>) => {
    setPolicy({
      ...policy,
      rules: policy.rules.map(rule =>
        rule.id === ruleId ? { ...rule, ...updates } : rule
      ),
    });
  };

  const removeRule = (ruleId: string) => {
    setPolicy({
      ...policy,
      rules: policy.rules.filter(rule => rule.id !== ruleId),
    });
  };

  const validate = (): boolean => {
    const errors: Record<string, string> = {};

    if (!policy.name.trim()) {
      errors.name = 'Policy name is required';
    }

    if (policy.rules.length === 0) {
      errors.rules = 'At least one rule is required';
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validate()) {
      return;
    }

    setError(null);
    setIsSubmitting(true);

    try {
      const createdPolicy = await policiesApi.create({
        name: policy.name,
        description: policy.description || undefined,
        isActive: policy.isActive,
        rules: policy.rules,
        appliedToProjects: policy.appliedToProjects,
      });

      router.push(`/policies/${createdPolicy.id}?new=true`);
    } catch (err) {
      console.error('Failed to create policy:', err);
      setError(err instanceof Error ? err.message : 'Failed to create policy. Please try again.');
      setIsSubmitting(false);
    }
  };

  const getRuleTypeIcon = (type: PolicyRule['type']) => {
    const ruleType = RULE_TYPES.find(r => r.value === type);
    return ruleType?.icon || Shield;
  };

  return (
    <div className="max-w-3xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <Link
          href="/policies/new"
          className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary mb-4"
        >
          <ArrowLeft size={16} />
          Back to Templates
        </Link>

        <h1 className="text-2xl font-bold text-text-primary">
          {templateId ? 'Customize Policy' : 'Create Policy'}
        </h1>
        <p className="text-text-secondary mt-1">
          {templateId
            ? `Starting from the ${TEMPLATES[templateId]?.name || 'template'} template`
            : 'Define your security policy rules'}
        </p>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="mb-6 p-4 rounded-lg bg-error/10 border border-error/20">
          <div className="flex items-center gap-2 text-error">
            <AlertTriangle size={16} />
            <span className="font-medium">Failed to create policy</span>
          </div>
          <p className="text-sm text-text-secondary mt-1">{error}</p>
        </div>
      )}

      {/* Form */}
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Basic Info */}
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-text-primary mb-4">Policy Details</h2>

          <div className="space-y-4">
            {/* Name */}
            <div>
              <label className="block text-sm font-medium text-text-primary mb-2">
                Policy Name <span className="text-error">*</span>
              </label>
              <input
                type="text"
                value={policy.name}
                onChange={e => setPolicy({ ...policy, name: e.target.value })}
                placeholder="e.g., Production Deploy Policy"
                className={cn('input w-full', validationErrors.name && 'border-error')}
              />
              {validationErrors.name && (
                <p className="text-sm text-error mt-1">{validationErrors.name}</p>
              )}
            </div>

            {/* Description */}
            <div>
              <label className="block text-sm font-medium text-text-primary mb-2">
                Description
              </label>
              <textarea
                value={policy.description}
                onChange={e => setPolicy({ ...policy, description: e.target.value })}
                placeholder="Describe what this policy enforces..."
                rows={3}
                className="input w-full resize-none"
              />
            </div>

            {/* Active Toggle */}
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={policy.isActive}
                onChange={e => setPolicy({ ...policy, isActive: e.target.checked })}
              />
              <span className="text-sm text-text-primary">Enable policy immediately</span>
            </label>
          </div>
        </div>

        {/* Rules */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-text-primary">Policy Rules</h2>
              <p className="text-sm text-text-secondary mt-1">
                Define the conditions that must be met for a scan to pass
              </p>
            </div>
            <button
              type="button"
              onClick={addRule}
              className="btn-secondary text-sm"
            >
              <Plus size={16} />
              Add Rule
            </button>
          </div>

          {validationErrors.rules && (
            <div className="mb-4 p-3 rounded-lg bg-error/10 border border-error/20">
              <p className="text-sm text-error flex items-center gap-2">
                <AlertTriangle size={14} />
                {validationErrors.rules}
              </p>
            </div>
          )}

          {policy.rules.length === 0 ? (
            <div className="text-center py-8 border border-dashed border-border-primary rounded-lg">
              <Info size={24} className="mx-auto text-text-tertiary mb-2" />
              <p className="text-text-secondary">No rules defined yet</p>
              <button
                type="button"
                onClick={addRule}
                className="mt-3 text-sm text-primary-400 hover:text-primary-300"
              >
                Add your first rule
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {policy.rules.map((rule, _index) => {
                const Icon = getRuleTypeIcon(rule.type);

                return (
                  <div
                    key={rule.id}
                    className="p-4 rounded-lg border border-border-primary bg-bg-secondary"
                  >
                    <div className="flex items-start gap-4">
                      <div className="w-8 h-8 rounded-lg bg-bg-tertiary flex items-center justify-center flex-shrink-0">
                        <Icon size={16} className="text-text-secondary" />
                      </div>

                      <div className="flex-1 space-y-3">
                        {/* Rule Type */}
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-xs font-medium text-text-tertiary mb-1">
                              Rule Type
                            </label>
                            <select
                              value={rule.type}
                              onChange={e => updateRule(rule.id, {
                                type: e.target.value as PolicyRule['type'],
                                condition: e.target.value === 'severity_threshold' ? 'max_critical' :
                                           e.target.value === 'scanner_required' ? 'require' :
                                           e.target.value === 'score_minimum' ? 'minimum' : '',
                                value: e.target.value === 'score_minimum' ? 70 : 0,
                              })}
                              className="input w-full text-sm"
                            >
                              {RULE_TYPES.map(type => (
                                <option key={type.value} value={type.value}>
                                  {type.label}
                                </option>
                              ))}
                            </select>
                          </div>

                          {/* Condition based on type */}
                          {rule.type === 'severity_threshold' && (
                            <div>
                              <label className="block text-xs font-medium text-text-tertiary mb-1">
                                Condition
                              </label>
                              <select
                                value={rule.condition}
                                onChange={e => updateRule(rule.id, { condition: e.target.value })}
                                className="input w-full text-sm"
                              >
                                {SEVERITY_CONDITIONS.map(cond => (
                                  <option key={cond.value} value={cond.value}>
                                    {cond.label}
                                  </option>
                                ))}
                              </select>
                            </div>
                          )}

                          {rule.type === 'scanner_required' && (
                            <div>
                              <label className="block text-xs font-medium text-text-tertiary mb-1">
                                Required Scanner
                              </label>
                              <select
                                value={String(rule.value)}
                                onChange={e => updateRule(rule.id, { value: e.target.value })}
                                className="input w-full text-sm"
                              >
                                {REQUIRED_SCANNERS.map(scanner => (
                                  <option key={scanner.value} value={scanner.value}>
                                    {scanner.label}
                                  </option>
                                ))}
                              </select>
                            </div>
                          )}

                          {rule.type === 'score_minimum' && (
                            <div>
                              <label className="block text-xs font-medium text-text-tertiary mb-1">
                                Minimum Score
                              </label>
                              <input
                                type="number"
                                min={0}
                                max={1000}
                                value={typeof rule.value === 'number' ? rule.value : 0}
                                onChange={e => updateRule(rule.id, { value: parseInt(e.target.value) || 0 })}
                                className="input w-full text-sm"
                              />
                            </div>
                          )}

                          {rule.type === 'custom' && (
                            <div>
                              <label className="block text-xs font-medium text-text-tertiary mb-1">
                                Custom Condition
                              </label>
                              <input
                                type="text"
                                value={rule.condition}
                                onChange={e => updateRule(rule.id, { condition: e.target.value })}
                                placeholder="e.g., cve_age < 30"
                                className="input w-full text-sm"
                              />
                            </div>
                          )}
                        </div>

                        {/* Value for severity threshold */}
                        {rule.type === 'severity_threshold' && (
                          <div className="w-32">
                            <label className="block text-xs font-medium text-text-tertiary mb-1">
                              Maximum Allowed
                            </label>
                            <input
                              type="number"
                              min={0}
                              value={typeof rule.value === 'number' ? rule.value : 0}
                              onChange={e => updateRule(rule.id, { value: parseInt(e.target.value) || 0 })}
                              className="input w-full text-sm"
                            />
                          </div>
                        )}

                        {rule.type === 'custom' && (
                          <div>
                            <label className="block text-xs font-medium text-text-tertiary mb-1">
                              Value
                            </label>
                            <input
                              type="text"
                              value={String(rule.value)}
                              onChange={e => updateRule(rule.id, { value: e.target.value })}
                              placeholder="Enter value"
                              className="input w-full text-sm"
                            />
                          </div>
                        )}
                      </div>

                      {/* Remove Button */}
                      <button
                        type="button"
                        onClick={() => removeRule(rule.id)}
                        className="p-2 text-text-tertiary hover:text-error transition-colors"
                        title="Remove rule"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Info Box */}
        <div className="p-4 rounded-lg bg-bg-tertiary border border-border-primary">
          <div className="flex items-start gap-3">
            <Info size={16} className="text-primary-400 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-text-secondary">
              <p className="font-medium text-text-primary mb-1">How policies work</p>
              <p>
                Policies define quality gates that scans must pass before deployment.
                When a scan runs, it will be evaluated against all active policies
                applied to the project. Failed policies will block deployment in CI/CD pipelines.
              </p>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-end gap-3 pt-4">
          <Link
            href="/policies"
            className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-hover transition-colors"
          >
            Cancel
          </Link>
          <button
            type="submit"
            disabled={isSubmitting}
            className="btn-primary"
          >
            {isSubmitting ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                Creating...
              </>
            ) : (
              <>
                <Save size={16} />
                Create Policy
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
