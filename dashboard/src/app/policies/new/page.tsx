'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ArrowLeft,
  Factory,
  TestTube,
  FileCheck,
  FileCode,
  Loader2,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface Template {
  id: string;
  name: string;
  description: string;
  icon: typeof Factory;
  yaml: string;
}

const templates: Template[] = [
  {
    id: 'production',
    name: 'Production',
    description: 'Zero tolerance for critical and high findings',
    icon: Factory,
    yaml: `name: Production Deploy Policy

gates:
  production:
    max_critical: 0
    max_high: 0
    max_medium: 10
    require_attestation: true
    require_sbom: true

exceptions: []
`,
  },
  {
    id: 'staging',
    name: 'Staging',
    description: 'Balanced rules for staging environment',
    icon: TestTube,
    yaml: `name: Staging Rules

gates:
  staging:
    max_critical: 0
    max_high: 5
    max_medium: 20

exceptions: []
`,
  },
  {
    id: 'soc2',
    name: 'SOC 2',
    description: 'Full SOC 2 compliance requirements',
    icon: FileCheck,
    yaml: `name: SOC 2 Compliance

gates:
  all:
    max_critical: 0
    require_sbom: true
    require_attestation: true
    require_secrets_scan: true
    require_dependency_scan: true

exceptions: []
`,
  },
];

export default function NewPolicyPage() {
  const router = useRouter();
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);

  const handleTemplateSelect = async (templateId: string) => {
    setSelectedTemplate(templateId);
    setIsCreating(true);

    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 500));

    // Navigate to editor with template
    router.push(`/policies/new-draft?template=${templateId}`);
  };

  const handleBlankPolicy = async () => {
    setSelectedTemplate('blank');
    setIsCreating(true);

    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 500));

    router.push('/policies/new-draft');
  };

  return (
    <div className="max-w-3xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <Link
          href="/policies"
          className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary mb-4"
        >
          <ArrowLeft size={16} />
          Back to Policies
        </Link>

        <h1 className="text-2xl font-bold text-text-primary">Create New Policy</h1>
        <p className="text-text-secondary mt-1">
          Start from a template or create a blank policy.
        </p>
      </div>

      {/* Templates */}
      <div className="space-y-4 mb-8">
        <h2 className="text-sm font-medium text-text-tertiary uppercase tracking-wider">
          Start from a template
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {templates.map(template => {
            const Icon = template.icon;
            const isSelected = selectedTemplate === template.id;

            return (
              <button
                key={template.id}
                onClick={() => handleTemplateSelect(template.id)}
                disabled={isCreating}
                className={cn(
                  'card p-6 text-left transition-all hover:border-primary-500/50',
                  isSelected && 'border-primary-500 bg-primary-500/5',
                  isCreating && !isSelected && 'opacity-50'
                )}
              >
                <div className="w-10 h-10 rounded-lg bg-bg-tertiary flex items-center justify-center mb-4">
                  {isSelected && isCreating ? (
                    <Loader2 size={20} className="text-primary-400 animate-spin" />
                  ) : (
                    <Icon size={20} className="text-primary-400" />
                  )}
                </div>
                <h3 className="font-semibold text-text-primary mb-1">{template.name}</h3>
                <p className="text-sm text-text-secondary">{template.description}</p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Blank Policy */}
      <div className="space-y-4">
        <h2 className="text-sm font-medium text-text-tertiary uppercase tracking-wider">
          Or start from scratch
        </h2>
        <button
          onClick={handleBlankPolicy}
          disabled={isCreating}
          className={cn(
            'card p-6 w-full text-left flex items-center gap-4 transition-all hover:border-primary-500/50',
            selectedTemplate === 'blank' && 'border-primary-500 bg-primary-500/5',
            isCreating && selectedTemplate !== 'blank' && 'opacity-50'
          )}
        >
          <div className="w-10 h-10 rounded-lg bg-bg-tertiary flex items-center justify-center">
            {selectedTemplate === 'blank' && isCreating ? (
              <Loader2 size={20} className="text-text-tertiary animate-spin" />
            ) : (
              <FileCode size={20} className="text-text-tertiary" />
            )}
          </div>
          <div>
            <h3 className="font-semibold text-text-primary">Blank Policy</h3>
            <p className="text-sm text-text-secondary">
              Start with an empty policy and define your own rules
            </p>
          </div>
        </button>
      </div>

      {/* Policy Types Info */}
      <div className="mt-8 p-4 rounded-lg bg-bg-tertiary border border-border-primary">
        <h3 className="text-sm font-medium text-text-primary mb-3">Policy Types</h3>
        <div className="space-y-3 text-sm">
          <div className="flex items-start gap-3">
            <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-primary-500/10 text-primary-400">
              YAML
            </span>
            <p className="text-text-secondary">
              Simple, declarative format for basic quality gates. Best for most use cases.
            </p>
          </div>
          <div className="flex items-start gap-3">
            <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-400">
              REGO
            </span>
            <p className="text-text-secondary">
              Advanced policy language using Open Policy Agent. For complex conditional logic.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
