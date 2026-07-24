'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ArrowLeft,
  ArrowRight,
  Check,
  FolderOpen,
  Github,
  Gitlab,
  SkipForward,
  Loader2,
  AlertTriangle,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { projectsApi } from '@/lib/api';

type Step = 1 | 2 | 3;

export default function NewProjectPage() {
  const router = useRouter();
  const [step, setStep] = useState<Step>(1);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Step 1: Details
  const [projectName, setProjectName] = useState('');
  const [description, setDescription] = useState('');
  const [nameError, setNameError] = useState<string | null>(null);

  // Step 2: Repository
  const [connectionType, setConnectionType] = useState<'local' | 'skip' | null>(null);
  const [localPath, setLocalPath] = useState('');

  // Step 3: Settings
  const [scanType, setScanType] = useState('standard');
  const [autoScan, setAutoScan] = useState(true);
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [slackNotifications, setSlackNotifications] = useState(true);

  const validateName = (name: string) => {
    if (!name.trim()) {
      setNameError('Project name is required');
      return false;
    }
    if (name.length > 255) {
      setNameError('Project name must be less than 255 characters');
      return false;
    }
    setNameError(null);
    return true;
  };

  const handleNextFromStep1 = () => {
    if (validateName(projectName)) {
      setStep(2);
    }
  };

  const handleSelectLocal = () => {
    setConnectionType('local');
  };

  const handleLocalNext = () => {
    if (localPath.trim()) {
      setStep(3);
    }
  };

  const handleSkipRepo = () => {
    setConnectionType('skip');
    setStep(3);
  };

  const handleCreate = async () => {
    setIsSubmitting(true);
    setSubmitError(null);

    try {
      // Build repository URL from selected repo if available
      let repositoryUrl: string | undefined;
      if (connectionType === 'local' && localPath.trim()) {
        repositoryUrl = `file://${localPath.trim()}`;
      }

      const project = await projectsApi.create({
        name: projectName,
        description: description || undefined,
        repositoryUrl,
      });

      router.push(`/projects/${project.id}?new=true`);
    } catch (err) {
      console.error('Failed to create project:', err);
      setSubmitError(err instanceof Error ? err.message : 'Failed to create project. Please try again.');
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <Link
          href="/projects"
          className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary mb-4"
        >
          <ArrowLeft size={16} />
          Back to Projects
        </Link>

        <h1 className="text-2xl font-bold text-text-primary">Create New Project</h1>
      </div>

      {/* Step Indicator */}
      <div className="flex items-center justify-center gap-4 mb-8">
        {[1, 2, 3].map(s => (
          <div key={s} className="flex items-center">
            <div className={cn(
              'w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-colors',
              step >= s
                ? 'bg-primary-500 text-white'
                : 'bg-bg-tertiary text-text-tertiary'
            )}>
              {step > s ? <Check size={16} /> : s}
            </div>
            <span className={cn(
              'ml-2 text-sm hidden sm:block',
              step >= s ? 'text-text-primary' : 'text-text-tertiary'
            )}>
              {s === 1 && 'Details'}
              {s === 2 && 'Repository'}
              {s === 3 && 'Settings'}
            </span>
            {s < 3 && (
              <div className={cn(
                'w-12 h-0.5 mx-4',
                step > s ? 'bg-primary-500' : 'bg-bg-tertiary'
              )} />
            )}
          </div>
        ))}
      </div>

      {/* Step Content */}
      <div className="card p-6">
        {/* Step 1: Details */}
        {step === 1 && (
          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-text-primary mb-2">
                Project Name <span className="text-error">*</span>
              </label>
              <input
                type="text"
                value={projectName}
                onChange={e => {
                  setProjectName(e.target.value);
                  if (nameError) validateName(e.target.value);
                }}
                onBlur={() => validateName(projectName)}
                placeholder="My Awesome App"
                className={cn(
                  'input w-full',
                  nameError && 'border-error focus:border-error focus:ring-error'
                )}
              />
              {nameError ? (
                <p className="text-sm text-error mt-1">{nameError}</p>
              ) : (
                <p className="text-xs text-text-tertiary mt-1">
                  Choose a name for your project
                </p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-text-primary mb-2">
                Description <span className="text-text-tertiary">(optional)</span>
              </label>
              <textarea
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="E-commerce platform built with Next.js"
                rows={3}
                className="input w-full resize-none"
              />
              <p className="text-xs text-text-tertiary mt-1">
                Brief description of what this project does
              </p>
            </div>

            <div className="flex justify-end">
              <button
                onClick={handleNextFromStep1}
                disabled={!projectName.trim()}
                className="btn-primary"
              >
                Next
                <ArrowRight size={16} />
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Repository */}
        {step === 2 && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-medium text-text-primary mb-2">
                Connect a repository
              </h3>
              <p className="text-sm text-text-secondary">
                Choose how to connect your code for scanning.
              </p>
            </div>

            <div className="space-y-3">
              {/* GitHub — Coming Soon */}
              <div className="w-full p-4 rounded-lg border border-border-primary text-left opacity-60 cursor-not-allowed">
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-lg bg-bg-tertiary flex items-center justify-center">
                    <Github size={20} className="text-text-tertiary" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h4 className="font-medium text-text-primary">Connect GitHub Repository</h4>
                      <span className="px-2 py-0.5 text-xs rounded-full bg-primary-500/10 text-primary-400 border border-primary-500/20">
                        Coming soon
                      </span>
                    </div>
                    <p className="text-sm text-text-secondary mt-1">
                      Scan code directly from GitHub
                    </p>
                  </div>
                </div>
              </div>

              {/* GitLab — Coming Soon */}
              <div className="w-full p-4 rounded-lg border border-border-primary text-left opacity-60 cursor-not-allowed">
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-lg bg-bg-tertiary flex items-center justify-center">
                    <Gitlab size={20} className="text-text-tertiary" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h4 className="font-medium text-text-primary">Connect GitLab Repository</h4>
                      <span className="px-2 py-0.5 text-xs rounded-full bg-primary-500/10 text-primary-400 border border-primary-500/20">
                        Coming soon
                      </span>
                    </div>
                    <p className="text-sm text-text-secondary mt-1">
                      Scan code directly from GitLab
                    </p>
                  </div>
                </div>
              </div>

              {/* Local Repository */}
              <button
                onClick={handleSelectLocal}
                className={cn(
                  'w-full p-4 rounded-lg border border-border-primary hover:border-primary-500/50 text-left transition-colors',
                  connectionType === 'local' && 'border-primary-500 bg-primary-500/5'
                )}
              >
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-lg bg-bg-tertiary flex items-center justify-center">
                    <FolderOpen size={20} className="text-text-secondary" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-medium text-text-primary">Local Repository</h4>
                    <p className="text-sm text-text-secondary mt-1">
                      Scan code from a local directory on the host machine
                    </p>
                    <div className="flex items-center gap-4 mt-3 text-xs text-text-tertiary">
                      <span className="flex items-center gap-1">
                        <Check size={12} className="text-success" />
                        No authentication required
                      </span>
                      <span className="flex items-center gap-1">
                        <Check size={12} className="text-success" />
                        Direct filesystem access
                      </span>
                    </div>
                  </div>
                </div>
              </button>

              {/* Local path input (shown when local is selected) */}
              {connectionType === 'local' && (
                <div className="pl-14 space-y-3">
                  <div>
                    <label className="block text-sm font-medium text-text-primary mb-1">
                      Repository Path
                    </label>
                    <input
                      type="text"
                      value={localPath}
                      onChange={e => setLocalPath(e.target.value)}
                      placeholder="~/Code/my-project"
                      className="input w-full font-mono text-sm"
                      autoFocus
                    />
                    <p className="text-xs text-text-tertiary mt-1">
                      Absolute path to the project directory on the host
                    </p>
                  </div>
                  <div className="flex justify-end">
                    <button
                      onClick={handleLocalNext}
                      disabled={!localPath.trim()}
                      className="btn-primary"
                    >
                      Next
                      <ArrowRight size={16} />
                    </button>
                  </div>
                </div>
              )}

              <div className="flex items-center gap-4 py-2">
                <div className="flex-1 h-px bg-border-primary" />
                <span className="text-sm text-text-tertiary">or</span>
                <div className="flex-1 h-px bg-border-primary" />
              </div>

              {/* Skip */}
              <button
                onClick={handleSkipRepo}
                className="w-full p-4 rounded-lg border border-border-primary hover:border-border-secondary text-left transition-colors"
              >
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-lg bg-bg-tertiary flex items-center justify-center">
                    <SkipForward size={20} className="text-text-tertiary" />
                  </div>
                  <div>
                    <h4 className="font-medium text-text-primary">Skip for now</h4>
                    <p className="text-sm text-text-secondary mt-1">
                      You can connect a repository later or upload code manually
                    </p>
                  </div>
                </div>
              </button>
            </div>

            <div className="flex justify-between">
              <button onClick={() => setStep(1)} className="btn-secondary">
                <ArrowLeft size={16} />
                Back
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Settings */}
        {step === 3 && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-medium text-text-primary mb-2">
                Configure Settings
              </h3>
              <p className="text-sm text-text-secondary">
                Set up scanning preferences for your project.
              </p>
            </div>

            {/* Scan Type */}
            <div>
              <label className="block text-sm font-medium text-text-primary mb-2">
                Default Scan Type
              </label>
              <select
                value={scanType}
                onChange={e => setScanType(e.target.value)}
                className="input w-full"
              >
                <option value="quick">Quick (~10 seconds)</option>
                <option value="standard">Standard (~45 seconds)</option>
                <option value="comprehensive">Comprehensive (~3 minutes)</option>
              </select>
            </div>

            {/* Auto Scan */}
            <label className="flex items-center gap-3 p-3 rounded-lg border border-border-primary hover:border-border-secondary cursor-pointer">
              <input
                type="checkbox"
                checked={autoScan}
                onChange={e => setAutoScan(e.target.checked)}
              />
              <div>
                <p className="font-medium text-text-primary">Automatically scan when code is pushed</p>
                <p className="text-xs text-text-tertiary">Trigger scans on every push to the monitored branch</p>
              </div>
            </label>

            {/* Notifications */}
            <div>
              <label className="block text-sm font-medium text-text-primary mb-2">
                Notification Settings
              </label>
              <div className="space-y-2">
                <label className="flex items-center gap-2 p-2 rounded hover:bg-bg-hover cursor-pointer">
                  <input
                    type="checkbox"
                    checked={emailNotifications}
                    onChange={e => setEmailNotifications(e.target.checked)}
                  />
                  <span className="text-sm text-text-primary">Email me when critical findings found</span>
                </label>
                <label className="flex items-center gap-2 p-2 rounded hover:bg-bg-hover cursor-pointer">
                  <input
                    type="checkbox"
                    checked={slackNotifications}
                    onChange={e => setSlackNotifications(e.target.checked)}
                  />
                  <span className="text-sm text-text-primary">Slack notifications (if connected)</span>
                </label>
              </div>
            </div>

            {/* Error Message */}
            {submitError && (
              <div className="p-4 rounded-lg bg-error/10 border border-error/20">
                <div className="flex items-center gap-2 text-error">
                  <AlertTriangle size={16} />
                  <span className="font-medium">Failed to create project</span>
                </div>
                <p className="text-sm text-text-secondary mt-1">{submitError}</p>
              </div>
            )}

            <div className="flex justify-between pt-4">
              <button onClick={() => setStep(2)} className="btn-secondary">
                <ArrowLeft size={16} />
                Back
              </button>
              <button
                onClick={handleCreate}
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
                    Create Project
                    <Check size={16} />
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
