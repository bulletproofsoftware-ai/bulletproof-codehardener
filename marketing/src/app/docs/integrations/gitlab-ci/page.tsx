import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, GitBranch, Copy } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'GitLab CI Integration',
  description: 'Integrate Code Hardener security scanning into your GitLab CI/CD pipelines.',
};

export default function GitLabCIPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="pt-32 pb-16">
        <div className="container mx-auto px-6">
          <div className="max-w-4xl mx-auto">
            {/* Breadcrumb */}
            <nav className="mb-8" aria-label="Breadcrumb">
              <ol className="flex items-center gap-2 text-sm">
                <li>
                  <Link href="/docs" className="text-text-secondary hover:text-text-primary transition-colors">
                    Docs
                  </Link>
                </li>
                <li className="text-text-tertiary">/</li>
                <li>
                  <Link href="/docs/integrations" className="text-text-secondary hover:text-text-primary transition-colors">
                    Integrations
                  </Link>
                </li>
                <li className="text-text-tertiary">/</li>
                <li className="text-text-primary">GitLab CI</li>
              </ol>
            </nav>

            {/* Header */}
            <div className="mb-12">
              <div className="flex items-center gap-4 mb-4">
                <div className="w-12 h-12 rounded-lg bg-bg-tertiary flex items-center justify-center">
                  <GitBranch className="h-6 w-6 text-text-primary" aria-hidden="true" />
                </div>
                <span className="px-2 py-0.5 rounded-full bg-primary-500/10 text-primary-500 text-xs font-medium">
                  Popular
                </span>
              </div>
              <h1 className="text-h1 mb-4">GitLab CI Integration</h1>
              <p className="text-xl text-text-secondary">
                Add Code Hardener security scanning to your GitLab CI/CD pipelines. Scan on every commit, merge request, and scheduled pipeline.
              </p>
            </div>

            {/* Quick Start */}
            <div className="card p-6 mb-12">
              <h2 className="text-h3 mb-4">Quick Start</h2>
              <p className="text-text-secondary mb-4">
                Add this configuration to your <code className="text-primary-400">.gitlab-ci.yml</code>:
              </p>
              <div className="relative">
                <div className="flex items-center justify-between px-4 py-2 bg-bg-tertiary rounded-t-lg border border-b-0 border-border-primary">
                  <span className="text-sm text-text-tertiary">.gitlab-ci.yml</span>
                  <button type="button" className="flex items-center gap-1 text-sm text-text-tertiary hover:text-text-primary transition-colors" aria-label="Copy code">
                    <Copy className="h-4 w-4" aria-hidden="true" />
                    Copy
                  </button>
                </div>
                <pre className="p-4 bg-[#0d1117] rounded-b-lg border border-border-primary overflow-x-auto">
                  <code className="text-sm text-[#c9d1d9] font-mono whitespace-pre">{`include:
  - remote: 'https://registry.codehardener.com/gitlab/v1/template.yml'

variables:
  AIHARDENER_API_KEY: $AIHARDENER_API_KEY

stages:
  - test
  - security
  - deploy

security-scan:
  stage: security
  extends: .codehardener-scan
  variables:
    SCAN_PATH: "."
    FAIL_ON: "high"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# Optional: Generate attestation on releases
attestation:
  stage: security
  extends: .codehardener-attest
  rules:
    - if: $CI_COMMIT_TAG
  artifacts:
    paths:
      - attestation.json`}</code>
                </pre>
              </div>
            </div>

            {/* Setup Steps */}
            <div className="space-y-8 mb-12">
              <h2 className="text-h2">Setup</h2>

              <div className="card p-6">
                <h3 className="text-h4 mb-4 flex items-center gap-3">
                  <span className="w-8 h-8 rounded-full bg-primary-500 text-white flex items-center justify-center text-sm font-bold">1</span>
                  Add CI/CD Variable
                </h3>
                <p className="text-text-secondary mb-4">
                  Store your API key as a protected CI/CD variable:
                </p>
                <ol className="list-decimal list-inside text-text-secondary space-y-2">
                  <li>Go to Settings &rarr; CI/CD &rarr; Variables</li>
                  <li>Click &quot;Add variable&quot;</li>
                  <li>Key: <code className="text-primary-400">AIHARDENER_API_KEY</code></li>
                  <li>Value: Your API key</li>
                  <li>Enable &quot;Mask variable&quot; and &quot;Protect variable&quot;</li>
                </ol>
              </div>

              <div className="card p-6">
                <h3 className="text-h4 mb-4 flex items-center gap-3">
                  <span className="w-8 h-8 rounded-full bg-primary-500 text-white flex items-center justify-center text-sm font-bold">2</span>
                  Update .gitlab-ci.yml
                </h3>
                <p className="text-text-secondary">
                  Add the configuration above to your pipeline. The template provides <code className="text-primary-400">.codehardener-scan</code> and <code className="text-primary-400">.codehardener-attest</code> jobs that you can extend.
                </p>
              </div>
            </div>

            {/* Configuration */}
            <div className="space-y-6 mb-12">
              <h2 className="text-h2">Configuration Variables</h2>
              <div className="card overflow-hidden">
                <table className="w-full">
                  <thead>
                    <tr className="bg-bg-tertiary border-b border-border-primary">
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Variable</th>
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Description</th>
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Default</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-primary">
                    {[
                      { name: 'AIHARDENER_API_KEY', description: 'Your Code Hardener API key', default: 'Required' },
                      { name: 'SCAN_PATH', description: 'Path to scan', default: '.' },
                      { name: 'FAIL_ON', description: 'Minimum severity to fail (low, medium, high, critical)', default: 'high' },
                      { name: 'OUTPUT_FORMAT', description: 'Report format (text, json, gitlab)', default: 'gitlab' },
                      { name: 'TOOLS', description: 'Comma-separated list of tools', default: 'all' },
                    ].map((option) => (
                      <tr key={option.name}>
                        <td className="px-6 py-4"><code className="text-primary-400 text-sm">{option.name}</code></td>
                        <td className="px-6 py-4 text-sm text-text-secondary">{option.description}</td>
                        <td className="px-6 py-4 text-sm text-text-tertiary">{option.default}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* GitLab Security Dashboard */}
            <div className="card p-6 mb-12">
              <h2 className="text-h3 mb-4">GitLab Security Dashboard Integration</h2>
              <p className="text-text-secondary mb-4">
                Code Hardener outputs results in GitLab&apos;s security report format, enabling full integration with the Security Dashboard:
              </p>
              <ul className="list-disc list-inside text-text-secondary space-y-2">
                <li>View findings in Merge Request security widgets</li>
                <li>Track vulnerabilities in the Security Dashboard</li>
                <li>Create issues directly from findings</li>
                <li>Set approval rules based on security status</li>
              </ul>
            </div>

            {/* Navigation */}
            <div className="mt-12 flex items-center justify-between pt-8 border-t border-border-primary">
              <Link href="/docs/integrations/github-actions" className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors">
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                GitHub Actions
              </Link>
              <Link href="/docs/integrations/vscode" className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors">
                VS Code
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </Link>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
