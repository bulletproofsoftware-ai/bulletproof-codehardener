import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, Github, Copy, AlertCircle, Info } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'GitHub Actions Integration',
  description: 'Integrate Code Hardener security scanning into your GitHub Actions workflows.',
};

export default function GitHubActionsPage() {
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
                  <Link
                    href="/docs"
                    className="text-text-secondary hover:text-text-primary transition-colors"
                  >
                    Docs
                  </Link>
                </li>
                <li className="text-text-tertiary">/</li>
                <li>
                  <Link
                    href="/docs/integrations"
                    className="text-text-secondary hover:text-text-primary transition-colors"
                  >
                    Integrations
                  </Link>
                </li>
                <li className="text-text-tertiary">/</li>
                <li className="text-text-primary">GitHub Actions</li>
              </ol>
            </nav>

            {/* Header */}
            <div className="mb-12">
              <div className="flex items-center gap-4 mb-4">
                <div className="w-12 h-12 rounded-lg bg-bg-tertiary flex items-center justify-center">
                  <Github className="h-6 w-6 text-text-primary" aria-hidden="true" />
                </div>
                <div>
                  <span className="px-2 py-0.5 rounded-full bg-primary-500/10 text-primary-500 text-xs font-medium">
                    Popular
                  </span>
                </div>
              </div>
              <h1 className="text-h1 mb-4">GitHub Actions Integration</h1>
              <p className="text-xl text-text-secondary">
                Add automated security scanning to your GitHub workflows. Scan code on every push and pull request, block vulnerable code from being merged, and generate attestations for compliance.
              </p>
            </div>

            {/* Quick Start */}
            <div className="card p-6 mb-12">
              <h2 className="text-h3 mb-4">Quick Start</h2>
              <p className="text-text-secondary mb-4">
                Add this workflow to your repository to get started in minutes:
              </p>
              <div className="relative">
                <div className="flex items-center justify-between px-4 py-2 bg-bg-tertiary rounded-t-lg border border-b-0 border-border-primary">
                  <span className="text-sm text-text-tertiary">.github/workflows/security.yml</span>
                  <button
                    type="button"
                    className="flex items-center gap-1 text-sm text-text-tertiary hover:text-text-primary transition-colors"
                    aria-label="Copy code"
                  >
                    <Copy className="h-4 w-4" aria-hidden="true" />
                    Copy
                  </button>
                </div>
                <pre className="p-4 bg-[#0d1117] rounded-b-lg border border-border-primary overflow-x-auto">
                  <code className="text-sm text-[#c9d1d9] font-mono whitespace-pre">{`name: Code Hardener Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Code Hardener Scan
        uses: codehardener/scan-action@v1
        with:
          api-key: \${{ secrets.AIHARDENER_API_KEY }}
          fail-on: high
          format: sarif

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: codehardener-results.sarif

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: codehardener/comment-action@v1
        with:
          api-key: \${{ secrets.AIHARDENER_API_KEY }}`}</code>
                </pre>
              </div>
            </div>

            {/* Setup Steps */}
            <div className="space-y-8 mb-12">
              <h2 className="text-h2">Setup</h2>

              {/* Step 1 */}
              <div className="card p-6">
                <h3 className="text-h4 mb-4 flex items-center gap-3">
                  <span className="w-8 h-8 rounded-full bg-primary-500 text-white flex items-center justify-center text-sm font-bold">
                    1
                  </span>
                  Get your API key
                </h3>
                <p className="text-text-secondary mb-4">
                  Generate an API key from your Code Hardener dashboard. We recommend creating a dedicated key for CI/CD use.
                </p>
                <ol className="list-decimal list-inside text-text-secondary space-y-2 mb-4">
                  <li>Go to <Link href="/dashboard/settings/api-keys" className="text-primary-500 hover:text-primary-400">Dashboard &rarr; Settings &rarr; API Keys</Link></li>
                  <li>Click &quot;Create New Key&quot;</li>
                  <li>Name it (e.g., &quot;GitHub Actions - my-repo&quot;)</li>
                  <li>Copy the key (it won&apos;t be shown again)</li>
                </ol>
              </div>

              {/* Step 2 */}
              <div className="card p-6">
                <h3 className="text-h4 mb-4 flex items-center gap-3">
                  <span className="w-8 h-8 rounded-full bg-primary-500 text-white flex items-center justify-center text-sm font-bold">
                    2
                  </span>
                  Add secret to repository
                </h3>
                <p className="text-text-secondary mb-4">
                  Store your API key as a GitHub repository secret:
                </p>
                <ol className="list-decimal list-inside text-text-secondary space-y-2 mb-4">
                  <li>Go to your repository &rarr; Settings &rarr; Secrets and variables &rarr; Actions</li>
                  <li>Click &quot;New repository secret&quot;</li>
                  <li>Name: <code className="text-primary-400">AIHARDENER_API_KEY</code></li>
                  <li>Value: Paste your API key</li>
                  <li>Click &quot;Add secret&quot;</li>
                </ol>
                <div className="p-4 bg-warning/10 rounded-lg flex gap-3">
                  <AlertCircle className="h-5 w-5 text-warning flex-shrink-0 mt-0.5" aria-hidden="true" />
                  <p className="text-sm text-text-secondary">
                    For organization-wide use, consider adding the secret at the organization level.
                  </p>
                </div>
              </div>

              {/* Step 3 */}
              <div className="card p-6">
                <h3 className="text-h4 mb-4 flex items-center gap-3">
                  <span className="w-8 h-8 rounded-full bg-primary-500 text-white flex items-center justify-center text-sm font-bold">
                    3
                  </span>
                  Create workflow file
                </h3>
                <p className="text-text-secondary mb-4">
                  Create the workflow file at <code className="text-primary-400">.github/workflows/security.yml</code> with the configuration shown above, or customize based on your needs.
                </p>
              </div>
            </div>

            {/* Configuration Options */}
            <div className="space-y-6 mb-12">
              <h2 className="text-h2">Configuration Options</h2>

              <div className="card overflow-hidden">
                <table className="w-full">
                  <thead>
                    <tr className="bg-bg-tertiary border-b border-border-primary">
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Input</th>
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Description</th>
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Default</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-primary">
                    {[
                      { name: 'api-key', description: 'Your Code Hardener API key', default: 'Required' },
                      { name: 'path', description: 'Path to scan (relative to repository root)', default: '.' },
                      { name: 'fail-on', description: 'Minimum severity to fail the build (low, medium, high, critical)', default: 'high' },
                      { name: 'format', description: 'Output format (text, json, sarif)', default: 'sarif' },
                      { name: 'tools', description: 'Comma-separated list of tools to run', default: 'all' },
                      { name: 'ignore-paths', description: 'Paths to exclude from scanning', default: 'node_modules,.git' },
                      { name: 'config', description: 'Path to .hardener.yml configuration file', default: '.hardener.yml' },
                    ].map((option) => (
                      <tr key={option.name}>
                        <td className="px-6 py-4">
                          <code className="text-primary-400 text-sm">{option.name}</code>
                        </td>
                        <td className="px-6 py-4 text-sm text-text-secondary">{option.description}</td>
                        <td className="px-6 py-4 text-sm text-text-tertiary">{option.default}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Advanced Examples */}
            <div className="space-y-8 mb-12">
              <h2 className="text-h2">Advanced Examples</h2>

              {/* Example: Matrix builds */}
              <div className="card p-6">
                <h3 className="text-h4 mb-4">Matrix Build for Multiple Languages</h3>
                <p className="text-text-secondary mb-4">
                  Scan different parts of your monorepo with language-specific configurations:
                </p>
                <div className="relative">
                  <pre className="p-4 bg-[#0d1117] rounded-lg border border-border-primary overflow-x-auto">
                    <code className="text-sm text-[#c9d1d9] font-mono whitespace-pre">{`jobs:
  scan:
    strategy:
      matrix:
        include:
          - path: ./backend
            tools: opengrep,trivy
          - path: ./frontend
            tools: opengrep,eslint
          - path: ./infrastructure
            tools: checkov,trivy

    steps:
      - uses: actions/checkout@v4
      - uses: codehardener/scan-action@v1
        with:
          api-key: \${{ secrets.AIHARDENER_API_KEY }}
          path: \${{ matrix.path }}
          tools: \${{ matrix.tools }}`}</code>
                  </pre>
                </div>
              </div>

              {/* Example: Attestation */}
              <div className="card p-6">
                <h3 className="text-h4 mb-4">Generate Attestation on Release</h3>
                <p className="text-text-secondary mb-4">
                  Create a signed attestation when publishing a release:
                </p>
                <div className="relative">
                  <pre className="p-4 bg-[#0d1117] rounded-lg border border-border-primary overflow-x-auto">
                    <code className="text-sm text-[#c9d1d9] font-mono whitespace-pre">{`on:
  release:
    types: [published]

jobs:
  attest:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for Sigstore

    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        uses: codehardener/scan-action@v1
        with:
          api-key: \${{ secrets.AIHARDENER_API_KEY }}

      - name: Generate Attestation
        uses: codehardener/attest-action@v1
        with:
          api-key: \${{ secrets.AIHARDENER_API_KEY }}
          sign: true  # Uses Sigstore for signing

      - name: Upload Attestation
        uses: actions/upload-artifact@v4
        with:
          name: attestation-bundle
          path: attestation.json`}</code>
                  </pre>
                </div>
              </div>

              {/* Example: PR blocking */}
              <div className="card p-6">
                <h3 className="text-h4 mb-4">Block PRs with Critical Findings</h3>
                <p className="text-text-secondary mb-4">
                  Configure branch protection to require passing security scans:
                </p>
                <div className="p-4 bg-bg-secondary rounded-lg">
                  <ol className="list-decimal list-inside text-text-secondary space-y-2">
                    <li>Go to repository Settings &rarr; Branches</li>
                    <li>Add or edit a branch protection rule for <code className="text-primary-400">main</code></li>
                    <li>Enable &quot;Require status checks to pass before merging&quot;</li>
                    <li>Search for and select &quot;Code Hardener Security Scan&quot;</li>
                    <li>Save changes</li>
                  </ol>
                </div>
              </div>
            </div>

            {/* Troubleshooting */}
            <div className="card p-6 mb-12">
              <h2 className="text-h3 mb-4">Troubleshooting</h2>
              <div className="space-y-4">
                <div>
                  <p className="font-medium text-text-primary mb-1">Action fails with authentication error</p>
                  <p className="text-sm text-text-secondary">
                    Verify your API key is correctly stored in repository secrets and the secret name matches your workflow configuration.
                  </p>
                </div>
                <div>
                  <p className="font-medium text-text-primary mb-1">SARIF upload fails</p>
                  <p className="text-sm text-text-secondary">
                    Ensure the workflow has <code className="text-primary-400">security-events: write</code> permission.
                  </p>
                </div>
                <div>
                  <p className="font-medium text-text-primary mb-1">Scan takes too long</p>
                  <p className="text-sm text-text-secondary">
                    Use the <code className="text-primary-400">ignore-paths</code> option to exclude test fixtures, generated code, or vendor directories.
                  </p>
                </div>
              </div>
            </div>

            {/* Related */}
            <div className="p-6 bg-bg-secondary rounded-xl border border-border-primary mb-12">
              <h2 className="text-h4 mb-4 flex items-center gap-2">
                <Info className="h-5 w-5 text-primary-400" aria-hidden="true" />
                Related Resources
              </h2>
              <ul className="space-y-2">
                <li>
                  <Link href="/docs/cli" className="text-primary-500 hover:text-primary-400">
                    CLI Reference &rarr;
                  </Link>
                </li>
                <li>
                  <Link href="/docs/api" className="text-primary-500 hover:text-primary-400">
                    API Documentation &rarr;
                  </Link>
                </li>
                <li>
                  <Link href="/blog/github-actions-security-pipeline" className="text-primary-500 hover:text-primary-400">
                    Tutorial: Complete Security Pipeline with GitHub Actions &rarr;
                  </Link>
                </li>
              </ul>
            </div>

            {/* Navigation */}
            <div className="mt-12 flex items-center justify-between pt-8 border-t border-border-primary">
              <Link
                href="/docs/integrations"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                All Integrations
              </Link>
              <Link
                href="/docs/integrations/gitlab-ci"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                GitLab CI
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
