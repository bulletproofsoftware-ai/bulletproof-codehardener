import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, Terminal, Download, Copy } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'CLI Reference',
  description: 'Code Hardener command-line interface documentation. Installation, commands, and usage examples.',
};

const commands = [
  {
    name: 'auth',
    description: 'Authentication commands',
    subcommands: [
      { name: 'auth login', description: 'Authenticate with Code Hardener', usage: 'hardener auth login [--api-key KEY]' },
      { name: 'auth logout', description: 'Log out and clear credentials', usage: 'hardener auth logout' },
      { name: 'auth status', description: 'Show current authentication status', usage: 'hardener auth status' },
    ],
  },
  {
    name: 'scan',
    description: 'Security scanning commands',
    subcommands: [
      { name: 'scan', description: 'Run a security scan on a directory or file', usage: 'hardener scan [path] [options]' },
      { name: 'scan --tools', description: 'Specify which tools to run', usage: 'hardener scan . --tools opengrep,trivy' },
      { name: 'scan --format', description: 'Set output format (text, json, sarif)', usage: 'hardener scan . --format json' },
      { name: 'scan --output', description: 'Write results to a file', usage: 'hardener scan . --output results.json' },
    ],
  },
  {
    name: 'results',
    description: 'View and manage scan results',
    subcommands: [
      { name: 'results', description: 'Show recent scan results', usage: 'hardener results [scan-id]' },
      { name: 'results --open', description: 'Open results in browser', usage: 'hardener results --open' },
      { name: 'results --summary', description: 'Show summary only', usage: 'hardener results --summary' },
    ],
  },
  {
    name: 'attest',
    description: 'Generate attestations',
    subcommands: [
      { name: 'attest', description: 'Generate attestation for last scan', usage: 'hardener attest [options]' },
      { name: 'attest --sign', description: 'Sign attestation with Sigstore', usage: 'hardener attest --sign' },
      { name: 'attest --output', description: 'Save attestation bundle', usage: 'hardener attest --output bundle.json' },
    ],
  },
  {
    name: 'project',
    description: 'Project management commands',
    subcommands: [
      { name: 'project list', description: 'List all projects', usage: 'hardener project list' },
      { name: 'project create', description: 'Create a new project', usage: 'hardener project create [name]' },
      { name: 'project link', description: 'Link current directory to a project', usage: 'hardener project link [project-id]' },
    ],
  },
  {
    name: 'policy',
    description: 'Security policy commands',
    subcommands: [
      { name: 'policy list', description: 'List available policies', usage: 'hardener policy list' },
      { name: 'policy check', description: 'Check scan against policies', usage: 'hardener policy check [scan-id]' },
      { name: 'policy export', description: 'Export policy configuration', usage: 'hardener policy export [policy-id]' },
    ],
  },
];

export default function CliReferencePage() {
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
                <li className="text-text-primary">CLI Reference</li>
              </ol>
            </nav>

            {/* Header */}
            <div className="mb-12">
              <h1 className="text-h1 mb-4">CLI Reference</h1>
              <p className="text-xl text-text-secondary">
                The Code Hardener CLI provides a powerful command-line interface for running security scans, generating attestations, and integrating with your development workflow.
              </p>
            </div>

            {/* Installation */}
            <div className="card p-6 mb-12">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-h3 flex items-center gap-2">
                  <Download className="h-6 w-6 text-primary-400" aria-hidden="true" />
                  Installation
                </h2>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-text-secondary mb-2">Using npm (recommended)</p>
                  <div className="relative">
                    <pre className="p-4 bg-[#0d1117] rounded-lg border border-border-primary">
                      <code className="text-sm text-[#c9d1d9] font-mono">npm install -g @codehardener/cli</code>
                    </pre>
                    <button
                      type="button"
                      className="absolute right-3 top-3 p-1 text-text-tertiary hover:text-text-primary transition-colors"
                      aria-label="Copy code"
                    >
                      <Copy className="h-4 w-4" aria-hidden="true" />
                    </button>
                  </div>
                </div>
                <div>
                  <p className="text-sm text-text-secondary mb-2">Using Homebrew (macOS/Linux)</p>
                  <div className="relative">
                    <pre className="p-4 bg-[#0d1117] rounded-lg border border-border-primary">
                      <code className="text-sm text-[#c9d1d9] font-mono">brew install codehardener/tap/hardener</code>
                    </pre>
                    <button
                      type="button"
                      className="absolute right-3 top-3 p-1 text-text-tertiary hover:text-text-primary transition-colors"
                      aria-label="Copy code"
                    >
                      <Copy className="h-4 w-4" aria-hidden="true" />
                    </button>
                  </div>
                </div>
                <div>
                  <p className="text-sm text-text-secondary mb-2">Direct download</p>
                  <div className="flex flex-wrap gap-2">
                    <a
                      href="#"
                      className="inline-flex items-center gap-2 px-4 py-2 bg-bg-tertiary rounded-lg text-sm text-text-secondary hover:text-text-primary hover:bg-bg-hover transition-colors"
                    >
                      <Download className="h-4 w-4" aria-hidden="true" />
                      macOS (Intel)
                    </a>
                    <a
                      href="#"
                      className="inline-flex items-center gap-2 px-4 py-2 bg-bg-tertiary rounded-lg text-sm text-text-secondary hover:text-text-primary hover:bg-bg-hover transition-colors"
                    >
                      <Download className="h-4 w-4" aria-hidden="true" />
                      macOS (Apple Silicon)
                    </a>
                    <a
                      href="#"
                      className="inline-flex items-center gap-2 px-4 py-2 bg-bg-tertiary rounded-lg text-sm text-text-secondary hover:text-text-primary hover:bg-bg-hover transition-colors"
                    >
                      <Download className="h-4 w-4" aria-hidden="true" />
                      Linux (x64)
                    </a>
                    <a
                      href="#"
                      className="inline-flex items-center gap-2 px-4 py-2 bg-bg-tertiary rounded-lg text-sm text-text-secondary hover:text-text-primary hover:bg-bg-hover transition-colors"
                    >
                      <Download className="h-4 w-4" aria-hidden="true" />
                      Windows (x64)
                    </a>
                  </div>
                </div>
              </div>
            </div>

            {/* Commands */}
            <div className="space-y-8">
              <h2 className="text-h2">Commands</h2>

              {commands.map((category) => (
                <div key={category.name} className="card overflow-hidden">
                  <div className="px-6 py-4 bg-bg-tertiary border-b border-border-primary">
                    <h3 className="text-h4 flex items-center gap-2">
                      <Terminal className="h-5 w-5 text-primary-400" aria-hidden="true" />
                      {category.name}
                    </h3>
                    <p className="text-sm text-text-secondary mt-1">
                      {category.description}
                    </p>
                  </div>
                  <div className="divide-y divide-border-primary">
                    {category.subcommands.map((cmd) => (
                      <div key={cmd.name} className="px-6 py-4">
                        <div className="flex items-start justify-between gap-4">
                          <div>
                            <code className="text-primary-400 font-mono text-sm">
                              {cmd.name}
                            </code>
                            <p className="text-sm text-text-secondary mt-1">
                              {cmd.description}
                            </p>
                          </div>
                        </div>
                        <div className="mt-3 relative">
                          <pre className="p-3 bg-[#0d1117] rounded-lg border border-border-primary text-sm overflow-x-auto">
                            <code className="text-[#c9d1d9] font-mono">{cmd.usage}</code>
                          </pre>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {/* Global Options */}
            <div className="card p-6 mt-12">
              <h2 className="text-h3 mb-4">Global Options</h2>
              <div className="space-y-4">
                {[
                  { flag: '--help, -h', description: 'Show help for any command' },
                  { flag: '--version, -v', description: 'Show CLI version' },
                  { flag: '--verbose', description: 'Enable verbose output' },
                  { flag: '--quiet, -q', description: 'Suppress non-essential output' },
                  { flag: '--config', description: 'Path to config file (default: .hardener.yml)' },
                  { flag: '--no-color', description: 'Disable colored output' },
                ].map((option) => (
                  <div key={option.flag} className="flex items-start gap-4">
                    <code className="text-primary-400 font-mono text-sm whitespace-nowrap">
                      {option.flag}
                    </code>
                    <p className="text-sm text-text-secondary">{option.description}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Configuration */}
            <div className="card p-6 mt-8">
              <h2 className="text-h3 mb-4">Configuration File</h2>
              <p className="text-text-secondary mb-4">
                Create a <code className="text-primary-400">.hardener.yml</code> file in your project root:
              </p>
              <div className="relative">
                <pre className="p-4 bg-[#0d1117] rounded-lg border border-border-primary overflow-x-auto">
                  <code className="text-sm text-[#c9d1d9] font-mono whitespace-pre">{`# .hardener.yml
project: my-project

scan:
  tools:
    - opengrep
    - trivy
    - gitleaks
  ignore:
    - node_modules/
    - .git/
    - "*.test.js"

policies:
  - name: production
    severity_threshold: medium
    fail_on_findings: true

attestation:
  auto_sign: true
  include_sbom: true`}</code>
                </pre>
              </div>
            </div>

            {/* Navigation */}
            <div className="mt-12 flex items-center justify-between pt-8 border-t border-border-primary">
              <Link
                href="/docs/api"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                API Reference
              </Link>
              <Link
                href="/docs/integrations"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                Integrations
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
