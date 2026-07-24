import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, Github, GitBranch, Code, Terminal, Cpu, Cloud, ArrowUpRight } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Integrations',
  description: 'Integrate Code Hardener with your development workflow. GitHub Actions, GitLab CI, VS Code, and more.',
};

const integrations = [
  {
    category: 'CI/CD',
    items: [
      {
        icon: Github,
        name: 'GitHub Actions',
        description: 'Add security scanning to your GitHub workflow',
        href: '/docs/integrations/github-actions',
        popular: true,
      },
      {
        icon: GitBranch,
        name: 'GitLab CI',
        description: 'Integrate with GitLab pipelines',
        href: '/docs/integrations/gitlab-ci',
        popular: true,
      },
      {
        icon: Cloud,
        name: 'Azure DevOps',
        description: 'Add to Azure Pipelines',
        href: '/docs/integrations/azure-devops',
        popular: false,
      },
      {
        icon: Terminal,
        name: 'Jenkins',
        description: 'Plugin for Jenkins pipelines',
        href: '/docs/integrations/jenkins',
        popular: false,
      },
      {
        icon: Cloud,
        name: 'CircleCI',
        description: 'Orb for CircleCI workflows',
        href: '/docs/integrations/circleci',
        popular: false,
      },
    ],
  },
  {
    category: 'AI Editors',
    items: [
      {
        icon: Cpu,
        name: 'Claude Code (MCP)',
        description: 'Real-time scanning in Claude Code',
        href: '/docs/mcp',
        popular: true,
      },
      {
        icon: Code,
        name: 'Cursor',
        description: 'Extension for Cursor IDE',
        href: '/docs/integrations/cursor',
        popular: true,
      },
      {
        icon: Github,
        name: 'GitHub Copilot',
        description: 'Companion for Copilot suggestions',
        href: '/docs/integrations/copilot',
        popular: false,
      },
    ],
  },
  {
    category: 'IDEs & Editors',
    items: [
      {
        icon: Code,
        name: 'VS Code',
        description: 'Extension for Visual Studio Code',
        href: '/docs/integrations/vscode',
        popular: true,
      },
      {
        icon: Code,
        name: 'JetBrains',
        description: 'Plugin for IntelliJ, WebStorm, etc.',
        href: '/docs/integrations/jetbrains',
        popular: false,
      },
      {
        icon: Terminal,
        name: 'Neovim',
        description: 'Lua plugin for Neovim',
        href: '/docs/integrations/neovim',
        popular: false,
      },
    ],
  },
  {
    category: 'Hosting & Deployment',
    items: [
      {
        icon: Cloud,
        name: 'Vercel',
        description: 'Pre-deployment security checks',
        href: '/docs/integrations/vercel',
        popular: true,
      },
      {
        icon: Cloud,
        name: 'Netlify',
        description: 'Build plugin for Netlify',
        href: '/docs/integrations/netlify',
        popular: false,
      },
      {
        icon: Cloud,
        name: 'AWS CodePipeline',
        description: 'Action for AWS pipelines',
        href: '/docs/integrations/aws-codepipeline',
        popular: false,
      },
    ],
  },
];

export default function IntegrationsPage() {
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
                <li className="text-text-primary">Integrations</li>
              </ol>
            </nav>

            {/* Header */}
            <div className="mb-12">
              <h1 className="text-h1 mb-4">Integrations</h1>
              <p className="text-xl text-text-secondary">
                Code Hardener integrates seamlessly with your existing development tools and workflows. Add security scanning wherever you write code.
              </p>
            </div>

            {/* Integration Categories */}
            <div className="space-y-12">
              {integrations.map((category) => (
                <div key={category.category}>
                  <h2 className="text-h3 mb-6">{category.category}</h2>
                  <div className="grid sm:grid-cols-2 gap-4">
                    {category.items.map((integration) => (
                      <Link
                        key={integration.name}
                        href={integration.href}
                        className="card-interactive p-5 group"
                      >
                        <div className="flex items-start gap-4">
                          <div className="w-10 h-10 rounded-lg bg-bg-tertiary flex items-center justify-center flex-shrink-0">
                            <integration.icon
                              className="h-5 w-5 text-text-secondary"
                              aria-hidden="true"
                            />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <h3 className="font-medium text-text-primary group-hover:text-primary-400 transition-colors">
                                {integration.name}
                              </h3>
                              {integration.popular && (
                                <span className="px-2 py-0.5 rounded-full bg-primary-500/10 text-primary-500 text-xs">
                                  Popular
                                </span>
                              )}
                            </div>
                            <p className="text-sm text-text-secondary mt-1">
                              {integration.description}
                            </p>
                          </div>
                          <ArrowUpRight
                            className="h-5 w-5 text-text-tertiary group-hover:text-primary-400 transition-colors flex-shrink-0"
                            aria-hidden="true"
                          />
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {/* GitHub Actions Quick Start */}
            <div className="card p-6 mt-12">
              <h2 className="text-h3 mb-4">Quick Start: GitHub Actions</h2>
              <p className="text-text-secondary mb-4">
                Add Code Hardener to your GitHub workflow in minutes:
              </p>
              <div className="relative">
                <pre className="p-4 bg-[#0d1117] rounded-lg border border-border-primary overflow-x-auto">
                  <code className="text-sm text-[#c9d1d9] font-mono whitespace-pre">{`# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Code Hardener Scan
        uses: codehardener/scan-action@v1
        with:
          api-key: \${{ secrets.AIHARDENER_API_KEY }}
          fail-on: high

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: codehardener-results.sarif`}</code>
                </pre>
              </div>
              <p className="text-sm text-text-secondary mt-4">
                <Link
                  href="/docs/integrations/github-actions"
                  className="text-primary-500 hover:text-primary-400"
                >
                  View full GitHub Actions documentation &rarr;
                </Link>
              </p>
            </div>

            {/* Request Integration */}
            <div className="mt-12 p-6 bg-bg-secondary rounded-xl border border-border-primary text-center">
              <h2 className="text-h4 mb-2">Missing an integration?</h2>
              <p className="text-text-secondary mb-4">
                Let us know what tools you&apos;d like us to support next.
              </p>
              <Link href="/contact" className="btn-secondary">
                Request Integration
              </Link>
            </div>

            {/* Navigation */}
            <div className="mt-12 flex items-center justify-between pt-8 border-t border-border-primary">
              <Link
                href="/docs/cli"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                CLI Reference
              </Link>
              <Link
                href="/docs/integrations/github-actions"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                GitHub Actions
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
