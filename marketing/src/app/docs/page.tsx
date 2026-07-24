import type { Metadata } from 'next';
import Link from 'next/link';
import {
  Book,
  Rocket,
  Code,
  Terminal,
  Plug,
  Shield,
  FileCode,
  Key,
  ArrowRight,
  Search,
} from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Documentation',
  description: 'Code Hardener documentation. Learn how to integrate security scanning into your development workflow.',
};

const quickLinks = [
  {
    icon: Rocket,
    title: 'Quickstart',
    description: 'Get up and running in under 5 minutes',
    href: '/docs/quickstart',
  },
  {
    icon: Code,
    title: 'API Reference',
    description: 'Complete REST API documentation',
    href: '/docs/api',
  },
  {
    icon: Terminal,
    title: 'CLI Reference',
    description: 'Command-line interface documentation',
    href: '/docs/cli',
  },
  {
    icon: Plug,
    title: 'Integrations',
    description: 'Connect with your existing tools',
    href: '/docs/integrations',
  },
];

const sections = [
  {
    title: 'Getting Started',
    description: 'New to Code Hardener? Start here.',
    links: [
      { title: 'Introduction', href: '/docs/introduction' },
      { title: 'Quickstart Guide', href: '/docs/quickstart' },
      { title: 'Key Concepts', href: '/docs/concepts' },
      { title: 'Your First Scan', href: '/docs/first-scan' },
    ],
  },
  {
    title: 'Integrations',
    description: 'Connect Code Hardener to your workflow.',
    links: [
      { title: 'GitHub Actions', href: '/docs/integrations/github-actions' },
      { title: 'GitLab CI', href: '/docs/integrations/gitlab-ci' },
      { title: 'VS Code Extension', href: '/docs/integrations/vscode' },
      { title: 'MCP for Claude Code', href: '/docs/mcp' },
    ],
  },
  {
    title: 'API & CLI',
    description: 'Programmatic access to Code Hardener.',
    links: [
      { title: 'API Overview', href: '/docs/api' },
      { title: 'Authentication', href: '/docs/api/authentication' },
      { title: 'CLI Installation', href: '/docs/cli' },
      { title: 'CLI Commands', href: '/docs/cli/commands' },
    ],
  },
  {
    title: 'Security & Compliance',
    description: 'Security features and compliance info.',
    links: [
      { title: 'Attestations', href: '/docs/attestations' },
      { title: 'SBOM Generation', href: '/docs/sbom' },
      { title: 'Policy Configuration', href: '/docs/policies' },
      { title: 'Compliance Reports', href: '/docs/compliance' },
    ],
  },
];

const popularTopics = [
  { icon: Shield, title: 'Attestations', href: '/docs/attestations' },
  { icon: FileCode, title: 'SBOM', href: '/docs/sbom' },
  { icon: Key, title: 'API Keys', href: '/docs/api/keys' },
  { icon: Plug, title: 'MCP Integration', href: '/docs/mcp' },
];

export default function DocsPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="pt-32 pb-16">
        <div className="container mx-auto px-6">
          {/* Header */}
          <div className="max-w-3xl mx-auto text-center mb-16">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-bg-secondary border border-border-primary mb-6">
              <Book className="h-4 w-4 text-primary-500" aria-hidden="true" />
              <span className="text-sm text-text-secondary">Documentation</span>
            </div>
            <h1 className="text-h1 mb-6">How can we help?</h1>
            <p className="text-xl text-text-secondary mb-8">
              Everything you need to integrate Code Hardener into your development workflow.
            </p>

            {/* Search */}
            <div className="relative max-w-xl mx-auto">
              <Search
                className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-text-tertiary"
                aria-hidden="true"
              />
              <input
                type="search"
                placeholder="Search documentation..."
                className="input pl-12"
                aria-label="Search documentation"
              />
              <kbd className="absolute right-4 top-1/2 -translate-y-1/2 hidden sm:inline-flex items-center gap-1 px-2 py-1 text-xs text-text-tertiary bg-bg-tertiary rounded border border-border-primary">
                <span>Ctrl</span>
                <span>K</span>
              </kbd>
            </div>
          </div>

          {/* Quick Links */}
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4 mb-16">
            {quickLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="card-interactive p-6 group"
              >
                <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary-500/20 to-accent-500/20 flex items-center justify-center mb-4">
                  <link.icon
                    className="h-5 w-5 text-primary-400"
                    aria-hidden="true"
                  />
                </div>
                <h2 className="text-h4 mb-1 group-hover:text-primary-400 transition-colors">
                  {link.title}
                </h2>
                <p className="text-sm text-text-secondary">{link.description}</p>
              </Link>
            ))}
          </div>

          {/* Sections Grid */}
          <div className="grid md:grid-cols-2 gap-8 mb-16">
            {sections.map((section) => (
              <div key={section.title} className="card p-6">
                <h2 className="text-h4 mb-2">{section.title}</h2>
                <p className="text-sm text-text-secondary mb-4">
                  {section.description}
                </p>
                <ul className="space-y-2">
                  {section.links.map((link) => (
                    <li key={link.href}>
                      <Link
                        href={link.href}
                        className="flex items-center gap-2 text-text-secondary hover:text-primary-400 transition-colors group"
                      >
                        <ArrowRight
                          className="h-4 w-4 text-text-tertiary group-hover:text-primary-400 transition-colors"
                          aria-hidden="true"
                        />
                        {link.title}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Popular Topics */}
          <div className="max-w-3xl mx-auto">
            <h2 className="text-h3 text-center mb-8">Popular Topics</h2>
            <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-4">
              {popularTopics.map((topic) => (
                <Link
                  key={topic.href}
                  href={topic.href}
                  className="flex items-center gap-3 p-4 rounded-lg bg-bg-secondary border border-border-primary hover:border-primary-500/50 transition-colors group"
                >
                  <topic.icon
                    className="h-5 w-5 text-text-tertiary group-hover:text-primary-400 transition-colors"
                    aria-hidden="true"
                  />
                  <span className="text-text-secondary group-hover:text-text-primary transition-colors">
                    {topic.title}
                  </span>
                </Link>
              ))}
            </div>
          </div>

          {/* Help CTA */}
          <div className="mt-16 text-center">
            <p className="text-text-secondary mb-4">
              Can&apos;t find what you&apos;re looking for?
            </p>
            <div className="flex items-center justify-center gap-4">
              <Link href="/contact" className="btn-secondary">
                Contact Support
              </Link>
              <a
                href="https://github.com/codehardener/codehardener/discussions"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-ghost"
              >
                Community Forum
              </a>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
