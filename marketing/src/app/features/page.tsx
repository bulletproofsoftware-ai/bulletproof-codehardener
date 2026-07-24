import Link from 'next/link';
import { Metadata } from 'next';
import {
  Lock,
  Code,
  FileCheck,
  Terminal,
  Zap,
  Globe,
  Key,
  Container,
  GitBranch,
  MessageSquare,
  ArrowRight,
  Check,
} from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Features',
  description:
    'Explore Code Hardener features: 27 security tools, plain-language findings, cryptographic attestation, and seamless AI tool integration.',
};

const securityTools = [
  {
    category: 'Static Analysis (SAST)',
    icon: Code,
    tools: ['Opengrep', 'Bandit', 'Gosec', 'ESLint Security', 'PMD'],
    description: 'Find vulnerabilities in source code before they reach production',
  },
  {
    category: 'Dynamic Analysis (DAST)',
    icon: Globe,
    tools: ['OWASP ZAP', 'Nuclei'],
    description: 'Test running applications for security weaknesses',
  },
  {
    category: 'Dependency Scanning (SCA)',
    icon: GitBranch,
    tools: ['Trivy', 'Grype'],
    description: 'Identify vulnerable dependencies in your supply chain',
  },
  {
    category: 'Secret Detection',
    icon: Key,
    tools: ['Gitleaks', 'detect-secrets'],
    description: 'Prevent API keys and credentials from leaking',
  },
  {
    category: 'Container Security',
    icon: Container,
    tools: ['Trivy', 'Grype', 'Syft'],
    description: 'Scan container images for vulnerabilities',
  },
  {
    category: 'Infrastructure as Code',
    icon: FileCheck,
    tools: ['Checkov'],
    description: 'Validate Terraform, Kubernetes, and cloud configs',
  },
];

const coreFeatures = [
  {
    title: 'Plain Language Findings',
    icon: MessageSquare,
    description:
      'Every vulnerability is translated from CVE-speak into clear, actionable language. No more Googling cryptic error codes.',
    benefits: [
      'Human-readable vulnerability descriptions',
      'Step-by-step remediation guidance',
      'Code snippets showing exactly what to fix',
      'Severity context for prioritization',
    ],
  },
  {
    title: 'Cryptographic Attestation',
    icon: Lock,
    description:
      'Get Sigstore-signed attestations for every scan. Prove to auditors exactly when and how your code was verified.',
    benefits: [
      'Sigstore-signed security attestations',
      'VEX (Vulnerability Exploitability eXchange)',
      'SBOM generation and verification',
      'Audit trail for compliance',
    ],
  },
  {
    title: 'AI Tool Integration',
    icon: Terminal,
    description:
      'Native support for the AI coding tools you already use. One command, one prompt, one connection.',
    benefits: [
      'MCP server for Claude Code',
      'Cursor integration',
      'GitHub Copilot compatibility',
      'REST API for any tool',
    ],
  },
  {
    title: 'Blazing Fast',
    icon: Zap,
    description:
      'Parallel scanning across all 27 tools means results in seconds, not minutes. Ship faster without waiting.',
    benefits: [
      'Parallel tool execution',
      'Incremental scanning for changed files',
      'Cached results for repeated scans',
      'Real-time progress streaming',
    ],
  },
];

export default function FeaturesPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="pt-16">
        {/* Hero */}
        <section className="section bg-hero-gradient bg-grid-pattern">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mx-auto text-center">
              <h1 className="text-h1 mb-6">
                27 Security Tools.{' '}
                <span className="text-gradient">One Platform.</span>
              </h1>
              <p className="text-xl text-text-secondary mb-10">
                From SAST to SBOM, container scanning to secret detection. AI
                Hardener unifies the best open-source security tools into a
                single, developer-friendly experience.
              </p>
              <Link href="/signup" className="btn-primary">
                Start Free
                <ArrowRight className="h-5 w-5" aria-hidden="true" />
              </Link>
            </div>
          </div>
        </section>

        {/* Security Tools Grid */}
        <section className="section">
          <div className="container mx-auto px-6">
            <div className="text-center mb-16">
              <h2 className="text-h2 mb-4">Comprehensive Security Coverage</h2>
              <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                We orchestrate 27 industry-leading security tools so you do not
                have to configure them yourself.
              </p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
              {securityTools.map((category) => (
                <div key={category.category} className="card p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary-500/20 to-accent-500/20 flex items-center justify-center">
                      <category.icon
                        className="h-5 w-5 text-primary-400"
                        aria-hidden="true"
                      />
                    </div>
                    <h3 className="text-h4">{category.category}</h3>
                  </div>
                  <p className="text-text-secondary mb-4">{category.description}</p>
                  <div className="flex flex-wrap gap-2">
                    {category.tools.map((tool) => (
                      <span
                        key={tool}
                        className="px-2 py-1 text-xs rounded bg-bg-tertiary text-text-secondary"
                      >
                        {tool}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Core Features */}
        <section className="section bg-bg-secondary border-y border-border-primary">
          <div className="container mx-auto px-6">
            <div className="text-center mb-16">
              <h2 className="text-h2 mb-4">Built for Developers</h2>
              <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                Security tools are useless if they slow you down. Code Hardener is
                designed to fit your workflow, not fight it.
              </p>
            </div>

            <div className="space-y-16">
              {coreFeatures.map((feature, index) => (
                <div
                  key={feature.title}
                  className={`flex flex-col ${
                    index % 2 === 1 ? 'lg:flex-row-reverse' : 'lg:flex-row'
                  } gap-12 items-center`}
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-primary-500/20 to-accent-500/20 flex items-center justify-center">
                        <feature.icon
                          className="h-6 w-6 text-primary-400"
                          aria-hidden="true"
                        />
                      </div>
                      <h3 className="text-h3">{feature.title}</h3>
                    </div>
                    <p className="text-lg text-text-secondary mb-6">
                      {feature.description}
                    </p>
                    <ul className="space-y-3">
                      {feature.benefits.map((benefit) => (
                        <li key={benefit} className="flex items-start gap-3">
                          <Check
                            className="h-5 w-5 text-success mt-0.5 shrink-0"
                            aria-hidden="true"
                          />
                          <span className="text-text-primary">{benefit}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="flex-1">
                    <div className="card p-8 bg-bg-tertiary aspect-video flex items-center justify-center">
                      <feature.icon
                        className="h-24 w-24 text-primary-500/30"
                        aria-hidden="true"
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="section">
          <div className="container mx-auto px-6">
            <div className="card p-12 text-center bg-gradient-to-r from-primary-500/10 to-accent-500/10 border-primary-500/20">
              <h2 className="text-h2 mb-4">Ready to secure your code?</h2>
              <p className="text-lg text-text-secondary mb-8 max-w-xl mx-auto">
                Start with 3 free projects and 200 scans per month. No credit card
                required.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <Link href="/signup" className="btn-primary">
                  Start Free
                  <ArrowRight className="h-5 w-5" aria-hidden="true" />
                </Link>
                <Link href="/docs" className="btn-secondary">
                  Read the Docs
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}
