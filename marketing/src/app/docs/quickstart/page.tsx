import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, Check, Copy, Terminal, Zap } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Quickstart',
  description: 'Get started with Code Hardener in under 5 minutes. Install the CLI and run your first security scan.',
};

const steps = [
  {
    number: 1,
    title: 'Install the CLI',
    description: 'Install the Code Hardener CLI using npm, Homebrew, or download the binary directly.',
    code: `# Using npm (recommended)
npm install -g @codehardener/cli

# Using Homebrew (macOS/Linux)
brew install codehardener/tap/hardener

# Using curl
curl -fsSL https://get.codehardener.com | sh`,
  },
  {
    number: 2,
    title: 'Authenticate',
    description: 'Log in to your Code Hardener account to connect the CLI.',
    code: `# Login with your account
hardener auth login

# Or use an API key
hardener auth login --api-key YOUR_API_KEY`,
  },
  {
    number: 3,
    title: 'Run your first scan',
    description: 'Navigate to your project directory and run a security scan.',
    code: `# Scan the current directory
hardener scan .

# Scan with specific tools
hardener scan . --tools opengrep,trivy,gitleaks

# Get JSON output
hardener scan . --format json --output results.json`,
  },
  {
    number: 4,
    title: 'View results',
    description: 'Review your scan results in the terminal or on the dashboard.',
    code: `# Open results in browser
hardener results --open

# Show summary
hardener results --summary

# Generate attestation
hardener attest --sign`,
  },
];

export default function QuickstartPage() {
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
                <li className="text-text-primary">Quickstart</li>
              </ol>
            </nav>

            {/* Header */}
            <div className="mb-12">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-success/10 text-success text-sm mb-4">
                <Zap className="h-4 w-4" aria-hidden="true" />
                5 minute setup
              </div>
              <h1 className="text-h1 mb-4">Quickstart Guide</h1>
              <p className="text-xl text-text-secondary">
                Get Code Hardener installed and run your first security scan in under 5 minutes.
              </p>
            </div>

            {/* Prerequisites */}
            <div className="card p-6 mb-12">
              <h2 className="text-h4 mb-4">Prerequisites</h2>
              <ul className="space-y-2">
                {[
                  'Node.js 18+ (for npm installation)',
                  'Git installed and configured',
                  'An Code Hardener account (free tier available)',
                ].map((item) => (
                  <li
                    key={item}
                    className="flex items-center gap-2 text-text-secondary"
                  >
                    <Check
                      className="h-4 w-4 text-success flex-shrink-0"
                      aria-hidden="true"
                    />
                    {item}
                  </li>
                ))}
              </ul>
            </div>

            {/* Steps */}
            <div className="space-y-12">
              {steps.map((step, index) => (
                <div key={step.number} className="relative">
                  {/* Connector line */}
                  {index < steps.length - 1 && (
                    <div className="absolute left-5 top-12 w-0.5 h-[calc(100%+1rem)] bg-border-primary" />
                  )}

                  <div className="flex gap-6">
                    {/* Step number */}
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center flex-shrink-0">
                      <span className="text-lg font-bold text-white">
                        {step.number}
                      </span>
                    </div>

                    {/* Content */}
                    <div className="flex-1 pb-8">
                      <h2 className="text-h3 mb-2">{step.title}</h2>
                      <p className="text-text-secondary mb-4">
                        {step.description}
                      </p>

                      {/* Code block */}
                      <div className="relative">
                        <div className="flex items-center justify-between px-4 py-2 bg-bg-tertiary rounded-t-lg border border-b-0 border-border-primary">
                          <div className="flex items-center gap-2 text-sm text-text-tertiary">
                            <Terminal className="h-4 w-4" aria-hidden="true" />
                            Terminal
                          </div>
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
                          <code className="text-sm text-[#c9d1d9] font-mono whitespace-pre">
                            {step.code}
                          </code>
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Next steps */}
            <div className="mt-12 p-6 bg-bg-secondary rounded-xl border border-border-primary">
              <h2 className="text-h3 mb-4">Next Steps</h2>
              <div className="grid sm:grid-cols-2 gap-4">
                {[
                  {
                    title: 'Integrate with CI/CD',
                    description: 'Add security scanning to your pipeline',
                    href: '/docs/integrations',
                  },
                  {
                    title: 'Configure policies',
                    description: 'Set up security policies for your team',
                    href: '/docs/policies',
                  },
                  {
                    title: 'Generate attestations',
                    description: 'Create cryptographic proof of scans',
                    href: '/docs/attestations',
                  },
                  {
                    title: 'API reference',
                    description: 'Build custom integrations',
                    href: '/docs/api',
                  },
                ].map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className="flex items-center justify-between p-4 rounded-lg bg-bg-tertiary hover:bg-bg-hover transition-colors group"
                  >
                    <div>
                      <p className="font-medium text-text-primary group-hover:text-primary-400 transition-colors">
                        {item.title}
                      </p>
                      <p className="text-sm text-text-secondary">
                        {item.description}
                      </p>
                    </div>
                    <ArrowRight
                      className="h-5 w-5 text-text-tertiary group-hover:text-primary-400 transition-colors"
                      aria-hidden="true"
                    />
                  </Link>
                ))}
              </div>
            </div>

            {/* Navigation */}
            <div className="mt-12 flex items-center justify-between pt-8 border-t border-border-primary">
              <Link
                href="/docs"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                Documentation
              </Link>
              <Link
                href="/docs/concepts"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                Key Concepts
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
