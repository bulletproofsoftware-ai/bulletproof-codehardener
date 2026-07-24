import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, Zap, Terminal, Check, Copy } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'MCP Integration',
  description: 'Integrate Code Hardener with Claude Code using the Model Context Protocol (MCP) for real-time security scanning.',
};

export default function McpPage() {
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
                <li className="text-text-primary">MCP</li>
              </ol>
            </nav>

            {/* Header */}
            <div className="mb-12">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 text-primary-500 text-sm mb-4">
                <Zap className="h-4 w-4" aria-hidden="true" />
                New Feature
              </div>
              <h1 className="text-h1 mb-4">MCP Integration for Claude Code</h1>
              <p className="text-xl text-text-secondary">
                Run Code Hardener security scans directly from Claude Code using the Model Context Protocol. Get real-time security feedback while you code.
              </p>
            </div>

            {/* Benefits */}
            <div className="grid sm:grid-cols-3 gap-4 mb-12">
              {[
                { title: 'Real-time scanning', description: 'Scan code as Claude generates it' },
                { title: 'Context-aware', description: 'Claude understands your security findings' },
                { title: 'Auto-remediation', description: 'Get fix suggestions inline' },
              ].map((benefit) => (
                <div key={benefit.title} className="card p-4">
                  <p className="font-medium text-text-primary mb-1">{benefit.title}</p>
                  <p className="text-sm text-text-secondary">{benefit.description}</p>
                </div>
              ))}
            </div>

            {/* Prerequisites */}
            <div className="card p-6 mb-12">
              <h2 className="text-h4 mb-4">Prerequisites</h2>
              <ul className="space-y-2">
                {[
                  'Claude Code (Anthropic\'s code assistant)',
                  'Code Hardener account with API key',
                  'Node.js 18+ installed',
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

            {/* Installation */}
            <div className="space-y-8 mb-12">
              <h2 className="text-h2">Installation</h2>

              {/* Step 1 */}
              <div className="card p-6">
                <h3 className="text-h4 mb-4">1. Install the MCP Server</h3>
                <p className="text-text-secondary mb-4">
                  Install the Code Hardener MCP server globally:
                </p>
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
                    <code className="text-sm text-[#c9d1d9] font-mono">npm install -g @codehardener/mcp-server</code>
                  </pre>
                </div>
              </div>

              {/* Step 2 */}
              <div className="card p-6">
                <h3 className="text-h4 mb-4">2. Configure Claude Code</h3>
                <p className="text-text-secondary mb-4">
                  Add the Code Hardener MCP server to your Claude Code configuration. Create or update{' '}
                  <code className="text-primary-400">~/.claude/mcp.json</code>:
                </p>
                <div className="relative">
                  <div className="flex items-center justify-between px-4 py-2 bg-bg-tertiary rounded-t-lg border border-b-0 border-border-primary">
                    <div className="flex items-center gap-2 text-sm text-text-tertiary">
                      mcp.json
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
                    <code className="text-sm text-[#c9d1d9] font-mono whitespace-pre">{`{
  "mcpServers": {
    "codehardener": {
      "command": "codehardener-mcp",
      "env": {
        "AIHARDENER_API_KEY": "your-api-key-here"
      }
    }
  }
}`}</code>
                  </pre>
                </div>
              </div>

              {/* Step 3 */}
              <div className="card p-6">
                <h3 className="text-h4 mb-4">3. Restart Claude Code</h3>
                <p className="text-text-secondary mb-4">
                  Restart Claude Code to load the new MCP server. You should see &quot;Code Hardener&quot; in your available tools.
                </p>
              </div>
            </div>

            {/* Usage */}
            <div className="space-y-8 mb-12">
              <h2 className="text-h2">Usage</h2>

              <div className="card p-6">
                <h3 className="text-h4 mb-4">Available Commands</h3>
                <p className="text-text-secondary mb-4">
                  Once configured, you can use the following commands in Claude Code:
                </p>
                <div className="space-y-4">
                  <div className="p-4 bg-bg-tertiary rounded-lg">
                    <p className="font-mono text-primary-400 mb-2">@codehardener scan</p>
                    <p className="text-sm text-text-secondary">
                      Scan the current file or selection for security issues
                    </p>
                  </div>
                  <div className="p-4 bg-bg-tertiary rounded-lg">
                    <p className="font-mono text-primary-400 mb-2">@codehardener scan-project</p>
                    <p className="text-sm text-text-secondary">
                      Scan the entire project directory
                    </p>
                  </div>
                  <div className="p-4 bg-bg-tertiary rounded-lg">
                    <p className="font-mono text-primary-400 mb-2">@codehardener explain [finding-id]</p>
                    <p className="text-sm text-text-secondary">
                      Get a detailed explanation of a specific finding
                    </p>
                  </div>
                  <div className="p-4 bg-bg-tertiary rounded-lg">
                    <p className="font-mono text-primary-400 mb-2">@codehardener fix [finding-id]</p>
                    <p className="text-sm text-text-secondary">
                      Get AI-generated fix suggestions for a finding
                    </p>
                  </div>
                  <div className="p-4 bg-bg-tertiary rounded-lg">
                    <p className="font-mono text-primary-400 mb-2">@codehardener attest</p>
                    <p className="text-sm text-text-secondary">
                      Generate a signed attestation for the current project
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Example */}
            <div className="card p-6 mb-12">
              <h2 className="text-h4 mb-4">Example Workflow</h2>
              <p className="text-text-secondary mb-4">
                Here&apos;s a typical workflow using Code Hardener with Claude Code:
              </p>
              <div className="relative">
                <pre className="p-4 bg-[#0d1117] rounded-lg border border-border-primary overflow-x-auto">
                  <code className="text-sm text-[#c9d1d9] font-mono whitespace-pre">{`You: Write a function to authenticate users with a database

Claude: [generates code with potential SQL injection]

You: @codehardener scan

Code Hardener: Found 1 critical issue:
  - SQL Injection (CWE-89) at line 12
    User input directly concatenated into SQL query

You: @codehardener fix sql-injection-1

Code Hardener: Suggested fix:
  Replace string concatenation with parameterized queries.
  [Shows diff with fix applied]

Claude: I'll update the code with parameterized queries...
  [generates secure version]

You: @codehardener scan

Code Hardener: No security issues found. Ready for attestation.

You: @codehardener attest

Code Hardener: Attestation generated:
  Bundle ID: att-abc123
  Signed with Sigstore
  View: https://app.codehardener.com/attestations/att-abc123`}</code>
                </pre>
              </div>
            </div>

            {/* Troubleshooting */}
            <div className="card p-6 mb-12">
              <h2 className="text-h4 mb-4">Troubleshooting</h2>
              <div className="space-y-4">
                <div>
                  <p className="font-medium text-text-primary mb-1">
                    MCP server not appearing in Claude Code
                  </p>
                  <p className="text-sm text-text-secondary">
                    Ensure the mcp.json file is correctly formatted and the API key is valid. Try running{' '}
                    <code className="text-primary-400">codehardener-mcp --version</code> to verify installation.
                  </p>
                </div>
                <div>
                  <p className="font-medium text-text-primary mb-1">
                    Authentication errors
                  </p>
                  <p className="text-sm text-text-secondary">
                    Generate a new API key from your{' '}
                    <Link href="/dashboard/settings/api-keys" className="text-primary-500 hover:text-primary-400">
                      dashboard settings
                    </Link>{' '}
                    and update your mcp.json.
                  </p>
                </div>
                <div>
                  <p className="font-medium text-text-primary mb-1">
                    Slow scans
                  </p>
                  <p className="text-sm text-text-secondary">
                    Large projects may take longer to scan. Use{' '}
                    <code className="text-primary-400">@codehardener scan</code> for quick file scans.
                  </p>
                </div>
              </div>
            </div>

            {/* Navigation */}
            <div className="mt-12 flex items-center justify-between pt-8 border-t border-border-primary">
              <Link
                href="/docs/integrations"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                Integrations
              </Link>
              <Link
                href="/docs/cli"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                CLI Reference
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
