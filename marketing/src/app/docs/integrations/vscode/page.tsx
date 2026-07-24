import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, Code, Download } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'VS Code Extension',
  description: 'Code Hardener extension for Visual Studio Code. Real-time security feedback as you code.',
};

export default function VSCodePage() {
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
                  <Link href="/docs" className="text-text-secondary hover:text-text-primary transition-colors">Docs</Link>
                </li>
                <li className="text-text-tertiary">/</li>
                <li>
                  <Link href="/docs/integrations" className="text-text-secondary hover:text-text-primary transition-colors">Integrations</Link>
                </li>
                <li className="text-text-tertiary">/</li>
                <li className="text-text-primary">VS Code</li>
              </ol>
            </nav>

            {/* Header */}
            <div className="mb-12">
              <div className="flex items-center gap-4 mb-4">
                <div className="w-12 h-12 rounded-lg bg-[#007ACC] flex items-center justify-center">
                  <Code className="h-6 w-6 text-white" aria-hidden="true" />
                </div>
                <span className="px-2 py-0.5 rounded-full bg-primary-500/10 text-primary-500 text-xs font-medium">Popular</span>
              </div>
              <h1 className="text-h1 mb-4">VS Code Extension</h1>
              <p className="text-xl text-text-secondary">
                Get real-time security feedback directly in Visual Studio Code. See vulnerabilities inline, get quick fixes, and scan your entire workspace.
              </p>
            </div>

            {/* Install Button */}
            <div className="card p-6 mb-12">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <h2 className="text-h4 mb-2">Install from Marketplace</h2>
                  <p className="text-text-secondary">Version 1.2.0 | 50k+ installs | 4.8 stars</p>
                </div>
                <a
                  href="vscode:extension/codehardener.vscode-codehardener"
                  className="btn-primary"
                >
                  <Download className="h-5 w-5" aria-hidden="true" />
                  Install Extension
                </a>
              </div>
            </div>

            {/* Features */}
            <div className="mb-12">
              <h2 className="text-h2 mb-6">Features</h2>
              <div className="grid sm:grid-cols-2 gap-4">
                {[
                  { title: 'Inline Diagnostics', description: 'Security issues appear as squiggly underlines with hover details' },
                  { title: 'Quick Fixes', description: 'Apply suggested fixes with a single click or keyboard shortcut' },
                  { title: 'Workspace Scanning', description: 'Scan your entire project from the command palette' },
                  { title: 'Problems Panel', description: 'View all findings in the standard VS Code problems panel' },
                  { title: 'Status Bar', description: 'See scan status and finding counts at a glance' },
                  { title: 'Git Integration', description: 'Automatically scan changed files on save' },
                ].map((feature) => (
                  <div key={feature.title} className="card p-4">
                    <h3 className="font-medium text-text-primary mb-1">{feature.title}</h3>
                    <p className="text-sm text-text-secondary">{feature.description}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Setup */}
            <div className="space-y-8 mb-12">
              <h2 className="text-h2">Setup</h2>

              <div className="card p-6">
                <h3 className="text-h4 mb-4 flex items-center gap-3">
                  <span className="w-8 h-8 rounded-full bg-primary-500 text-white flex items-center justify-center text-sm font-bold">1</span>
                  Install the extension
                </h3>
                <p className="text-text-secondary mb-4">
                  Install from the VS Code Marketplace or search for &quot;Code Hardener&quot; in the Extensions view (<kbd className="px-2 py-1 bg-bg-tertiary rounded text-xs">Ctrl+Shift+X</kbd>).
                </p>
              </div>

              <div className="card p-6">
                <h3 className="text-h4 mb-4 flex items-center gap-3">
                  <span className="w-8 h-8 rounded-full bg-primary-500 text-white flex items-center justify-center text-sm font-bold">2</span>
                  Configure API key
                </h3>
                <p className="text-text-secondary mb-4">
                  Open Settings (<kbd className="px-2 py-1 bg-bg-tertiary rounded text-xs">Ctrl+,</kbd>) and search for &quot;Code Hardener&quot;. Enter your API key in the <code className="text-primary-400">codehardener.apiKey</code> setting.
                </p>
                <div className="p-4 bg-bg-secondary rounded-lg">
                  <p className="text-sm text-text-tertiary mb-2">settings.json</p>
                  <pre className="text-sm text-[#c9d1d9] font-mono">
{`{
  "codehardener.apiKey": "your-api-key-here",
  "codehardener.scanOnSave": true,
  "codehardener.severityThreshold": "low"
}`}
                  </pre>
                </div>
              </div>

              <div className="card p-6">
                <h3 className="text-h4 mb-4 flex items-center gap-3">
                  <span className="w-8 h-8 rounded-full bg-primary-500 text-white flex items-center justify-center text-sm font-bold">3</span>
                  Start scanning
                </h3>
                <p className="text-text-secondary">
                  Open a file and save it to trigger a scan, or use the command palette (<kbd className="px-2 py-1 bg-bg-tertiary rounded text-xs">Ctrl+Shift+P</kbd>) and run &quot;Code Hardener: Scan Current File&quot; or &quot;Code Hardener: Scan Workspace&quot;.
                </p>
              </div>
            </div>

            {/* Commands */}
            <div className="mb-12">
              <h2 className="text-h2 mb-6">Commands</h2>
              <div className="card overflow-hidden">
                <table className="w-full">
                  <thead>
                    <tr className="bg-bg-tertiary border-b border-border-primary">
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Command</th>
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-primary">
                    {[
                      { command: 'Code Hardener: Scan Current File', description: 'Scan the currently open file' },
                      { command: 'Code Hardener: Scan Workspace', description: 'Scan all files in the workspace' },
                      { command: 'Code Hardener: Show Results', description: 'Open the Code Hardener results panel' },
                      { command: 'Code Hardener: Clear Results', description: 'Clear all current findings' },
                      { command: 'Code Hardener: Generate Attestation', description: 'Generate attestation for current workspace' },
                    ].map((cmd) => (
                      <tr key={cmd.command}>
                        <td className="px-6 py-4"><code className="text-primary-400 text-sm">{cmd.command}</code></td>
                        <td className="px-6 py-4 text-sm text-text-secondary">{cmd.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Settings */}
            <div className="mb-12">
              <h2 className="text-h2 mb-6">Settings</h2>
              <div className="card overflow-hidden">
                <table className="w-full">
                  <thead>
                    <tr className="bg-bg-tertiary border-b border-border-primary">
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Setting</th>
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Description</th>
                      <th className="text-left px-6 py-3 text-sm font-medium text-text-primary">Default</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-primary">
                    {[
                      { setting: 'codehardener.apiKey', description: 'Your Code Hardener API key', default: '' },
                      { setting: 'codehardener.scanOnSave', description: 'Automatically scan files on save', default: 'true' },
                      { setting: 'codehardener.severityThreshold', description: 'Minimum severity to show (low, medium, high, critical)', default: 'low' },
                      { setting: 'codehardener.enableInlineFixes', description: 'Show quick fix suggestions inline', default: 'true' },
                      { setting: 'codehardener.ignorePaths', description: 'Glob patterns to exclude from scanning', default: '[]' },
                    ].map((s) => (
                      <tr key={s.setting}>
                        <td className="px-6 py-4"><code className="text-primary-400 text-sm">{s.setting}</code></td>
                        <td className="px-6 py-4 text-sm text-text-secondary">{s.description}</td>
                        <td className="px-6 py-4 text-sm text-text-tertiary">{s.default}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Navigation */}
            <div className="mt-12 flex items-center justify-between pt-8 border-t border-border-primary">
              <Link href="/docs/integrations/gitlab-ci" className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors">
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                GitLab CI
              </Link>
              <Link href="/docs/integrations/cursor" className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors">
                Cursor
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
