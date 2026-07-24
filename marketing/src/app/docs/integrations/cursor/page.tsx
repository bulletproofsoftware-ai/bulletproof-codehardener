import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, Code, Zap, Check } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Cursor Integration',
  description: 'Code Hardener integration for Cursor IDE. Security scanning for AI-assisted development.',
};

export default function CursorPage() {
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
                <li className="text-text-primary">Cursor</li>
              </ol>
            </nav>

            {/* Header */}
            <div className="mb-12">
              <div className="flex items-center gap-4 mb-4">
                <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center">
                  <Code className="h-6 w-6 text-white" aria-hidden="true" />
                </div>
                <span className="px-2 py-0.5 rounded-full bg-primary-500/10 text-primary-500 text-xs font-medium">Popular</span>
              </div>
              <h1 className="text-h1 mb-4">Cursor Integration</h1>
              <p className="text-xl text-text-secondary">
                Secure your AI-assisted development workflow. Code Hardener scans code as Cursor generates it, catching vulnerabilities before they reach your codebase.
              </p>
            </div>

            {/* Why Cursor */}
            <div className="card p-6 mb-12">
              <h2 className="text-h3 mb-4 flex items-center gap-2">
                <Zap className="h-6 w-6 text-primary-400" aria-hidden="true" />
                Why Code Hardener + Cursor?
              </h2>
              <p className="text-text-secondary mb-4">
                Cursor&apos;s AI-powered code generation is incredibly productive, but AI-generated code can contain security vulnerabilities. Code Hardener provides the safety net.
              </p>
              <ul className="space-y-2">
                {[
                  'Scan AI-generated code before accepting suggestions',
                  'Get security explanations in plain language',
                  'Apply secure alternatives with one click',
                  'Build security awareness as you code',
                ].map((item) => (
                  <li key={item} className="flex items-center gap-2 text-text-secondary">
                    <Check className="h-4 w-4 text-success flex-shrink-0" aria-hidden="true" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>

            {/* Installation */}
            <div className="space-y-8 mb-12">
              <h2 className="text-h2">Installation</h2>

              <div className="card p-6">
                <h3 className="text-h4 mb-4">Method 1: VS Code Extension (Recommended)</h3>
                <p className="text-text-secondary mb-4">
                  Cursor is built on VS Code, so our VS Code extension works seamlessly:
                </p>
                <ol className="list-decimal list-inside text-text-secondary space-y-2">
                  <li>Open Cursor&apos;s Extensions view (<kbd className="px-2 py-1 bg-bg-tertiary rounded text-xs">Cmd+Shift+X</kbd>)</li>
                  <li>Search for &quot;Code Hardener&quot;</li>
                  <li>Click Install</li>
                  <li>Configure your API key in settings</li>
                </ol>
              </div>

              <div className="card p-6">
                <h3 className="text-h4 mb-4">Method 2: Cursor Rules Integration</h3>
                <p className="text-text-secondary mb-4">
                  Add Code Hardener awareness to Cursor&apos;s AI by creating a <code className="text-primary-400">.cursorrules</code> file:
                </p>
                <pre className="p-4 bg-[#0d1117] rounded-lg border border-border-primary overflow-x-auto text-sm text-[#c9d1d9] font-mono">
{`# Security-First Development Rules

When generating code:
1. Never hardcode credentials, API keys, or secrets
2. Always use parameterized queries for database operations
3. Sanitize all user inputs before use
4. Use secure defaults for cryptographic operations
5. Validate authentication and authorization on all endpoints

After generating code, remind the user to run:
\`hardener scan [filename]\`

For security questions, reference Code Hardener documentation
at https://codehardener.com/docs`}
                </pre>
              </div>
            </div>

            {/* Workflow */}
            <div className="mb-12">
              <h2 className="text-h2 mb-6">Recommended Workflow</h2>
              <div className="space-y-4">
                {[
                  { step: '1', title: 'Generate code with Cursor', description: 'Use Cursor\'s AI to write your code as usual' },
                  { step: '2', title: 'Review Code Hardener diagnostics', description: 'Security issues appear as inline warnings' },
                  { step: '3', title: 'Apply quick fixes', description: 'Click the lightbulb or use Cmd+. to apply secure alternatives' },
                  { step: '4', title: 'Commit with confidence', description: 'Your code is secure before it enters version control' },
                ].map((item) => (
                  <div key={item.step} className="card p-4 flex items-start gap-4">
                    <span className="w-8 h-8 rounded-full bg-primary-500 text-white flex items-center justify-center text-sm font-bold flex-shrink-0">
                      {item.step}
                    </span>
                    <div>
                      <h3 className="font-medium text-text-primary">{item.title}</h3>
                      <p className="text-sm text-text-secondary">{item.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Tips */}
            <div className="card p-6 mb-12">
              <h2 className="text-h3 mb-4">Pro Tips</h2>
              <ul className="space-y-3 text-text-secondary">
                <li className="flex items-start gap-2">
                  <Check className="h-4 w-4 text-primary-400 mt-1 flex-shrink-0" aria-hidden="true" />
                  <span>Enable <code className="text-primary-400">scanOnSave</code> to automatically check files when you save</span>
                </li>
                <li className="flex items-start gap-2">
                  <Check className="h-4 w-4 text-primary-400 mt-1 flex-shrink-0" aria-hidden="true" />
                  <span>Use the &quot;Code Hardener: Explain Finding&quot; command to understand why something is flagged</span>
                </li>
                <li className="flex items-start gap-2">
                  <Check className="h-4 w-4 text-primary-400 mt-1 flex-shrink-0" aria-hidden="true" />
                  <span>Add common false positives to your <code className="text-primary-400">.hardener.yml</code> ignore rules</span>
                </li>
              </ul>
            </div>

            {/* Navigation */}
            <div className="mt-12 flex items-center justify-between pt-8 border-t border-border-primary">
              <Link href="/docs/integrations/vscode" className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors">
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                VS Code
              </Link>
              <Link href="/docs/mcp" className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors">
                Claude Code (MCP)
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
