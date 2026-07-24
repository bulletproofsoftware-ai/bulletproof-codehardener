import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, Code, Key, Shield, FileJson } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'API Reference',
  description: 'Complete Code Hardener REST API documentation. Authentication, endpoints, and code examples.',
};

const endpoints = [
  {
    category: 'Authentication',
    items: [
      { method: 'POST', path: '/api/v1/auth/login', description: 'Authenticate with email/password' },
      { method: 'POST', path: '/api/v1/auth/register', description: 'Create a new account' },
      { method: 'POST', path: '/api/v1/auth/refresh', description: 'Refresh access token' },
      { method: 'POST', path: '/api/v1/auth/logout', description: 'Invalidate current token' },
    ],
  },
  {
    category: 'Projects',
    items: [
      { method: 'GET', path: '/api/v1/projects', description: 'List all projects' },
      { method: 'POST', path: '/api/v1/projects', description: 'Create a new project' },
      { method: 'GET', path: '/api/v1/projects/:id', description: 'Get project details' },
      { method: 'PATCH', path: '/api/v1/projects/:id', description: 'Update project settings' },
      { method: 'DELETE', path: '/api/v1/projects/:id', description: 'Delete a project' },
    ],
  },
  {
    category: 'Scans',
    items: [
      { method: 'POST', path: '/api/v1/scans', description: 'Trigger a new scan' },
      { method: 'GET', path: '/api/v1/scans/:id', description: 'Get scan status and results' },
      { method: 'GET', path: '/api/v1/scans/:id/findings', description: 'List findings from scan' },
      { method: 'POST', path: '/api/v1/scans/:id/attest', description: 'Generate attestation' },
    ],
  },
  {
    category: 'Attestations',
    items: [
      { method: 'GET', path: '/api/v1/attestations', description: 'List all attestations' },
      { method: 'GET', path: '/api/v1/attestations/:id', description: 'Get attestation details' },
      { method: 'GET', path: '/api/v1/attestations/:id/verify', description: 'Verify attestation signature' },
      { method: 'GET', path: '/api/v1/attestations/:id/download', description: 'Download attestation bundle' },
    ],
  },
];

const methodColors: Record<string, string> = {
  GET: 'text-success',
  POST: 'text-info',
  PATCH: 'text-warning',
  DELETE: 'text-error',
  PUT: 'text-warning',
};

export default function ApiReferencePage() {
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
                <li className="text-text-primary">API Reference</li>
              </ol>
            </nav>

            {/* Header */}
            <div className="mb-12">
              <h1 className="text-h1 mb-4">API Reference</h1>
              <p className="text-xl text-text-secondary">
                The Code Hardener REST API enables you to integrate security scanning into your applications and workflows programmatically.
              </p>
            </div>

            {/* Quick Links */}
            <div className="grid sm:grid-cols-3 gap-4 mb-12">
              {[
                { icon: Key, title: 'Authentication', href: '/docs/api/authentication' },
                { icon: Code, title: 'Code Examples', href: '/docs/api/examples' },
                { icon: FileJson, title: 'OpenAPI Spec', href: '/api/v1/openapi.json' },
              ].map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="card-interactive p-4 flex items-center gap-3 group"
                >
                  <item.icon
                    className="h-5 w-5 text-primary-400"
                    aria-hidden="true"
                  />
                  <span className="font-medium group-hover:text-primary-400 transition-colors">
                    {item.title}
                  </span>
                </Link>
              ))}
            </div>

            {/* Base URL */}
            <div className="card p-6 mb-12">
              <h2 className="text-h4 mb-4">Base URL</h2>
              <code className="block p-4 bg-bg-tertiary rounded-lg text-primary-400 font-mono">
                https://api.codehardener.com
              </code>
              <p className="text-sm text-text-secondary mt-4">
                All API requests must be made over HTTPS. Requests made over HTTP will be rejected.
              </p>
            </div>

            {/* Authentication */}
            <div className="card p-6 mb-12">
              <h2 className="text-h4 mb-4 flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary-400" aria-hidden="true" />
                Authentication
              </h2>
              <p className="text-text-secondary mb-4">
                The API supports two authentication methods:
              </p>
              <div className="space-y-4">
                <div className="p-4 bg-bg-tertiary rounded-lg">
                  <p className="font-medium mb-2">Bearer Token (JWT)</p>
                  <code className="text-sm text-text-secondary font-mono">
                    Authorization: Bearer YOUR_JWT_TOKEN
                  </code>
                </div>
                <div className="p-4 bg-bg-tertiary rounded-lg">
                  <p className="font-medium mb-2">API Key</p>
                  <code className="text-sm text-text-secondary font-mono">
                    X-API-Key: YOUR_API_KEY
                  </code>
                </div>
              </div>
              <p className="text-sm text-text-secondary mt-4">
                <Link href="/docs/api/authentication" className="text-primary-500 hover:text-primary-400">
                  Learn more about authentication &rarr;
                </Link>
              </p>
            </div>

            {/* Endpoints */}
            <div className="space-y-8">
              <h2 className="text-h2">Endpoints</h2>

              {endpoints.map((section) => (
                <div key={section.category} className="card overflow-hidden">
                  <div className="px-6 py-4 bg-bg-tertiary border-b border-border-primary">
                    <h3 className="text-h4">{section.category}</h3>
                  </div>
                  <div className="divide-y divide-border-primary">
                    {section.items.map((endpoint) => (
                      <div
                        key={endpoint.path}
                        className="px-6 py-4 hover:bg-bg-tertiary transition-colors"
                      >
                        <div className="flex items-center gap-4">
                          <span
                            className={`font-mono text-sm font-medium w-16 ${
                              methodColors[endpoint.method] || 'text-text-primary'
                            }`}
                          >
                            {endpoint.method}
                          </span>
                          <code className="font-mono text-sm text-text-primary">
                            {endpoint.path}
                          </code>
                        </div>
                        <p className="text-sm text-text-secondary mt-1 ml-20">
                          {endpoint.description}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {/* Rate Limits */}
            <div className="card p-6 mt-12">
              <h2 className="text-h4 mb-4">Rate Limits</h2>
              <p className="text-text-secondary mb-4">
                API requests are rate limited based on your plan:
              </p>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border-primary">
                      <th className="text-left py-2 text-text-primary font-medium">Plan</th>
                      <th className="text-left py-2 text-text-primary font-medium">Requests/min</th>
                      <th className="text-left py-2 text-text-primary font-medium">Burst</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-border-primary">
                      <td className="py-2 text-text-secondary">Free</td>
                      <td className="py-2 text-text-secondary">60</td>
                      <td className="py-2 text-text-secondary">10</td>
                    </tr>
                    <tr className="border-b border-border-primary">
                      <td className="py-2 text-text-secondary">Pro</td>
                      <td className="py-2 text-text-secondary">300</td>
                      <td className="py-2 text-text-secondary">50</td>
                    </tr>
                    <tr className="border-b border-border-primary">
                      <td className="py-2 text-text-secondary">Team</td>
                      <td className="py-2 text-text-secondary">1000</td>
                      <td className="py-2 text-text-secondary">100</td>
                    </tr>
                    <tr>
                      <td className="py-2 text-text-secondary">Enterprise</td>
                      <td className="py-2 text-text-secondary">Custom</td>
                      <td className="py-2 text-text-secondary">Custom</td>
                    </tr>
                  </tbody>
                </table>
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
                href="/docs/api/authentication"
                className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
              >
                Authentication
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
