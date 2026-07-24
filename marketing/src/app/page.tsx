import Link from 'next/link';
import {
  Wand2,
  MessageSquare,
  Shield,
  Lock,
  Plug,
  Wrench,
  ArrowRight,
  Star,
} from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

// Feature cards data
const features = [
  {
    icon: Wand2,
    title: 'Zero Config',
    description: 'Works out of the box with intelligent language detection',
  },
  {
    icon: MessageSquare,
    title: 'Plain Language',
    description: 'Translates CVEs into human-readable explanations',
  },
  {
    icon: Shield,
    title: '27 Security Tools',
    description: 'SAST, DAST, SCA, secrets, and more in one platform',
  },
  {
    icon: Lock,
    title: 'Cryptographic Proof',
    description: 'Sigstore-signed attestations for compliance evidence',
  },
  {
    icon: Plug,
    title: 'AI Tool Integration',
    description: 'Native support for Cursor, Copilot, and Claude Code',
  },
  {
    icon: Wrench,
    title: 'One-Click Fixes',
    description: 'Auto-remediation for common vulnerabilities',
  },
];

// How it works steps
const steps = [
  {
    step: 1,
    title: 'Connect',
    description: 'Connect your repository or paste code',
  },
  {
    step: 2,
    title: 'Scan',
    description: '27 security tools analyze your code in seconds',
  },
  {
    step: 3,
    title: 'Ship Secure',
    description: 'Get attestation and deploy with confidence',
  },
];

// Integration logos
const integrations = [
  { name: 'Cursor', category: 'AI Editor' },
  { name: 'Claude Code', category: 'AI Editor' },
  { name: 'GitHub Copilot', category: 'AI Assistant' },
  { name: 'GitHub Actions', category: 'CI/CD' },
  { name: 'GitLab CI', category: 'CI/CD' },
  { name: 'Vercel', category: 'Hosting' },
  { name: 'Netlify', category: 'Hosting' },
  { name: 'Replit', category: 'IDE' },
];

// Pricing tiers
const pricingTiers = [
  {
    name: 'Free',
    price: '$0',
    period: '',
    description: '3 projects, 200 scans/mo',
    featured: false,
  },
  {
    name: 'Pro',
    price: '$19',
    period: '/mo',
    description: '10 projects, unlimited scans',
    featured: true,
  },
  {
    name: 'Team',
    price: '$39',
    period: '/dev/mo',
    description: 'Unlimited + SSO',
    featured: false,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    period: '',
    description: 'Self-hosted + SLA',
    featured: false,
  },
];

// Testimonials
const testimonials = [
  {
    quote:
      'Code Hardener caught security issues in our AI-generated code that we never would have found manually. Setup took less than 2 minutes.',
    author: 'Sarah Chen',
    role: 'Staff Engineer',
    company: 'TechFlow',
  },
  {
    quote:
      'We needed SOC 2 compliance fast. The cryptographic attestations gave our auditors exactly what they needed. Saved us weeks.',
    author: 'Marcus Johnson',
    role: 'Co-founder',
    company: 'DataSync',
  },
  {
    quote:
      'The MCP integration with Claude Code is seamless. Our whole team now uses it and our vulnerability count dropped by 73%.',
    author: 'Emily Park',
    role: 'Engineering Lead',
    company: 'Amplitude Labs',
  },
];

export default function HomePage() {
  return (
    <>
      <Header transparent />
      <main id="main-content">
        {/* Hero Section */}
        <section className="relative min-h-screen flex items-center bg-hero-gradient bg-grid-pattern overflow-hidden">
          <div className="container mx-auto px-6 pt-32 pb-20">
            <div className="max-w-4xl mx-auto text-center">
              {/* Badge */}
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-bg-secondary border border-border-primary mb-8 animate-fade-in">
                <Star className="h-4 w-4 text-warning" aria-hidden="true" />
                <span className="text-sm text-text-secondary">
                  Now with MCP support for Claude Code
                </span>
              </div>

              {/* Headline */}
              <h1 className="text-hero mb-6 animate-fade-in-up">
                Security for{' '}
                <span className="text-gradient">AI-First Developers</span>
              </h1>

              {/* Subheadline */}
              <p className="text-xl md:text-2xl text-text-secondary mb-10 max-w-2xl mx-auto animate-fade-in-up" style={{ animationDelay: '100ms' }}>
                One prompt, one API call, or one MCP connection to secure any
                application. Built for developers who ship fast with AI.
              </p>

              {/* CTAs */}
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-fade-in-up" style={{ animationDelay: '200ms' }}>
                <Link href="/signup" className="btn-primary text-lg px-8 py-4">
                  Start Free
                  <ArrowRight className="h-5 w-5" aria-hidden="true" />
                </Link>
                <Link href="/docs/quickstart" className="btn-secondary text-lg px-8 py-4">
                  View Demo
                </Link>
              </div>

              {/* Trust badges */}
              <div className="mt-16 animate-fade-in" style={{ animationDelay: '300ms' }}>
                <p className="text-sm text-text-tertiary mb-6">
                  Trusted by developers using
                </p>
                <div className="flex flex-wrap items-center justify-center gap-8 opacity-60">
                  {['Cursor', 'GitHub Copilot', 'Claude', 'Replit', 'Vercel'].map(
                    (brand) => (
                      <span
                        key={brand}
                        className="text-lg font-medium text-text-secondary"
                      >
                        {brand}
                      </span>
                    )
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Gradient orbs */}
          <div className="absolute top-1/4 -left-64 w-[500px] h-[500px] bg-primary-500/20 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute bottom-1/4 -right-64 w-[500px] h-[500px] bg-accent-500/20 rounded-full blur-3xl pointer-events-none" />
        </section>

        {/* Problem/Solution Section */}
        <section className="section bg-bg-secondary border-y border-border-primary">
          <div className="container mx-auto px-6">
            <div className="max-w-4xl mx-auto text-center">
              <h2 className="text-h2 mb-8">The AI Security Problem</h2>
              <div className="grid md:grid-cols-3 gap-8 mb-12">
                <div className="p-6">
                  <p className="text-4xl font-bold text-error mb-2">45%</p>
                  <p className="text-text-secondary">
                    of AI-generated code contains vulnerabilities
                  </p>
                </div>
                <div className="p-6">
                  <p className="text-4xl font-bold text-warning mb-2">41%</p>
                  <p className="text-text-secondary">
                    of global code is now AI-generated
                  </p>
                </div>
                <div className="p-6">
                  <p className="text-4xl font-bold text-primary-500 mb-2">$3.89B</p>
                  <p className="text-text-secondary">
                    market with zero purpose-built security
                  </p>
                </div>
              </div>
              <p className="text-xl text-text-primary">
                <span className="text-gradient font-semibold">Code Hardener:</span>{' '}
                The security layer built for how you actually code
              </p>
            </div>
          </div>
        </section>

        {/* Features Grid */}
        <section className="section">
          <div className="container mx-auto px-6">
            <div className="text-center mb-16">
              <h2 className="text-h2 mb-4">
                Everything you need to ship secure code
              </h2>
              <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                27 industry-leading security tools, unified into one platform with
                plain-language results.
              </p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {features.map((feature, index) => (
                <div
                  key={feature.title}
                  className="card-interactive p-6 animate-fade-in-up"
                  style={{ animationDelay: `${index * 50}ms` }}
                >
                  <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-primary-500/20 to-accent-500/20 flex items-center justify-center mb-4">
                    <feature.icon
                      className="h-6 w-6 text-primary-400"
                      aria-hidden="true"
                    />
                  </div>
                  <h3 className="text-h4 mb-2">{feature.title}</h3>
                  <p className="text-text-secondary">{feature.description}</p>
                </div>
              ))}
            </div>

            <div className="text-center mt-12">
              <Link href="/features" className="btn-secondary">
                View all features
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </Link>
            </div>
          </div>
        </section>

        {/* How It Works */}
        <section className="section bg-bg-secondary border-y border-border-primary">
          <div className="container mx-auto px-6">
            <div className="text-center mb-16">
              <h2 className="text-h2 mb-4">How it works</h2>
              <p className="text-lg text-text-secondary">
                From code to attestation in three simple steps
              </p>
            </div>

            <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
              {steps.map((step, index) => (
                <div key={step.step} className="text-center relative">
                  {/* Connector line */}
                  {index < steps.length - 1 && (
                    <div className="hidden md:block absolute top-8 left-1/2 w-full h-px bg-gradient-to-r from-primary-500/50 to-transparent" />
                  )}
                  <div className="w-16 h-16 rounded-full bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center mx-auto mb-6 relative z-10">
                    <span className="text-2xl font-bold text-white">
                      {step.step}
                    </span>
                  </div>
                  <h3 className="text-h3 mb-2">{step.title}</h3>
                  <p className="text-text-secondary">{step.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Integrations */}
        <section className="section">
          <div className="container mx-auto px-6">
            <div className="text-center mb-16">
              <h2 className="text-h2 mb-4">Integrates with your workflow</h2>
              <p className="text-lg text-text-secondary">
                Works seamlessly with the tools you already use
              </p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto">
              {integrations.map((integration) => (
                <div
                  key={integration.name}
                  className="card p-4 text-center hover:border-primary-500/50 transition-colors"
                >
                  <p className="font-medium text-text-primary">
                    {integration.name}
                  </p>
                  <p className="text-sm text-text-tertiary">
                    {integration.category}
                  </p>
                </div>
              ))}
            </div>

            <div className="text-center mt-12">
              <Link href="/docs/integrations" className="btn-ghost">
                View all integrations
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </Link>
            </div>
          </div>
        </section>

        {/* Pricing Preview */}
        <section className="section bg-bg-secondary border-y border-border-primary">
          <div className="container mx-auto px-6">
            <div className="text-center mb-16">
              <h2 className="text-h2 mb-4">Simple, transparent pricing</h2>
              <p className="text-lg text-text-secondary">
                Start free, scale as you grow
              </p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-5xl mx-auto">
              {pricingTiers.map((tier) => (
                <div
                  key={tier.name}
                  className={`card p-6 ${
                    tier.featured
                      ? 'border-primary-500 bg-gradient-to-b from-primary-500/10 to-transparent'
                      : ''
                  }`}
                >
                  {tier.featured && (
                    <p className="text-xs font-medium text-primary-500 mb-2">
                      Most popular
                    </p>
                  )}
                  <h3 className="text-h4 mb-2">{tier.name}</h3>
                  <p className="text-3xl font-bold mb-1">
                    {tier.price}
                    <span className="text-sm font-normal text-text-secondary">
                      {tier.period}
                    </span>
                  </p>
                  <p className="text-sm text-text-secondary">{tier.description}</p>
                </div>
              ))}
            </div>

            <div className="text-center mt-12">
              <Link href="/pricing" className="btn-secondary">
                View full pricing comparison
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </Link>
            </div>
          </div>
        </section>

        {/* Testimonials */}
        <section className="section">
          <div className="container mx-auto px-6">
            <div className="text-center mb-16">
              <h2 className="text-h2 mb-4">Loved by developers</h2>
              <p className="text-lg text-text-secondary">
                Join thousands of developers shipping secure code
              </p>
            </div>

            <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
              {testimonials.map((testimonial, index) => (
                <div key={index} className="card p-6">
                  <div className="flex items-center gap-1 mb-4">
                    {[...Array(5)].map((_, i) => (
                      <Star
                        key={i}
                        className="h-4 w-4 fill-warning text-warning"
                        aria-hidden="true"
                      />
                    ))}
                  </div>
                  <blockquote className="text-text-primary mb-6">
                    &ldquo;{testimonial.quote}&rdquo;
                  </blockquote>
                  <div>
                    <p className="font-medium text-text-primary">
                      {testimonial.author}
                    </p>
                    <p className="text-sm text-text-secondary">
                      {testimonial.role}, {testimonial.company}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Final CTA */}
        <section className="section bg-hero-gradient relative overflow-hidden">
          <div className="container mx-auto px-6 relative z-10">
            <div className="max-w-3xl mx-auto text-center">
              <h2 className="text-h1 mb-6">
                Start securing your AI-generated code today
              </h2>
              <p className="text-xl text-text-secondary mb-10">
                Free tier includes 3 projects and 200 scans per month. No credit
                card required.
              </p>
              <Link href="/signup" className="btn-primary text-lg px-10 py-4">
                Get Started Free
                <ArrowRight className="h-5 w-5" aria-hidden="true" />
              </Link>
            </div>
          </div>

          {/* Background orbs */}
          <div className="absolute top-0 left-1/4 w-[400px] h-[400px] bg-primary-500/10 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute bottom-0 right-1/4 w-[400px] h-[400px] bg-accent-500/10 rounded-full blur-3xl pointer-events-none" />
        </section>
      </main>
      <Footer />
    </>
  );
}
