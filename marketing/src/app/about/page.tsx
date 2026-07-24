import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, Shield, Zap, Users, Target } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'About',
  description: 'Learn about Code Hardener, our mission to secure AI-generated code, and the team behind the platform.',
};

const values = [
  {
    icon: Shield,
    title: 'Security First',
    description: 'Every decision we make prioritizes the security of our users and their code.',
  },
  {
    icon: Zap,
    title: 'Developer Experience',
    description: 'Security tools should enhance productivity, not slow developers down.',
  },
  {
    icon: Users,
    title: 'Open Source Core',
    description: 'We build on and contribute back to the open-source security community.',
  },
  {
    icon: Target,
    title: 'Transparency',
    description: 'Clear findings, honest pricing, and open communication with our users.',
  },
];

const stats = [
  { value: '27', label: 'Security Tools' },
  { value: '10M+', label: 'Scans Completed' },
  { value: '5K+', label: 'Developers' },
  { value: '99.9%', label: 'Uptime' },
];

const team = [
  {
    name: 'Alex Chen',
    role: 'CEO & Co-founder',
    bio: 'Former security lead at Stripe. 15 years in application security.',
  },
  {
    name: 'Sarah Martinez',
    role: 'CTO & Co-founder',
    bio: 'Ex-Google security engineer. Built detection systems at scale.',
  },
  {
    name: 'James Wilson',
    role: 'VP Engineering',
    bio: 'Previously led infrastructure at Datadog. Focus on reliability.',
  },
  {
    name: 'Emily Park',
    role: 'Head of Product',
    bio: 'Product leader from GitHub. Passionate about developer tools.',
  },
];

export default function AboutPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="pt-32 pb-16">
        {/* Hero */}
        <section className="container mx-auto px-6 mb-20">
          <div className="max-w-3xl mx-auto text-center">
            <h1 className="text-h1 mb-6">
              Securing the Future of{' '}
              <span className="text-gradient">AI-Assisted Development</span>
            </h1>
            <p className="text-xl text-text-secondary">
              AI coding assistants are transforming how software is built. We&apos;re building the security layer to ensure that transformation is safe.
            </p>
          </div>
        </section>

        {/* Mission */}
        <section className="section bg-bg-secondary border-y border-border-primary">
          <div className="container mx-auto px-6">
            <div className="max-w-4xl mx-auto">
              <div className="grid md:grid-cols-2 gap-12 items-center">
                <div>
                  <h2 className="text-h2 mb-6">Our Mission</h2>
                  <p className="text-lg text-text-secondary mb-4">
                    By 2025, an estimated 41% of all code will be AI-generated. Studies show that nearly half of this AI-generated code contains security vulnerabilities.
                  </p>
                  <p className="text-lg text-text-secondary mb-4">
                    We founded Code Hardener to bridge this gap. Our platform makes enterprise-grade security accessible to every developer, whether you&apos;re a solo founder or part of a Fortune 500 engineering team.
                  </p>
                  <p className="text-lg text-text-secondary">
                    We believe security should be a feature that enables faster shipping, not a bottleneck that slows you down.
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  {stats.map((stat) => (
                    <div key={stat.label} className="card p-6 text-center">
                      <p className="text-3xl font-bold text-gradient mb-1">
                        {stat.value}
                      </p>
                      <p className="text-sm text-text-secondary">{stat.label}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Values */}
        <section className="section">
          <div className="container mx-auto px-6">
            <h2 className="text-h2 text-center mb-12">Our Values</h2>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-5xl mx-auto">
              {values.map((value) => (
                <div key={value.title} className="card p-6 text-center">
                  <div className="w-12 h-12 rounded-full bg-gradient-to-br from-primary-500/20 to-accent-500/20 flex items-center justify-center mx-auto mb-4">
                    <value.icon
                      className="h-6 w-6 text-primary-400"
                      aria-hidden="true"
                    />
                  </div>
                  <h3 className="text-h4 mb-2">{value.title}</h3>
                  <p className="text-sm text-text-secondary">{value.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Team */}
        <section className="section bg-bg-secondary border-y border-border-primary" id="team">
          <div className="container mx-auto px-6">
            <h2 className="text-h2 text-center mb-4">Leadership Team</h2>
            <p className="text-lg text-text-secondary text-center max-w-2xl mx-auto mb-12">
              We&apos;re a team of security engineers, product builders, and developer advocates united by a mission to make security accessible.
            </p>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-5xl mx-auto">
              {team.map((member) => (
                <div key={member.name} className="card p-6">
                  <div className="w-16 h-16 rounded-full bg-gradient-to-br from-primary-500 to-accent-500 mb-4" />
                  <h3 className="text-h4 mb-1">{member.name}</h3>
                  <p className="text-sm text-primary-500 mb-3">{member.role}</p>
                  <p className="text-sm text-text-secondary">{member.bio}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Careers */}
        <section className="section" id="careers">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mx-auto text-center">
              <h2 className="text-h2 mb-6">Join Our Team</h2>
              <p className="text-lg text-text-secondary mb-8">
                We&apos;re always looking for talented people who are passionate about security and developer experience. We offer competitive compensation, remote-first work, and the opportunity to shape the future of secure software development.
              </p>
              <div className="card p-8">
                <h3 className="text-h3 mb-6">Open Positions</h3>
                <div className="space-y-4">
                  {[
                    { title: 'Senior Security Engineer', location: 'Remote', type: 'Full-time' },
                    { title: 'Full Stack Engineer', location: 'Remote', type: 'Full-time' },
                    { title: 'Developer Advocate', location: 'Remote', type: 'Full-time' },
                    { title: 'Product Designer', location: 'Remote', type: 'Full-time' },
                  ].map((job) => (
                    <Link
                      key={job.title}
                      href={`/careers/${job.title.toLowerCase().replace(/\s+/g, '-')}`}
                      className="flex items-center justify-between p-4 rounded-lg bg-bg-tertiary hover:bg-bg-hover transition-colors group"
                    >
                      <div>
                        <p className="font-medium text-text-primary group-hover:text-primary-400 transition-colors">
                          {job.title}
                        </p>
                        <p className="text-sm text-text-secondary">
                          {job.location} &middot; {job.type}
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
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="section bg-hero-gradient">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mx-auto text-center">
              <h2 className="text-h2 mb-6">Ready to Secure Your Code?</h2>
              <p className="text-lg text-text-secondary mb-8">
                Join thousands of developers who trust Code Hardener to keep their AI-generated code secure.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <Link href="/signup" className="btn-primary">
                  Start Free
                  <ArrowRight className="h-4 w-4" aria-hidden="true" />
                </Link>
                <Link href="/contact" className="btn-secondary">
                  Talk to Sales
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
