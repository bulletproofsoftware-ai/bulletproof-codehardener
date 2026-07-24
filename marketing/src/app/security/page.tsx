import type { Metadata } from 'next';
import Link from 'next/link';
import {
  Shield,
  Lock,
  Server,
  Eye,
  FileCheck,
  Users,
  CheckCircle,
  ArrowRight,
} from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Security',
  description: 'Learn about Code Hardener security practices, compliance certifications, and data protection measures.',
};

const securityFeatures = [
  {
    icon: Lock,
    title: 'Encryption Everywhere',
    description: 'TLS 1.3 for data in transit, AES-256 for data at rest. All secrets are encrypted with unique per-customer keys.',
  },
  {
    icon: Server,
    title: 'Isolated Processing',
    description: 'Your code runs in ephemeral, isolated containers. Each scan environment is destroyed after completion.',
  },
  {
    icon: Eye,
    title: 'Zero Data Retention',
    description: 'Source code is automatically deleted after scanning. We never store your code unless you explicitly opt in.',
  },
  {
    icon: FileCheck,
    title: 'Cryptographic Attestation',
    description: 'Every scan generates Sigstore-signed attestations for tamper-proof compliance evidence.',
  },
  {
    icon: Users,
    title: 'Access Controls',
    description: 'Role-based access control, SSO/SAML support, and audit logs for all administrative actions.',
  },
  {
    icon: Shield,
    title: 'Continuous Monitoring',
    description: '24/7 security monitoring, intrusion detection, and automated vulnerability scanning of our own infrastructure.',
  },
];

const certifications = [
  {
    name: 'SOC 2 Type II',
    description: 'Annual third-party audits of security, availability, and confidentiality controls.',
    status: 'Certified',
  },
  {
    name: 'GDPR',
    description: 'Full compliance with EU General Data Protection Regulation requirements.',
    status: 'Compliant',
  },
  {
    name: 'CCPA',
    description: 'California Consumer Privacy Act compliance for user data rights.',
    status: 'Compliant',
  },
  {
    name: 'ISO 27001',
    description: 'Information security management system certification (in progress).',
    status: 'In Progress',
  },
];

const practices = [
  'All employees complete security awareness training',
  'Background checks for all employees with data access',
  'Principle of least privilege for all system access',
  'Regular penetration testing by third-party security firms',
  'Bug bounty program for responsible disclosure',
  'Incident response plan with 24-hour notification',
  'Disaster recovery and business continuity plans',
  'Regular security audits and code reviews',
];

export default function SecurityPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="pt-32 pb-16">
        {/* Hero */}
        <section className="container mx-auto px-6 mb-20">
          <div className="max-w-3xl mx-auto text-center">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-success/10 border border-success/20 mb-6">
              <Shield className="h-4 w-4 text-success" aria-hidden="true" />
              <span className="text-sm text-success">SOC 2 Type II Certified</span>
            </div>
            <h1 className="text-h1 mb-6">Security at Code Hardener</h1>
            <p className="text-xl text-text-secondary">
              We secure the tools that secure your code. Our infrastructure is built with security-first principles and continuously validated by third-party auditors.
            </p>
          </div>
        </section>

        {/* Security Features */}
        <section className="section bg-bg-secondary border-y border-border-primary">
          <div className="container mx-auto px-6">
            <h2 className="text-h2 text-center mb-12">How We Protect Your Data</h2>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {securityFeatures.map((feature) => (
                <div key={feature.title} className="card p-6">
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
          </div>
        </section>

        {/* Certifications */}
        <section className="section">
          <div className="container mx-auto px-6">
            <h2 className="text-h2 text-center mb-4">Compliance & Certifications</h2>
            <p className="text-lg text-text-secondary text-center max-w-2xl mx-auto mb-12">
              We maintain industry-standard certifications to give you confidence in our security posture.
            </p>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-5xl mx-auto">
              {certifications.map((cert) => (
                <div key={cert.name} className="card p-6 text-center">
                  <div className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-medium mb-4 ${
                    cert.status === 'Certified' || cert.status === 'Compliant'
                      ? 'bg-success/10 text-success'
                      : 'bg-warning/10 text-warning'
                  }`}>
                    <CheckCircle className="h-3 w-3" aria-hidden="true" />
                    {cert.status}
                  </div>
                  <h3 className="text-h4 mb-2">{cert.name}</h3>
                  <p className="text-sm text-text-secondary">{cert.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Security Practices */}
        <section className="section bg-bg-secondary border-y border-border-primary">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mx-auto">
              <h2 className="text-h2 text-center mb-12">Our Security Practices</h2>
              <div className="grid md:grid-cols-2 gap-4">
                {practices.map((practice) => (
                  <div
                    key={practice}
                    className="flex items-start gap-3 p-4 rounded-lg bg-bg-tertiary"
                  >
                    <CheckCircle
                      className="h-5 w-5 text-success flex-shrink-0 mt-0.5"
                      aria-hidden="true"
                    />
                    <span className="text-text-secondary">{practice}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Responsible Disclosure */}
        <section className="section">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mx-auto text-center">
              <h2 className="text-h2 mb-6">Responsible Disclosure</h2>
              <p className="text-lg text-text-secondary mb-8">
                We appreciate the security research community&apos;s efforts to help keep Code Hardener secure. If you discover a security vulnerability, please report it to us responsibly.
              </p>
              <div className="card p-8 text-left">
                <h3 className="text-h4 mb-4">Report a Vulnerability</h3>
                <p className="text-text-secondary mb-4">
                  Please email security@codehardener.com with details of the vulnerability. Include:
                </p>
                <ul className="list-disc pl-6 text-text-secondary mb-6 space-y-2">
                  <li>Description of the vulnerability</li>
                  <li>Steps to reproduce</li>
                  <li>Potential impact</li>
                  <li>Any suggested remediation</li>
                </ul>
                <p className="text-text-secondary">
                  We aim to acknowledge reports within 24 hours and provide a detailed response within 72 hours. We do not pursue legal action against researchers who follow responsible disclosure practices.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="section bg-hero-gradient">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mx-auto text-center">
              <h2 className="text-h2 mb-6">Questions About Security?</h2>
              <p className="text-lg text-text-secondary mb-8">
                Our security team is available to answer your questions and provide additional documentation for enterprise evaluations.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <Link href="/contact" className="btn-primary">
                  Contact Security Team
                  <ArrowRight className="h-4 w-4" aria-hidden="true" />
                </Link>
                <Link href="/docs/security" className="btn-secondary">
                  Security Documentation
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
