import Link from 'next/link';
import { Metadata } from 'next';
import { Check, ArrowRight, HelpCircle } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Pricing',
  description:
    'Simple, transparent pricing for Code Hardener. Start free with 3 projects and 200 scans. Scale as you grow.',
};

const plans = [
  {
    name: 'Free',
    description: 'Perfect for personal projects and learning',
    price: '$0',
    period: '',
    features: [
      '3 projects',
      '200 scans per month',
      'All 27 security tools',
      'Plain-language findings',
      'Basic attestations',
      'Community support',
    ],
    cta: 'Start Free',
    ctaLink: '/signup',
    featured: false,
  },
  {
    name: 'Pro',
    description: 'For professional developers and small teams',
    price: '$19',
    period: '/month',
    features: [
      '10 projects',
      'Unlimited scans',
      'All 27 security tools',
      'Plain-language findings',
      'Full attestation suite',
      'Priority email support',
      'Custom policies',
      'API access',
      'Webhooks',
    ],
    cta: 'Start Pro Trial',
    ctaLink: '/signup?plan=pro',
    featured: true,
  },
  {
    name: 'Team',
    description: 'For growing teams with collaboration needs',
    price: '$39',
    period: '/developer/month',
    features: [
      'Unlimited projects',
      'Unlimited scans',
      'All 27 security tools',
      'Plain-language findings',
      'Full attestation suite',
      'Priority support + Slack',
      'Custom policies',
      'API access',
      'Webhooks',
      'SSO (SAML/OIDC)',
      'Team management',
      'Audit logs',
    ],
    cta: 'Start Team Trial',
    ctaLink: '/signup?plan=team',
    featured: false,
  },
  {
    name: 'Enterprise',
    description: 'For organizations with advanced requirements',
    price: 'Custom',
    period: '',
    features: [
      'Everything in Team',
      'Self-hosted option',
      'Air-gapped deployment',
      'Custom SLA',
      'Dedicated support',
      'Custom integrations',
      'Advanced compliance',
      'Training & onboarding',
    ],
    cta: 'Contact Sales',
    ctaLink: '/contact?type=enterprise',
    featured: false,
  },
];

const faqs = [
  {
    question: 'What counts as a scan?',
    answer:
      'A scan is triggered when you analyze a project or repository. Each scan runs all applicable security tools (up to 27) and counts as one scan toward your monthly limit.',
  },
  {
    question: 'Can I upgrade or downgrade at any time?',
    answer:
      'Yes! You can change your plan at any time. When upgrading, you will be charged the prorated difference. When downgrading, the new rate takes effect at your next billing cycle.',
  },
  {
    question: 'What payment methods do you accept?',
    answer:
      'We accept all major credit cards (Visa, Mastercard, American Express) and can arrange invoicing for Enterprise customers.',
  },
  {
    question: 'Is there a free trial for paid plans?',
    answer:
      'Yes! Pro and Team plans come with a 14-day free trial. No credit card required to start.',
  },
  {
    question: 'What is included in the attestation suite?',
    answer:
      'Full attestation includes Sigstore-signed security attestations, VEX (Vulnerability Exploitability eXchange) documents, and SBOM (Software Bill of Materials) generation in SPDX and CycloneDX formats.',
  },
  {
    question: 'Can I self-host Code Hardener?',
    answer:
      'Self-hosting is available on the Enterprise plan. This includes air-gapped deployment options for organizations with strict security requirements.',
  },
];

export default function PricingPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="pt-16">
        {/* Hero */}
        <section className="section bg-hero-gradient bg-grid-pattern">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mx-auto text-center">
              <h1 className="text-h1 mb-6">
                Simple, <span className="text-gradient">transparent</span> pricing
              </h1>
              <p className="text-xl text-text-secondary mb-8">
                Start free, scale as you grow. No hidden fees, no surprises.
              </p>
            </div>
          </div>
        </section>

        {/* Pricing Cards */}
        <section className="section -mt-16">
          <div className="container mx-auto px-6">
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
              {plans.map((plan) => (
                <div
                  key={plan.name}
                  className={`card p-6 flex flex-col ${
                    plan.featured
                      ? 'border-primary-500 bg-gradient-to-b from-primary-500/10 to-transparent ring-1 ring-primary-500/20'
                      : ''
                  }`}
                >
                  {plan.featured && (
                    <div className="text-xs font-medium text-primary-500 mb-2">
                      Most popular
                    </div>
                  )}
                  <h2 className="text-h3 mb-1">{plan.name}</h2>
                  <p className="text-sm text-text-secondary mb-6">
                    {plan.description}
                  </p>

                  <div className="mb-6">
                    <span className="text-4xl font-bold">{plan.price}</span>
                    {plan.period && (
                      <span className="text-text-secondary">{plan.period}</span>
                    )}
                  </div>

                  <ul className="space-y-3 mb-8 flex-grow">
                    {plan.features.map((feature) => (
                      <li key={feature} className="flex items-start gap-3">
                        <Check
                          className="h-5 w-5 text-success mt-0.5 shrink-0"
                          aria-hidden="true"
                        />
                        <span className="text-sm text-text-primary">{feature}</span>
                      </li>
                    ))}
                  </ul>

                  <Link
                    href={plan.ctaLink}
                    className={plan.featured ? 'btn-primary w-full' : 'btn-secondary w-full'}
                  >
                    {plan.cta}
                  </Link>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Feature Comparison */}
        <section className="section bg-bg-secondary border-y border-border-primary">
          <div className="container mx-auto px-6">
            <div className="text-center mb-12">
              <h2 className="text-h2 mb-4">Compare plans</h2>
              <p className="text-text-secondary">
                See which plan is right for your needs
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[800px]">
                <thead>
                  <tr className="border-b border-border-primary">
                    <th className="text-left py-4 px-4 font-medium text-text-primary">
                      Feature
                    </th>
                    <th className="text-center py-4 px-4 font-medium text-text-primary">
                      Free
                    </th>
                    <th className="text-center py-4 px-4 font-medium text-primary-500">
                      Pro
                    </th>
                    <th className="text-center py-4 px-4 font-medium text-text-primary">
                      Team
                    </th>
                    <th className="text-center py-4 px-4 font-medium text-text-primary">
                      Enterprise
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-primary">
                  <tr>
                    <td className="py-4 px-4 text-text-secondary">Projects</td>
                    <td className="py-4 px-4 text-center">3</td>
                    <td className="py-4 px-4 text-center">10</td>
                    <td className="py-4 px-4 text-center">Unlimited</td>
                    <td className="py-4 px-4 text-center">Unlimited</td>
                  </tr>
                  <tr>
                    <td className="py-4 px-4 text-text-secondary">Scans/month</td>
                    <td className="py-4 px-4 text-center">200</td>
                    <td className="py-4 px-4 text-center">Unlimited</td>
                    <td className="py-4 px-4 text-center">Unlimited</td>
                    <td className="py-4 px-4 text-center">Unlimited</td>
                  </tr>
                  <tr>
                    <td className="py-4 px-4 text-text-secondary">Security tools</td>
                    <td className="py-4 px-4 text-center">27</td>
                    <td className="py-4 px-4 text-center">27</td>
                    <td className="py-4 px-4 text-center">27</td>
                    <td className="py-4 px-4 text-center">27 + Custom</td>
                  </tr>
                  <tr>
                    <td className="py-4 px-4 text-text-secondary">Attestations</td>
                    <td className="py-4 px-4 text-center">Basic</td>
                    <td className="py-4 px-4 text-center">Full</td>
                    <td className="py-4 px-4 text-center">Full</td>
                    <td className="py-4 px-4 text-center">Full + Custom</td>
                  </tr>
                  <tr>
                    <td className="py-4 px-4 text-text-secondary">API access</td>
                    <td className="py-4 px-4 text-center">-</td>
                    <td className="py-4 px-4 text-center">
                      <Check className="h-5 w-5 text-success mx-auto" />
                    </td>
                    <td className="py-4 px-4 text-center">
                      <Check className="h-5 w-5 text-success mx-auto" />
                    </td>
                    <td className="py-4 px-4 text-center">
                      <Check className="h-5 w-5 text-success mx-auto" />
                    </td>
                  </tr>
                  <tr>
                    <td className="py-4 px-4 text-text-secondary">SSO</td>
                    <td className="py-4 px-4 text-center">-</td>
                    <td className="py-4 px-4 text-center">-</td>
                    <td className="py-4 px-4 text-center">
                      <Check className="h-5 w-5 text-success mx-auto" />
                    </td>
                    <td className="py-4 px-4 text-center">
                      <Check className="h-5 w-5 text-success mx-auto" />
                    </td>
                  </tr>
                  <tr>
                    <td className="py-4 px-4 text-text-secondary">Self-hosted</td>
                    <td className="py-4 px-4 text-center">-</td>
                    <td className="py-4 px-4 text-center">-</td>
                    <td className="py-4 px-4 text-center">-</td>
                    <td className="py-4 px-4 text-center">
                      <Check className="h-5 w-5 text-success mx-auto" />
                    </td>
                  </tr>
                  <tr>
                    <td className="py-4 px-4 text-text-secondary">Support</td>
                    <td className="py-4 px-4 text-center text-sm">Community</td>
                    <td className="py-4 px-4 text-center text-sm">Email</td>
                    <td className="py-4 px-4 text-center text-sm">Priority + Slack</td>
                    <td className="py-4 px-4 text-center text-sm">Dedicated</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* FAQ */}
        <section className="section">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mx-auto">
              <div className="text-center mb-12">
                <h2 className="text-h2 mb-4">Frequently asked questions</h2>
              </div>

              <div className="space-y-6">
                {faqs.map((faq) => (
                  <div key={faq.question} className="card p-6">
                    <div className="flex items-start gap-3">
                      <HelpCircle
                        className="h-5 w-5 text-primary-500 mt-0.5 shrink-0"
                        aria-hidden="true"
                      />
                      <div>
                        <h3 className="font-medium text-text-primary mb-2">
                          {faq.question}
                        </h3>
                        <p className="text-text-secondary">{faq.answer}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="section bg-hero-gradient">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mx-auto text-center">
              <h2 className="text-h2 mb-4">Ready to get started?</h2>
              <p className="text-lg text-text-secondary mb-8">
                Start with the free plan and upgrade anytime. No credit card
                required.
              </p>
              <Link href="/signup" className="btn-primary text-lg px-8 py-4">
                Start Free
                <ArrowRight className="h-5 w-5" aria-hidden="true" />
              </Link>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}
