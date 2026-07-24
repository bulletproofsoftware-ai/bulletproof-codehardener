import type { Metadata } from 'next';
import Link from 'next/link';
import { Mail, MessageSquare, Building, Clock } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Contact',
  description: 'Get in touch with the Code Hardener team. We are here to help with sales, support, and partnerships.',
};

const contactOptions = [
  {
    icon: MessageSquare,
    title: 'General Support',
    description: 'Get help with your account, billing, or technical issues.',
    link: 'mailto:support@codehardener.com',
    linkText: 'support@codehardener.com',
    response: 'Response within 24 hours',
  },
  {
    icon: Building,
    title: 'Enterprise Sales',
    description: 'Learn about custom plans, SSO, and self-hosted options.',
    link: 'mailto:sales@codehardener.com',
    linkText: 'sales@codehardener.com',
    response: 'Response within 4 hours',
  },
  {
    icon: Mail,
    title: 'Partnerships',
    description: 'Explore integration partnerships and reseller opportunities.',
    link: 'mailto:partners@codehardener.com',
    linkText: 'partners@codehardener.com',
    response: 'Response within 48 hours',
  },
];

export default function ContactPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="pt-32 pb-16">
        <div className="container mx-auto px-6">
          <div className="max-w-5xl mx-auto">
            {/* Header */}
            <div className="text-center mb-16">
              <h1 className="text-h1 mb-6">Get in Touch</h1>
              <p className="text-xl text-text-secondary max-w-2xl mx-auto">
                Have a question or want to learn more about Code Hardener? We&apos;re here to help.
              </p>
            </div>

            {/* Contact Options */}
            <div className="grid md:grid-cols-3 gap-6 mb-16">
              {contactOptions.map((option) => (
                <div key={option.title} className="card p-6">
                  <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-primary-500/20 to-accent-500/20 flex items-center justify-center mb-4">
                    <option.icon
                      className="h-6 w-6 text-primary-400"
                      aria-hidden="true"
                    />
                  </div>
                  <h2 className="text-h4 mb-2">{option.title}</h2>
                  <p className="text-text-secondary mb-4">{option.description}</p>
                  <a
                    href={option.link}
                    className="text-primary-500 hover:text-primary-400 font-medium"
                  >
                    {option.linkText}
                  </a>
                  <p className="text-sm text-text-tertiary mt-2 flex items-center gap-1">
                    <Clock className="h-3 w-3" aria-hidden="true" />
                    {option.response}
                  </p>
                </div>
              ))}
            </div>

            {/* Contact Form */}
            <div className="grid lg:grid-cols-2 gap-12">
              <div>
                <h2 className="text-h2 mb-4">Send Us a Message</h2>
                <p className="text-text-secondary mb-6">
                  Fill out the form and we&apos;ll get back to you as soon as possible. For urgent issues, please email support@codehardener.com directly.
                </p>
                <div className="space-y-4 text-text-secondary">
                  <p>
                    <strong className="text-text-primary">Office Hours:</strong>
                    <br />
                    Monday - Friday, 9am - 6pm EST
                  </p>
                  <p>
                    <strong className="text-text-primary">Emergency Support:</strong>
                    <br />
                    Enterprise customers have access to 24/7 emergency support via their dedicated Slack channel.
                  </p>
                </div>
              </div>

              <div className="card p-8">
                <form className="space-y-6">
                  <div className="grid sm:grid-cols-2 gap-4">
                    <div>
                      <label
                        htmlFor="firstName"
                        className="block text-sm font-medium text-text-primary mb-2"
                      >
                        First name
                      </label>
                      <input
                        type="text"
                        id="firstName"
                        name="firstName"
                        autoComplete="given-name"
                        required
                        className="input"
                        placeholder="Jane"
                      />
                    </div>
                    <div>
                      <label
                        htmlFor="lastName"
                        className="block text-sm font-medium text-text-primary mb-2"
                      >
                        Last name
                      </label>
                      <input
                        type="text"
                        id="lastName"
                        name="lastName"
                        autoComplete="family-name"
                        required
                        className="input"
                        placeholder="Doe"
                      />
                    </div>
                  </div>

                  <div>
                    <label
                      htmlFor="email"
                      className="block text-sm font-medium text-text-primary mb-2"
                    >
                      Work email
                    </label>
                    <input
                      type="email"
                      id="email"
                      name="email"
                      autoComplete="email"
                      required
                      className="input"
                      placeholder="you@company.com"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="company"
                      className="block text-sm font-medium text-text-primary mb-2"
                    >
                      Company
                    </label>
                    <input
                      type="text"
                      id="company"
                      name="company"
                      autoComplete="organization"
                      className="input"
                      placeholder="Your company name"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="subject"
                      className="block text-sm font-medium text-text-primary mb-2"
                    >
                      Subject
                    </label>
                    <select
                      id="subject"
                      name="subject"
                      required
                      className="input"
                      defaultValue=""
                    >
                      <option value="" disabled>
                        Select a topic
                      </option>
                      <option value="sales">Enterprise Sales</option>
                      <option value="support">Technical Support</option>
                      <option value="billing">Billing Question</option>
                      <option value="partnership">Partnership Inquiry</option>
                      <option value="press">Press Inquiry</option>
                      <option value="other">Other</option>
                    </select>
                  </div>

                  <div>
                    <label
                      htmlFor="message"
                      className="block text-sm font-medium text-text-primary mb-2"
                    >
                      Message
                    </label>
                    <textarea
                      id="message"
                      name="message"
                      rows={5}
                      required
                      className="input resize-none"
                      placeholder="How can we help you?"
                    />
                  </div>

                  <div className="flex items-start">
                    <input
                      type="checkbox"
                      id="privacy"
                      name="privacy"
                      required
                      className="h-4 w-4 mt-0.5 rounded border-border-primary bg-bg-tertiary text-primary-500 focus:ring-primary-500 focus:ring-offset-0"
                    />
                    <label
                      htmlFor="privacy"
                      className="ml-2 text-sm text-text-secondary"
                    >
                      I agree to the{' '}
                      <Link
                        href="/privacy"
                        className="text-primary-500 hover:text-primary-400"
                      >
                        Privacy Policy
                      </Link>{' '}
                      and consent to receiving communications from Code Hardener.
                    </label>
                  </div>

                  <button type="submit" className="btn-primary w-full">
                    Send Message
                  </button>
                </form>
              </div>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
