import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, Github, Mail, Check } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Sign Up',
  description: 'Create your free Code Hardener account and start securing your AI-generated code in minutes.',
};

const benefits = [
  '3 projects included free',
  '200 scans per month',
  '27 security tools',
  'Plain-language findings',
  'No credit card required',
];

export default function SignupPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="min-h-screen flex items-center justify-center py-32 px-6">
        <div className="w-full max-w-md">
          {/* Back link */}
          <Link
            href="/"
            className="inline-flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors mb-8"
          >
            <ArrowLeft className="h-4 w-4" aria-hidden="true" />
            Back to home
          </Link>

          {/* Card */}
          <div className="card p-8">
            <div className="text-center mb-8">
              <h1 className="text-h3 mb-2">Create your account</h1>
              <p className="text-text-secondary">
                Start securing your AI-generated code for free
              </p>
            </div>

            {/* Benefits */}
            <div className="bg-bg-tertiary rounded-lg p-4 mb-6">
              <p className="text-xs font-medium text-text-tertiary uppercase tracking-wider mb-3">
                Free tier includes
              </p>
              <ul className="space-y-2">
                {benefits.map((benefit) => (
                  <li
                    key={benefit}
                    className="flex items-center gap-2 text-sm text-text-secondary"
                  >
                    <Check
                      className="h-4 w-4 text-success flex-shrink-0"
                      aria-hidden="true"
                    />
                    {benefit}
                  </li>
                ))}
              </ul>
            </div>

            {/* OAuth buttons */}
            <div className="space-y-3 mb-6">
              <button
                type="button"
                className="btn-secondary w-full justify-center"
              >
                <Github className="h-5 w-5" aria-hidden="true" />
                Continue with GitHub
              </button>
              <button
                type="button"
                className="btn-secondary w-full justify-center"
              >
                <Mail className="h-5 w-5" aria-hidden="true" />
                Continue with Google
              </button>
            </div>

            {/* Divider */}
            <div className="relative my-6">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-border-primary" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="bg-bg-secondary px-4 text-text-tertiary">
                  or sign up with email
                </span>
              </div>
            </div>

            {/* Form */}
            <form className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
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
                  htmlFor="password"
                  className="block text-sm font-medium text-text-primary mb-2"
                >
                  Password
                </label>
                <input
                  type="password"
                  id="password"
                  name="password"
                  autoComplete="new-password"
                  required
                  className="input"
                  placeholder="Create a strong password"
                />
                <p className="mt-1 text-xs text-text-tertiary">
                  Minimum 12 characters with uppercase, lowercase, and numbers
                </p>
              </div>

              <div className="flex items-start">
                <input
                  type="checkbox"
                  id="terms"
                  name="terms"
                  required
                  className="h-4 w-4 mt-0.5 rounded border-border-primary bg-bg-tertiary text-primary-500 focus:ring-primary-500 focus:ring-offset-0"
                />
                <label
                  htmlFor="terms"
                  className="ml-2 text-sm text-text-secondary"
                >
                  I agree to the{' '}
                  <Link
                    href="/terms"
                    className="text-primary-500 hover:text-primary-400"
                  >
                    Terms of Service
                  </Link>{' '}
                  and{' '}
                  <Link
                    href="/privacy"
                    className="text-primary-500 hover:text-primary-400"
                  >
                    Privacy Policy
                  </Link>
                </label>
              </div>

              <button type="submit" className="btn-primary w-full">
                Create account
              </button>
            </form>

            {/* Login link */}
            <p className="mt-6 text-center text-sm text-text-secondary">
              Already have an account?{' '}
              <Link
                href="/login"
                className="text-primary-500 hover:text-primary-400 font-medium"
              >
                Sign in
              </Link>
            </p>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
