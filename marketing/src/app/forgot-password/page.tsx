import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, Mail } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Forgot Password',
  description: 'Reset your Code Hardener account password.',
};

export default function ForgotPasswordPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="min-h-screen flex items-center justify-center py-32 px-6">
        <div className="w-full max-w-md">
          {/* Back link */}
          <Link
            href="/login"
            className="inline-flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors mb-8"
          >
            <ArrowLeft className="h-4 w-4" aria-hidden="true" />
            Back to login
          </Link>

          {/* Card */}
          <div className="card p-8">
            <div className="text-center mb-8">
              <div className="w-12 h-12 rounded-full bg-primary-500/10 flex items-center justify-center mx-auto mb-4">
                <Mail className="h-6 w-6 text-primary-500" aria-hidden="true" />
              </div>
              <h1 className="text-h3 mb-2">Forgot your password?</h1>
              <p className="text-text-secondary">
                No worries. Enter your email and we&apos;ll send you a reset link.
              </p>
            </div>

            {/* Form */}
            <form className="space-y-4">
              <div>
                <label
                  htmlFor="email"
                  className="block text-sm font-medium text-text-primary mb-2"
                >
                  Email address
                </label>
                <input
                  type="email"
                  id="email"
                  name="email"
                  autoComplete="email"
                  required
                  className="input"
                  placeholder="you@example.com"
                />
              </div>

              <button type="submit" className="btn-primary w-full">
                Send reset link
              </button>
            </form>

            {/* Login link */}
            <p className="mt-6 text-center text-sm text-text-secondary">
              Remember your password?{' '}
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
