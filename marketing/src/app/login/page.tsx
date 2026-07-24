import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, Github, Mail } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Login',
  description: 'Sign in to your Code Hardener account to manage your security scans and attestations.',
};

export default function LoginPage() {
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
              <h1 className="text-h3 mb-2">Welcome back</h1>
              <p className="text-text-secondary">
                Sign in to access your security dashboard
              </p>
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
                  or continue with email
                </span>
              </div>
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

              <div>
                <div className="flex items-center justify-between mb-2">
                  <label
                    htmlFor="password"
                    className="block text-sm font-medium text-text-primary"
                  >
                    Password
                  </label>
                  <Link
                    href="/forgot-password"
                    className="text-sm text-primary-500 hover:text-primary-400"
                  >
                    Forgot password?
                  </Link>
                </div>
                <input
                  type="password"
                  id="password"
                  name="password"
                  autoComplete="current-password"
                  required
                  className="input"
                  placeholder="Enter your password"
                />
              </div>

              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="remember"
                  name="remember"
                  className="h-4 w-4 rounded border-border-primary bg-bg-tertiary text-primary-500 focus:ring-primary-500 focus:ring-offset-0"
                />
                <label
                  htmlFor="remember"
                  className="ml-2 text-sm text-text-secondary"
                >
                  Remember me for 30 days
                </label>
              </div>

              <button type="submit" className="btn-primary w-full">
                Sign in
              </button>
            </form>

            {/* Sign up link */}
            <p className="mt-6 text-center text-sm text-text-secondary">
              Don&apos;t have an account?{' '}
              <Link
                href="/signup"
                className="text-primary-500 hover:text-primary-400 font-medium"
              >
                Create one for free
              </Link>
            </p>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
