import type { Metadata } from 'next';
import Link from 'next/link';
import { Lock, ArrowLeft, Check, AlertCircle } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Reset Password',
  description: 'Create a new password for your Code Hardener account.',
};

interface PageProps {
  params: Promise<{ token: string }>;
}

export default async function ResetPasswordPage({ params }: PageProps) {
  const resolvedParams = await params;
  const token = resolvedParams.token;

  // In a real app, we would validate the token here
  const isValidToken = token && token.length > 10;

  if (!isValidToken) {
    return (
      <>
        <Header />
        <main id="main-content" className="pt-32 pb-16 min-h-screen">
          <div className="container mx-auto px-6">
            <div className="max-w-md mx-auto">
              <div className="card p-8 text-center">
                <div className="w-16 h-16 rounded-full bg-error/10 flex items-center justify-center mx-auto mb-6">
                  <AlertCircle className="h-8 w-8 text-error" aria-hidden="true" />
                </div>
                <h1 className="text-h2 mb-4">Invalid or Expired Link</h1>
                <p className="text-text-secondary mb-8">
                  This password reset link is invalid or has expired. Please request a new one.
                </p>
                <Link href="/forgot-password" className="btn-primary w-full justify-center">
                  Request New Link
                </Link>
              </div>
            </div>
          </div>
        </main>
        <Footer />
      </>
    );
  }

  return (
    <>
      <Header />
      <main id="main-content" className="pt-32 pb-16 min-h-screen">
        <div className="container mx-auto px-6">
          <div className="max-w-md mx-auto">
            {/* Back link */}
            <Link
              href="/login"
              className="inline-flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors mb-8"
            >
              <ArrowLeft className="h-4 w-4" aria-hidden="true" />
              Back to login
            </Link>

            <div className="card p-8">
              {/* Header */}
              <div className="text-center mb-8">
                <div className="w-16 h-16 rounded-full bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center mx-auto mb-6">
                  <Lock className="h-8 w-8 text-white" aria-hidden="true" />
                </div>
                <h1 className="text-h2 mb-2">Create New Password</h1>
                <p className="text-text-secondary">
                  Enter your new password below.
                </p>
              </div>

              {/* Reset Form */}
              <form className="space-y-6">
                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-text-primary mb-2">
                    New Password
                  </label>
                  <input
                    id="password"
                    name="password"
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={12}
                    className="input w-full"
                    placeholder="Enter new password"
                  />
                </div>

                <div>
                  <label htmlFor="confirmPassword" className="block text-sm font-medium text-text-primary mb-2">
                    Confirm New Password
                  </label>
                  <input
                    id="confirmPassword"
                    name="confirmPassword"
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={12}
                    className="input w-full"
                    placeholder="Confirm new password"
                  />
                </div>

                {/* Password Requirements */}
                <div className="p-4 bg-bg-secondary rounded-lg">
                  <p className="text-sm font-medium text-text-primary mb-3">
                    Password requirements:
                  </p>
                  <ul className="space-y-2">
                    {[
                      'At least 12 characters long',
                      'Contains at least one uppercase letter',
                      'Contains at least one lowercase letter',
                      'Contains at least one number',
                      'Contains at least one special character',
                    ].map((requirement) => (
                      <li
                        key={requirement}
                        className="flex items-center gap-2 text-sm text-text-secondary"
                      >
                        <Check className="h-4 w-4 text-text-tertiary" aria-hidden="true" />
                        {requirement}
                      </li>
                    ))}
                  </ul>
                </div>

                <button type="submit" className="btn-primary w-full justify-center">
                  Reset Password
                </button>
              </form>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
