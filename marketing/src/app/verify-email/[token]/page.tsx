import type { Metadata } from 'next';
import Link from 'next/link';
import { CheckCircle, AlertCircle, Mail, ArrowRight } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Verify Email',
  description: 'Verify your email address to complete your Code Hardener account setup.',
};

interface PageProps {
  params: Promise<{ token: string }>;
}

export default async function VerifyEmailPage({ params }: PageProps) {
  const resolvedParams = await params;
  const token = resolvedParams.token;

  // In a real app, we would validate the token server-side
  // For demo purposes, we'll show success for valid-looking tokens
  const isValidToken = token && token.length > 10;

  if (!isValidToken) {
    return (
      <>
        <Header />
        <main id="main-content" className="pt-32 pb-16 min-h-screen">
          <div className="container mx-auto px-6">
            <div className="max-w-md mx-auto">
              <div className="card p-8 text-center">
                <div className="w-20 h-20 rounded-full bg-error/10 flex items-center justify-center mx-auto mb-6">
                  <AlertCircle className="h-10 w-10 text-error" aria-hidden="true" />
                </div>
                <h1 className="text-h2 mb-4">Verification Failed</h1>
                <p className="text-text-secondary mb-8">
                  This verification link is invalid or has expired. Please request a new verification email.
                </p>
                <div className="space-y-3">
                  <button type="button" className="btn-primary w-full justify-center">
                    <Mail className="h-5 w-5" aria-hidden="true" />
                    Resend Verification Email
                  </button>
                  <Link
                    href="/login"
                    className="btn-secondary w-full justify-center"
                  >
                    Back to Login
                  </Link>
                </div>
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
            <div className="card p-8 text-center">
              {/* Success Icon */}
              <div className="w-20 h-20 rounded-full bg-success/10 flex items-center justify-center mx-auto mb-6">
                <CheckCircle className="h-10 w-10 text-success" aria-hidden="true" />
              </div>

              {/* Success Message */}
              <h1 className="text-h2 mb-4">Email Verified!</h1>
              <p className="text-text-secondary mb-8">
                Your email address has been successfully verified. You can now access all features of your Code Hardener account.
              </p>

              {/* Next Steps */}
              <div className="space-y-4 mb-8">
                <div className="p-4 bg-bg-secondary rounded-lg text-left">
                  <h2 className="font-medium text-text-primary mb-3">Get started:</h2>
                  <ul className="space-y-3">
                    <li className="flex items-start gap-3">
                      <span className="w-6 h-6 rounded-full bg-primary-500/10 text-primary-500 flex items-center justify-center text-sm font-medium flex-shrink-0">
                        1
                      </span>
                      <span className="text-sm text-text-secondary">
                        Install the CLI to start scanning your code
                      </span>
                    </li>
                    <li className="flex items-start gap-3">
                      <span className="w-6 h-6 rounded-full bg-primary-500/10 text-primary-500 flex items-center justify-center text-sm font-medium flex-shrink-0">
                        2
                      </span>
                      <span className="text-sm text-text-secondary">
                        Create your first project and run a scan
                      </span>
                    </li>
                    <li className="flex items-start gap-3">
                      <span className="w-6 h-6 rounded-full bg-primary-500/10 text-primary-500 flex items-center justify-center text-sm font-medium flex-shrink-0">
                        3
                      </span>
                      <span className="text-sm text-text-secondary">
                        Set up CI/CD integration for automated scanning
                      </span>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Actions */}
              <div className="space-y-3">
                <Link
                  href="/dashboard"
                  className="btn-primary w-full justify-center"
                >
                  Go to Dashboard
                  <ArrowRight className="h-5 w-5" aria-hidden="true" />
                </Link>
                <Link
                  href="/docs/quickstart"
                  className="btn-secondary w-full justify-center"
                >
                  Read Quickstart Guide
                </Link>
              </div>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
