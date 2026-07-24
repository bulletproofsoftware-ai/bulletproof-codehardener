import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-inter',
});

export const metadata: Metadata = {
  title: {
    default: 'Code Hardener - Security for AI-First Developers',
    template: '%s | Code Hardener',
  },
  description:
    'The security platform built for developers using AI coding assistants. 27 open-source tools, plain-language findings, cryptographic attestation.',
  keywords: [
    'AI security',
    'code security',
    'SAST',
    'DAST',
    'SCA',
    'vulnerability scanning',
    'AI code assistant',
    'developer security',
    'security attestation',
    'SBOM',
  ],
  authors: [{ name: 'Code Hardener' }],
  creator: 'Code Hardener',
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://codehardener.com',
    siteName: 'Code Hardener',
    title: 'Code Hardener - Security for AI-First Developers',
    description:
      'The security platform built for developers using AI coding assistants. 27 open-source tools, plain-language findings, cryptographic attestation.',
    images: [
      {
        url: '/og/homepage.png',
        width: 1200,
        height: 630,
        alt: 'Code Hardener - Security for AI-First Developers',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Code Hardener - Security for AI-First Developers',
    description:
      'The security platform built for developers using AI coding assistants.',
    images: ['/og/homepage.png'],
  },
  robots: {
    index: true,
    follow: true,
  },
  icons: {
    icon: '/favicon.ico',
    apple: '/apple-touch-icon.png',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${inter.variable} dark`}>
      <body className="min-h-screen bg-bg-primary text-text-primary antialiased">
        <a href="#main-content" className="skip-link">
          Skip to main content
        </a>
        {children}
      </body>
    </html>
  );
}
