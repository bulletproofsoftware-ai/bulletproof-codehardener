import type { Metadata } from 'next';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Terms of Service',
  description: 'Code Hardener terms of service and acceptable use policy.',
};

export default function TermsPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="pt-32 pb-16">
        <div className="container mx-auto px-6">
          <div className="max-w-3xl mx-auto">
            {/* Header */}
            <div className="mb-12">
              <h1 className="text-h1 mb-4">Terms of Service</h1>
              <p className="text-text-secondary">
                Last updated: December 23, 2025
              </p>
            </div>

            {/* Content */}
            <div className="prose prose-invert prose-lg max-w-none">
              <section className="mb-12">
                <h2 className="text-h3 mb-4">1. Agreement to Terms</h2>
                <p className="text-text-secondary">
                  By accessing or using Code Hardener (&quot;Service&quot;), you agree to be bound by these Terms of Service (&quot;Terms&quot;). If you disagree with any part of these terms, you may not access the Service.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">2. Description of Service</h2>
                <p className="text-text-secondary">
                  Code Hardener provides automated security scanning, vulnerability detection, and cryptographic attestation services for software applications. The Service includes web-based tools, APIs, CLI tools, and integrations with third-party development tools.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">3. Account Registration</h2>
                <ul className="list-disc pl-6 text-text-secondary space-y-2">
                  <li>You must provide accurate and complete registration information</li>
                  <li>You are responsible for maintaining the security of your account credentials</li>
                  <li>You must notify us immediately of any unauthorized access</li>
                  <li>You may not share your account with others unless authorized by your plan</li>
                  <li>You must be at least 16 years old to use the Service</li>
                </ul>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">4. Acceptable Use</h2>
                <p className="text-text-secondary mb-4">You agree not to:</p>
                <ul className="list-disc pl-6 text-text-secondary space-y-2">
                  <li>Use the Service to scan code you do not own or have permission to scan</li>
                  <li>Attempt to circumvent rate limits or usage restrictions</li>
                  <li>Use the Service to develop competing products</li>
                  <li>Interfere with or disrupt the Service or servers</li>
                  <li>Use automated means to access the Service except through our APIs</li>
                  <li>Transmit malicious code or viruses</li>
                  <li>Violate any applicable laws or regulations</li>
                </ul>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">5. Intellectual Property</h2>
                <p className="text-text-secondary mb-4">
                  <strong className="text-text-primary">Your Code:</strong> You retain all rights to the source code you submit for scanning. We claim no ownership over your code or scan results.
                </p>
                <p className="text-text-secondary">
                  <strong className="text-text-primary">Our Service:</strong> The Service, including its software, documentation, and branding, is owned by Code Hardener and protected by intellectual property laws. You may not copy, modify, or distribute our Service without permission.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">6. Payment Terms</h2>
                <ul className="list-disc pl-6 text-text-secondary space-y-2">
                  <li>Paid plans are billed in advance on a monthly or annual basis</li>
                  <li>All fees are non-refundable except as required by law</li>
                  <li>We may change pricing with 30 days notice</li>
                  <li>Failed payments may result in service suspension</li>
                  <li>You are responsible for all applicable taxes</li>
                </ul>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">7. Service Level Agreement</h2>
                <p className="text-text-secondary mb-4">
                  For paid plans, we commit to:
                </p>
                <ul className="list-disc pl-6 text-text-secondary space-y-2">
                  <li>99.9% uptime for Pro and Team plans</li>
                  <li>99.99% uptime for Enterprise plans</li>
                  <li>Response times as specified in your plan documentation</li>
                  <li>Service credits for qualifying downtime events</li>
                </ul>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">8. Disclaimer of Warranties</h2>
                <p className="text-text-secondary">
                  THE SERVICE IS PROVIDED &quot;AS IS&quot; WITHOUT WARRANTIES OF ANY KIND. AI HARDENER DOES NOT GUARANTEE THAT SCANS WILL DETECT ALL VULNERABILITIES OR THAT YOUR CODE WILL BE SECURE AFTER USING OUR SERVICE. SECURITY SCANNING IS ONE COMPONENT OF A COMPREHENSIVE SECURITY PROGRAM.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">9. Limitation of Liability</h2>
                <p className="text-text-secondary">
                  TO THE MAXIMUM EXTENT PERMITTED BY LAW, AI HARDENER SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS OR REVENUES, WHETHER INCURRED DIRECTLY OR INDIRECTLY, OR ANY LOSS OF DATA, USE, GOODWILL, OR OTHER INTANGIBLE LOSSES.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">10. Indemnification</h2>
                <p className="text-text-secondary">
                  You agree to indemnify and hold harmless Code Hardener and its officers, directors, employees, and agents from any claims, damages, losses, or expenses arising from your use of the Service or violation of these Terms.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">11. Termination</h2>
                <p className="text-text-secondary">
                  We may terminate or suspend your account immediately, without prior notice, for conduct that we believe violates these Terms or is harmful to other users, us, or third parties. Upon termination, your right to use the Service will cease immediately.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">12. Changes to Terms</h2>
                <p className="text-text-secondary">
                  We reserve the right to modify these Terms at any time. We will provide notice of significant changes via email or through the Service. Your continued use of the Service after changes constitutes acceptance of the new Terms.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">13. Governing Law</h2>
                <p className="text-text-secondary">
                  These Terms shall be governed by the laws of the State of Delaware, United States, without regard to its conflict of law provisions. Any disputes shall be resolved in the courts of Delaware.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">14. Contact</h2>
                <p className="text-text-secondary">
                  For questions about these Terms, contact us at legal@codehardener.com
                </p>
              </section>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
