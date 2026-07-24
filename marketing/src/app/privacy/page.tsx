import type { Metadata } from 'next';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Privacy Policy',
  description: 'Code Hardener privacy policy. Learn how we collect, use, and protect your data.',
};

export default function PrivacyPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="pt-32 pb-16">
        <div className="container mx-auto px-6">
          <div className="max-w-3xl mx-auto">
            {/* Header */}
            <div className="mb-12">
              <h1 className="text-h1 mb-4">Privacy Policy</h1>
              <p className="text-text-secondary">
                Last updated: December 23, 2025
              </p>
            </div>

            {/* Content */}
            <div className="prose prose-invert prose-lg max-w-none">
              <section className="mb-12">
                <h2 className="text-h3 mb-4">1. Introduction</h2>
                <p className="text-text-secondary mb-4">
                  Code Hardener (&quot;we,&quot; &quot;our,&quot; or &quot;us&quot;) is committed to protecting your privacy. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our security scanning platform and related services.
                </p>
                <p className="text-text-secondary">
                  By using Code Hardener, you agree to the collection and use of information in accordance with this policy.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">2. Information We Collect</h2>

                <h3 className="text-h4 mb-3">2.1 Information You Provide</h3>
                <ul className="list-disc pl-6 text-text-secondary mb-4 space-y-2">
                  <li>Account information (name, email, password)</li>
                  <li>Payment information (processed securely via Stripe)</li>
                  <li>Source code submitted for security scanning</li>
                  <li>API keys and integration credentials</li>
                  <li>Support requests and communications</li>
                </ul>

                <h3 className="text-h4 mb-3">2.2 Information Collected Automatically</h3>
                <ul className="list-disc pl-6 text-text-secondary mb-4 space-y-2">
                  <li>Usage data (scans performed, features used)</li>
                  <li>Device information (browser type, operating system)</li>
                  <li>IP address and approximate location</li>
                  <li>Cookies and similar tracking technologies</li>
                </ul>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">3. How We Use Your Information</h2>
                <ul className="list-disc pl-6 text-text-secondary space-y-2">
                  <li>Provide and maintain our security scanning services</li>
                  <li>Process transactions and send related information</li>
                  <li>Respond to your comments, questions, and requests</li>
                  <li>Send you technical notices, updates, and security alerts</li>
                  <li>Monitor and analyze usage patterns to improve our services</li>
                  <li>Detect, prevent, and address technical issues</li>
                  <li>Comply with legal obligations</li>
                </ul>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">4. Code and Scan Data</h2>
                <p className="text-text-secondary mb-4">
                  We take special care with your source code and scan results:
                </p>
                <ul className="list-disc pl-6 text-text-secondary space-y-2">
                  <li>Source code is processed in isolated, ephemeral containers</li>
                  <li>Code is automatically deleted after scanning unless you opt to retain it</li>
                  <li>Scan results are encrypted at rest and in transit</li>
                  <li>We never share your code or findings with third parties</li>
                  <li>Enterprise customers can use self-hosted options for complete data control</li>
                </ul>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">5. Data Retention</h2>
                <p className="text-text-secondary">
                  We retain your personal information for as long as your account is active or as needed to provide services. Scan results are retained for 90 days by default, or longer based on your plan settings. You may request deletion of your data at any time.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">6. Data Sharing and Disclosure</h2>
                <p className="text-text-secondary mb-4">
                  We do not sell your personal information. We may share information only in these circumstances:
                </p>
                <ul className="list-disc pl-6 text-text-secondary space-y-2">
                  <li>With service providers who assist in our operations (under strict confidentiality)</li>
                  <li>To comply with legal obligations or valid legal process</li>
                  <li>To protect our rights, privacy, safety, or property</li>
                  <li>In connection with a merger, acquisition, or sale of assets</li>
                </ul>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">7. Security</h2>
                <p className="text-text-secondary">
                  We implement industry-standard security measures including encryption in transit (TLS 1.3) and at rest (AES-256), regular security audits, SOC 2 Type II compliance, and continuous monitoring. However, no method of transmission over the Internet is 100% secure.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">8. Your Rights</h2>
                <p className="text-text-secondary mb-4">
                  Depending on your location, you may have the following rights:
                </p>
                <ul className="list-disc pl-6 text-text-secondary space-y-2">
                  <li>Access and receive a copy of your personal data</li>
                  <li>Rectify inaccurate personal data</li>
                  <li>Request deletion of your personal data</li>
                  <li>Object to or restrict processing of your data</li>
                  <li>Data portability</li>
                  <li>Withdraw consent at any time</li>
                </ul>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">9. International Transfers</h2>
                <p className="text-text-secondary">
                  Your information may be transferred to and processed in countries other than your own. We ensure appropriate safeguards are in place, including Standard Contractual Clauses for transfers from the EU/EEA.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">10. Children&apos;s Privacy</h2>
                <p className="text-text-secondary">
                  Code Hardener is not intended for use by individuals under 16 years of age. We do not knowingly collect personal information from children.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">11. Changes to This Policy</h2>
                <p className="text-text-secondary">
                  We may update this Privacy Policy from time to time. We will notify you of any changes by posting the new policy on this page and updating the &quot;Last updated&quot; date.
                </p>
              </section>

              <section className="mb-12">
                <h2 className="text-h3 mb-4">12. Contact Us</h2>
                <p className="text-text-secondary">
                  If you have questions about this Privacy Policy, please contact us at:
                </p>
                <ul className="list-none text-text-secondary mt-4 space-y-1">
                  <li>Email: privacy@codehardener.com</li>
                  <li>Address: Code Hardener, Inc.</li>
                </ul>
              </section>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
