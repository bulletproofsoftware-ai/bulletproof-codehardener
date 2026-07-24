import type { Metadata } from 'next';
import Link from 'next/link';
import { Calendar, Clock, ArrowRight, Tag } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'Blog',
  description: 'Code Hardener blog. Security insights, product updates, and developer guides for AI-assisted development.',
};

const featuredPost = {
  slug: 'introducing-mcp-integration',
  title: 'Introducing MCP Integration: Real-Time Security for Claude Code',
  excerpt: 'Today we are announcing native Model Context Protocol (MCP) support, bringing Code Hardener security scanning directly into your Claude Code workflow.',
  date: '2025-12-20',
  readTime: '5 min read',
  category: 'Product',
  image: '/blog/mcp-integration.png',
};

const posts = [
  {
    slug: 'state-of-ai-code-security-2025',
    title: 'The State of AI-Generated Code Security in 2025',
    excerpt: 'We analyzed 10 million scans to understand the most common vulnerabilities in AI-generated code. Here is what we found.',
    date: '2025-12-15',
    readTime: '8 min read',
    category: 'Research',
  },
  {
    slug: 'securing-cursor-workflows',
    title: 'How to Secure Your Cursor AI Workflows',
    excerpt: 'A practical guide to integrating security scanning into your Cursor-based development process.',
    date: '2025-12-10',
    readTime: '6 min read',
    category: 'Tutorial',
  },
  {
    slug: 'sigstore-attestations-explained',
    title: 'Sigstore Attestations Explained: Cryptographic Proof for Your Code',
    excerpt: 'Understanding how Code Hardener uses Sigstore to create tamper-proof attestations for compliance and audit purposes.',
    date: '2025-12-05',
    readTime: '7 min read',
    category: 'Deep Dive',
  },
  {
    slug: 'sql-injection-ai-code',
    title: 'Why AI Assistants Keep Generating SQL Injection Vulnerabilities',
    excerpt: 'An analysis of why SQL injection remains the most common vulnerability in AI-generated code and how to prevent it.',
    date: '2025-11-28',
    readTime: '5 min read',
    category: 'Research',
  },
  {
    slug: 'github-actions-security-pipeline',
    title: 'Building a Complete Security Pipeline with GitHub Actions',
    excerpt: 'Step-by-step guide to creating a comprehensive security scanning pipeline using Code Hardener and GitHub Actions.',
    date: '2025-11-20',
    readTime: '10 min read',
    category: 'Tutorial',
  },
  {
    slug: 'soc2-compliance-developers',
    title: 'SOC 2 Compliance for Developers: What You Actually Need to Know',
    excerpt: 'A developer-friendly guide to understanding SOC 2 requirements and how Code Hardener helps you achieve compliance.',
    date: '2025-11-15',
    readTime: '8 min read',
    category: 'Compliance',
  },
];

const categories = ['All', 'Product', 'Research', 'Tutorial', 'Deep Dive', 'Compliance'];

function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

export default function BlogPage() {
  return (
    <>
      <Header />
      <main id="main-content" className="pt-32 pb-16">
        <div className="container mx-auto px-6">
          {/* Header */}
          <div className="max-w-3xl mx-auto text-center mb-16">
            <h1 className="text-h1 mb-6">Blog</h1>
            <p className="text-xl text-text-secondary">
              Security insights, product updates, and guides for developers building with AI assistants.
            </p>
          </div>

          {/* Categories */}
          <div className="flex flex-wrap items-center justify-center gap-2 mb-12">
            {categories.map((category, index) => (
              <button
                key={category}
                type="button"
                className={`px-4 py-2 rounded-full text-sm font-medium transition-colors ${
                  index === 0
                    ? 'bg-primary-500 text-white'
                    : 'bg-bg-secondary text-text-secondary hover:text-text-primary hover:bg-bg-tertiary'
                }`}
              >
                {category}
              </button>
            ))}
          </div>

          {/* Featured Post */}
          <div className="mb-16">
            <Link
              href={`/blog/${featuredPost.slug}`}
              className="block card-interactive overflow-hidden group"
            >
              <div className="grid md:grid-cols-2 gap-0">
                <div className="aspect-video md:aspect-auto bg-gradient-to-br from-primary-500/20 to-accent-500/20 flex items-center justify-center">
                  <div className="text-center p-8">
                    <div className="w-16 h-16 rounded-full bg-gradient-to-br from-primary-500 to-accent-500 mx-auto mb-4 flex items-center justify-center">
                      <span className="text-2xl font-bold text-white">MCP</span>
                    </div>
                    <p className="text-sm text-text-tertiary">Featured Image</p>
                  </div>
                </div>
                <div className="p-8 flex flex-col justify-center">
                  <div className="flex items-center gap-4 mb-4">
                    <span className="px-3 py-1 rounded-full bg-primary-500/10 text-primary-500 text-xs font-medium">
                      {featuredPost.category}
                    </span>
                    <span className="text-xs text-text-tertiary uppercase tracking-wider">
                      Featured
                    </span>
                  </div>
                  <h2 className="text-h3 mb-3 group-hover:text-primary-400 transition-colors">
                    {featuredPost.title}
                  </h2>
                  <p className="text-text-secondary mb-4">{featuredPost.excerpt}</p>
                  <div className="flex items-center gap-4 text-sm text-text-tertiary">
                    <span className="flex items-center gap-1">
                      <Calendar className="h-4 w-4" aria-hidden="true" />
                      {formatDate(featuredPost.date)}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-4 w-4" aria-hidden="true" />
                      {featuredPost.readTime}
                    </span>
                  </div>
                </div>
              </div>
            </Link>
          </div>

          {/* Post Grid */}
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {posts.map((post) => (
              <Link
                key={post.slug}
                href={`/blog/${post.slug}`}
                className="card-interactive p-6 group"
              >
                <div className="flex items-center gap-2 mb-4">
                  <Tag className="h-4 w-4 text-text-tertiary" aria-hidden="true" />
                  <span className="text-xs text-text-tertiary uppercase tracking-wider">
                    {post.category}
                  </span>
                </div>
                <h2 className="text-h4 mb-3 group-hover:text-primary-400 transition-colors line-clamp-2">
                  {post.title}
                </h2>
                <p className="text-sm text-text-secondary mb-4 line-clamp-3">
                  {post.excerpt}
                </p>
                <div className="flex items-center justify-between text-sm text-text-tertiary">
                  <span>{formatDate(post.date)}</span>
                  <span>{post.readTime}</span>
                </div>
              </Link>
            ))}
          </div>

          {/* Load More */}
          <div className="text-center mt-12">
            <button type="button" className="btn-secondary">
              Load more posts
              <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>

          {/* Newsletter */}
          <div className="mt-20 max-w-2xl mx-auto text-center">
            <div className="card p-8">
              <h2 className="text-h3 mb-4">Subscribe to our newsletter</h2>
              <p className="text-text-secondary mb-6">
                Get the latest security insights and product updates delivered to your inbox.
              </p>
              <form className="flex flex-col sm:flex-row gap-3">
                <input
                  type="email"
                  placeholder="you@example.com"
                  className="input flex-1"
                  required
                />
                <button type="submit" className="btn-primary whitespace-nowrap">
                  Subscribe
                </button>
              </form>
              <p className="text-xs text-text-tertiary mt-4">
                No spam. Unsubscribe anytime.
              </p>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
