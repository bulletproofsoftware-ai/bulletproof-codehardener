import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, Calendar, Clock, Share2, Twitter, Linkedin, Link as LinkIcon } from 'lucide-react';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';

// This would typically come from a CMS or database
const posts: Record<string, {
  title: string;
  excerpt: string;
  date: string;
  readTime: string;
  category: string;
  author: { name: string; role: string };
  content: string;
}> = {
  'introducing-mcp-integration': {
    title: 'Introducing MCP Integration: Real-Time Security for Claude Code',
    excerpt: 'Today we are announcing native Model Context Protocol (MCP) support, bringing Code Hardener security scanning directly into your Claude Code workflow.',
    date: '2025-12-20',
    readTime: '5 min read',
    category: 'Product',
    author: { name: 'Sarah Martinez', role: 'CTO & Co-founder' },
    content: `
Today, we're excited to announce our integration with Claude Code through the Model Context Protocol (MCP). This represents a significant step forward in our mission to make security scanning seamless for developers using AI coding assistants.

## Why MCP Matters

The Model Context Protocol is Anthropic's open standard for connecting AI assistants with external tools and data sources. By implementing MCP support, Code Hardener can now provide real-time security feedback directly within your Claude Code sessions.

This means you no longer need to switch contexts to run security scans. As Claude generates code, you can immediately check it for vulnerabilities, get explanations of findings, and receive AI-powered fix suggestions—all without leaving your workflow.

## Key Features

### Real-Time Scanning
Scan code snippets or entire files instantly with a simple \`@codehardener scan\` command. Results appear directly in your Claude Code conversation.

### Context-Aware Findings
Claude can see and understand Code Hardener's findings, enabling it to provide more informed remediation suggestions that take your specific codebase into account.

### Automatic Fix Generation
When issues are found, use \`@codehardener fix\` to get AI-generated fix suggestions that Claude can apply directly to your code.

### Attestation Generation
Generate Sigstore-signed attestations directly from Claude Code with \`@codehardener attest\`, creating cryptographic proof of your security posture.

## Getting Started

Installation takes just a few minutes:

1. Install the MCP server: \`npm install -g @codehardener/mcp-server\`
2. Add the configuration to your \`~/.claude/mcp.json\`
3. Restart Claude Code

For detailed instructions, check out our [MCP Integration documentation](/docs/mcp).

## What's Next

This is just the beginning of our AI editor integrations. We're actively working on similar integrations for Cursor, Windsurf, and other AI-powered development environments.

We'd love to hear your feedback on the MCP integration. Join our [Discord community](https://discord.gg/codehardener) or reach out to us on [Twitter](https://twitter.com/codehardener).
    `,
  },
  'state-of-ai-code-security-2025': {
    title: 'The State of AI-Generated Code Security in 2025',
    excerpt: 'We analyzed 10 million scans to understand the most common vulnerabilities in AI-generated code. Here is what we found.',
    date: '2025-12-15',
    readTime: '8 min read',
    category: 'Research',
    author: { name: 'Alex Chen', role: 'CEO & Co-founder' },
    content: `
Over the past year, Code Hardener has processed over 10 million security scans. We've analyzed this data to understand the current state of AI-generated code security and share our findings with the developer community.

## Key Findings

### 45% of AI-Generated Code Contains Vulnerabilities

Our data confirms what earlier studies suggested: nearly half of all AI-generated code contains at least one security vulnerability. This number has remained relatively stable throughout 2025, despite improvements in AI models.

### Top 5 Vulnerability Categories

1. **Injection Flaws (23%)** - SQL injection, command injection, and XSS remain the most common issues
2. **Hardcoded Credentials (18%)** - API keys, passwords, and secrets embedded in code
3. **Insecure Cryptography (15%)** - Weak algorithms, poor key management
4. **Missing Input Validation (12%)** - Insufficient sanitization of user input
5. **Insecure Dependencies (11%)** - Outdated or vulnerable packages

### Language-Specific Trends

Python and JavaScript/TypeScript account for 78% of all scans, reflecting their popularity in AI-assisted development. Interestingly, Python code shows a higher rate of injection vulnerabilities (28%), while JavaScript has more issues with insecure dependencies (15%).

## Recommendations

Based on our analysis, we recommend:

1. **Always scan AI-generated code** - Never deploy without security review
2. **Focus on input validation** - The most impactful mitigation
3. **Use secrets scanning** - Prevent credential leaks before they happen
4. **Keep dependencies updated** - Automate vulnerability patching
5. **Enable auto-remediation** - Fix common issues automatically

## Methodology

This analysis covers scans performed between January 1, 2025 and December 1, 2025, across 50,000+ unique projects. We normalized data to account for project size and scan frequency.

For the full report with additional data and visualizations, [download the PDF](/reports/ai-code-security-2025.pdf).
    `,
  },
};

interface PageProps {
  params: Promise<{ slug: string }>;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const resolvedParams = await params;
  const post = posts[resolvedParams.slug];

  if (!post) {
    return { title: 'Post Not Found' };
  }

  return {
    title: post.title,
    description: post.excerpt,
    openGraph: {
      title: post.title,
      description: post.excerpt,
      type: 'article',
      publishedTime: post.date,
      authors: [post.author.name],
    },
  };
}

function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

export default async function BlogPostPage({ params }: PageProps) {
  const resolvedParams = await params;
  const post = posts[resolvedParams.slug];

  if (!post) {
    return (
      <>
        <Header />
        <main id="main-content" className="pt-32 pb-16">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mx-auto text-center">
              <h1 className="text-h1 mb-4">Post Not Found</h1>
              <p className="text-text-secondary mb-8">
                The blog post you&apos;re looking for doesn&apos;t exist.
              </p>
              <Link href="/blog" className="btn-primary">
                Back to Blog
              </Link>
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
      <main id="main-content" className="pt-32 pb-16">
        <article className="container mx-auto px-6">
          <div className="max-w-3xl mx-auto">
            {/* Back link */}
            <Link
              href="/blog"
              className="inline-flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors mb-8"
            >
              <ArrowLeft className="h-4 w-4" aria-hidden="true" />
              Back to blog
            </Link>

            {/* Header */}
            <header className="mb-12">
              <div className="flex items-center gap-4 mb-6">
                <span className="px-3 py-1 rounded-full bg-primary-500/10 text-primary-500 text-sm font-medium">
                  {post.category}
                </span>
                <span className="flex items-center gap-1 text-sm text-text-tertiary">
                  <Calendar className="h-4 w-4" aria-hidden="true" />
                  {formatDate(post.date)}
                </span>
                <span className="flex items-center gap-1 text-sm text-text-tertiary">
                  <Clock className="h-4 w-4" aria-hidden="true" />
                  {post.readTime}
                </span>
              </div>

              <h1 className="text-h1 mb-6">{post.title}</h1>
              <p className="text-xl text-text-secondary">{post.excerpt}</p>

              {/* Author */}
              <div className="flex items-center gap-4 mt-8 pt-8 border-t border-border-primary">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-primary-500 to-accent-500" />
                <div>
                  <p className="font-medium text-text-primary">{post.author.name}</p>
                  <p className="text-sm text-text-secondary">{post.author.role}</p>
                </div>
              </div>
            </header>

            {/* Content */}
            <div className="prose prose-invert prose-lg max-w-none">
              {post.content.split('\n\n').map((paragraph, index) => {
                if (paragraph.startsWith('## ')) {
                  return (
                    <h2 key={index} className="text-h3 mt-12 mb-4">
                      {paragraph.replace('## ', '')}
                    </h2>
                  );
                }
                if (paragraph.startsWith('### ')) {
                  return (
                    <h3 key={index} className="text-h4 mt-8 mb-3">
                      {paragraph.replace('### ', '')}
                    </h3>
                  );
                }
                if (paragraph.startsWith('1. ') || paragraph.startsWith('- ')) {
                  const items = paragraph.split('\n');
                  const isOrdered = paragraph.startsWith('1.');
                  const ListTag = isOrdered ? 'ol' : 'ul';
                  return (
                    <ListTag key={index} className={`${isOrdered ? 'list-decimal' : 'list-disc'} pl-6 text-text-secondary space-y-2 my-4`}>
                      {items.map((item, i) => (
                        <li key={i}>
                          {item.replace(/^\d+\.\s\*\*|\*\*\s-\s|\*\*/g, '').replace(/\*\*/g, '')}
                        </li>
                      ))}
                    </ListTag>
                  );
                }
                if (paragraph.trim()) {
                  return (
                    <p key={index} className="text-text-secondary my-4">
                      {paragraph.trim()}
                    </p>
                  );
                }
                return null;
              })}
            </div>

            {/* Share */}
            <div className="mt-12 pt-8 border-t border-border-primary">
              <div className="flex items-center justify-between">
                <p className="text-sm text-text-secondary flex items-center gap-2">
                  <Share2 className="h-4 w-4" aria-hidden="true" />
                  Share this article
                </p>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    className="p-2 rounded-lg bg-bg-secondary hover:bg-bg-tertiary transition-colors"
                    aria-label="Share on Twitter"
                  >
                    <Twitter className="h-5 w-5 text-text-secondary" aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    className="p-2 rounded-lg bg-bg-secondary hover:bg-bg-tertiary transition-colors"
                    aria-label="Share on LinkedIn"
                  >
                    <Linkedin className="h-5 w-5 text-text-secondary" aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    className="p-2 rounded-lg bg-bg-secondary hover:bg-bg-tertiary transition-colors"
                    aria-label="Copy link"
                  >
                    <LinkIcon className="h-5 w-5 text-text-secondary" aria-hidden="true" />
                  </button>
                </div>
              </div>
            </div>

            {/* Related posts would go here */}
          </div>
        </article>
      </main>
      <Footer />
    </>
  );
}

export async function generateStaticParams() {
  return Object.keys(posts).map((slug) => ({ slug }));
}
