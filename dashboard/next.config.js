/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  images: {
    domains: ['localhost', 'api.codehardener.dev'],
  },
  async rewrites() {
    // Use API_URL for server-side rewrites (Docker internal), NEXT_PUBLIC_API_URL for client
    const serverApiUrl = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';
    return [
      {
        source: '/api/:path*',
        destination: `${serverApiUrl}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
