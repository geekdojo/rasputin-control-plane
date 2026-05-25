/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // In dev, proxy API + WebSocket to rasputin-api on localhost:8080.
  // In production, api and ui are served behind the same reverse proxy.
  async rewrites() {
    return [
      { source: '/api/:path*', destination: 'http://127.0.0.1:8080/api/:path*' },
      { source: '/ws/:path*',  destination: 'http://127.0.0.1:8080/ws/:path*' },
    ];
  },
};

export default nextConfig;
