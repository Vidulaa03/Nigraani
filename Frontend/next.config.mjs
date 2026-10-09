/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Keep dev output isolated from production builds so `next build` cannot
  // replace chunks currently being served by `next dev`.
  distDir: process.env.NODE_ENV === "development" ? ".next-dev" : ".next-build",
};

export default nextConfig;
