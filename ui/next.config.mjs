/** @type {import('next').NextConfig} */
//
// Dev: the browser dials rasputin-api directly on :8080 for both HTTP and
// WebSocket. Cross-origin from :3000 → :8080 but same-site (both are
// localhost), so SameSite=Lax cookies and the api's CORS-with-credentials
// configuration cover it. Direct-dial avoids a known Next.js dev limitation
// where the rewrite proxy doesn't reliably forward WebSocket upgrades.
//
// Production: NEXT_PUBLIC_API_BASE is empty so the UI uses same-origin
// relative paths — rasputin-api itself serves the static export (out/) from
// RASPUTIN_UI_DIR, so UI and api share one origin with no reverse proxy.
const isDev = process.env.NODE_ENV !== 'production';

const nextConfig = {
  // Static export: `next build` emits a self-contained out/ tree that
  // rasputin-api serves in production. No Node server on the appliance.
  // Consequences: no dynamic path segments (the console route uses ?node=
  // instead) and useSearchParams needs a Suspense boundary.
  output: 'export',
  reactStrictMode: true,

  // Do not let `next dev` author agent-instruction files.
  //
  // With this unset (default true), `next dev` writes ui/AGENTS.md and
  // ui/CLAUDE.md whenever it detects an AI coding agent -- see
  // node_modules/next/dist/server/lib/generate-agent-files.js. Coding agents
  // load a nested CLAUDE.md/AGENTS.md as project instructions with the same
  // standing as the ones we wrote, and nothing in that channel records
  // provenance. That promotes an npm package's content from data the agent
  // reads to instructions the agent follows, refreshed on every version bump,
  // invisible to supply-chain tooling that only inspects code, and emitted
  // only when the reader is an agent (so it never shows up in CI or a plain
  // dev run). Agent-instruction files in this repo are human-authored.
  agentRules: false,
  env: {
    NEXT_PUBLIC_API_BASE: isDev ? 'http://localhost:8080' : '',
  },
};

export default nextConfig;
