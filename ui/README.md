# rasputin-ui

Next.js (App Router, TypeScript) frontend for the Rasputin control plane.

Talks to `rasputin-api` over REST + WebSocket. In dev, `next.config.mjs` proxies `/api/*` and `/ws/*` to `http://127.0.0.1:8080`. In production, the api serves the built UI behind the same origin.

## Dev

```sh
npm install
npm run dev
```

Open http://localhost:3000.
