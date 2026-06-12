# rasputin-ui

Next.js (App Router, TypeScript) frontend for the Rasputin control plane.

Talks to `rasputin-api` over REST + WebSocket. In dev, the browser dials the api directly on `http://localhost:8080` (see `next.config.mjs`). In production, `npm run build` emits a static export (`out/`) that `rasputin-api` itself serves from `RASPUTIN_UI_DIR` (default `/usr/share/rasputin/ui` — where the OS image installs it), so UI and api share one origin.

Static-export constraints to keep in mind when adding routes:

- No dynamic path segments — pass runtime ids as query params (the console route is `/console?node=<id>`).
- `useSearchParams` needs a `<Suspense>` boundary.

## Dev

```sh
npm install
npm run dev
```

Open http://localhost:3000.

## Production-shaped local run

```sh
npm run build
cd ../api && RASPUTIN_UI_DIR=../ui/out go run ./cmd/rasputin-api
```

Open http://localhost:8080.
