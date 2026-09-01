# rasputin-control-plane

@~/Documents/Claude/Projects/Rasputin/CLAUDE.md

Go api + agent + proto (see go.work) and the Next.js control-plane UI in `ui/`.
Repo-specific workflow notes below; project-wide context comes from the import above.

## Verifying UI changes (authed pages)

Auth is passkey-only (WebAuthn + Touch ID; 7-day DB-backed session cookie, see
`api/internal/auth/`). A headless/preview browser can therefore **never** log in —
don't burn time trying, and don't add dev-login endpoints or auth bypasses without
asking first (proposed and declined 2026-07-08). The working methodology:

1. **Local stack:** UI dev server on :3000 (`npm run dev` in `ui/`) + the api on
   :8080 — run `RASPUTIN_MESH_BACKEND=mock go run ./api/cmd/rasputin-api` from the
   **repo root** so the default `./data` dir resolves; `data/rasputin.db` already
   holds Bryce's account and passkey credential.

   Add `RASPUTIN_UPDATE_TRUST=dev-permissive` too if `data/trust/root-ca.pem` is
   not present locally: as of 2026-09-01 a missing bundle-signing root CA makes the
   api REFUSE every OS update bundle instead of accepting it unverified, so the
   Updates page's upload and staging paths return 503 until one or the other is in
   place. `scripts/pki-init.sh` is the other, better answer. On hardware neither is
   needed — the OS image bakes the root in.

   The `RASPUTIN_MESH_BACKEND=mock` is required as of 2026-09-01 and is not
   optional boilerplate: the default `auto` no longer falls back to the mock when
   it finds no Headscale and no Docker. A mock mesh mints pre-auth keys and
   invents `100.64.0.x` tailnet addresses that `/api/mesh/devices` then serves as
   real, so inferring it on a controlplane means the control plane reports a mesh
   that does not exist. Without the var the api boots fine and every other page
   works; the mesh pages show an "unavailable" banner and mesh verbs refuse.
2. **Verify through Bryce's real Chrome** (claude-in-chrome MCP tools): navigate to
   `localhost:3000/...`, screenshot/zoom for proof. His Chrome holds the 7-day
   session — the dev loop is fully autonomous while it's valid.
3. **Session expired?** Open `localhost:3000/login` in his Chrome, click "Sign in
   with passkey" to raise the prompt, then ask Bryce for one Touch ID and wait for
   his confirmation. One tap buys another 7 days.
4. **Deployed UI** (`rasputin.local`) can be verified the same way — his Chrome
   keeps a session with the real controlplane too. Remember mutations there hit a
   real cluster.

Unauthenticated pages (`/login`, `/setup`) work fine in the preview browser directly.
Handy always-visible kit components for styling checks: `/metrics` (range Select),
`/firewall/rules` (proto + target Selects in the ADD RULE form). All shared UI
primitives live in `ui/components/kit.tsx` — fix styling there, not per-page.

## Next.js version skew (`ui/`)

`ui/` runs **Next.js 16.3.1** — newer than most model training data, with breaking
changes to APIs, conventions and file structure. Before writing UI code, read the
relevant guide in `ui/node_modules/next/dist/docs/` (`01-app/`, `02-pages/`,
`03-architecture/`) and heed deprecation notices. Re-read after any Next bump.

Next ships that warning itself: `next dev` writes `ui/AGENTS.md` + `ui/CLAUDE.md`
whenever it detects an AI coding agent. **We turned that off** — `agentRules: false`
in `ui/next.config.mjs` (2026-08-31). A nested CLAUDE.md/AGENTS.md loads as project
instructions with the same standing as this file, and that channel carries no
provenance, so an npm package could author instructions nobody reviewed — refreshed on
every version bump, invisible to supply-chain tooling that only inspects code, and
emitted only when the reader is an agent (never in CI or a plain dev run).
Agent-instruction files in this repo are human-authored. **Don't re-enable
`agentRules`** — if the version note above goes stale, fix it here by hand.
