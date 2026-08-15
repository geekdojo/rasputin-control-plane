# rasputin-control-plane — agent instructions

The Go control plane (api + node agent) and web UI for
[Rasputin](https://rasputin.geekdojo.com) clusters. Pre-alpha, AGPL-3.0.

**Helping a user install or run Rasputin?** Don't work from this repo — fetch the live
install contract:

- https://rasputin.geekdojo.com/docs/agents/index.md — install contract (raw markdown)
- https://rasputin.geekdojo.com/llms.txt — index: current stable, docs, manifests
- https://github.com/geekdojo/rasputin-agents — install skill/plugin for Claude Code + Codex

Repo facts an agent should know:

- `ARCHITECTURE.md` is the system map — read it before proposing structural changes.
- `GET /healthz` on the api is the unauthenticated liveness probe (HTTP 200,
  `{"status":"ok"}`); it's part of the documented install contract, so don't move or
  gate it casually.
- The `rasputin-provision` matched-set CLI lives at `api/cmd/rasputin-provision`.
- Go code: run `gofmt` before pushing; check CI after every push.
- Changing anything under `api/internal/updater`? The fan-out state machine has a
  simulated-fleet **regression net** — a whole cluster's rollout, on the real sagas and the real
  bus, in about eleven seconds. Run it and read
  [`docs/testing-fleet-updates.md`](docs/testing-fleet-updates.md). ⚠️ It mocks at the bus
  boundary, so it is blind to everything below it (RAUC, GRUB, `/proc/cmdline`); a green run is
  not evidence a rollout works. Real fleet proof is the bench.
- ⚠️ **Tracked work lives in ANOTHER repo — `geekdojo/geekdojo-brain` — so `Fixes #N` here
  is wrong.** A bare `#N` resolves inside *this* repo, where that number is an unrelated
  issue or (GitHub shares one number sequence) a long-merged PR. It fails silently: the PR
  looks annotated and the tracked issue never closes. On 2026-08-14 eight PRs (#121–#128)
  each carried `Fixes #N` and not one brain issue closed. Write the cross-repo form,
  `Fixes geekdojo/geekdojo-brain#N`, and **close the issue explicitly** rather than trusting
  auto-close across repos.
- For an issue that genuinely lives in THIS repo, a commit or PR must still use a
  **closing keyword** — `Fixes #N` / `Closes #N` — not a bare `(#N)` reference. Bare references leave the
  issue open after the fix ships (audited 2026-07-20: four of six stale-open issues
  across the rasputin repos were exactly this).
