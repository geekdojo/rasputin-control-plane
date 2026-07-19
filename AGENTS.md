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
