# rasputin-control-plane

Monorepo for the Rasputin control plane: API, web UI, and node agent.

## Layout

- `api/` — `rasputin-api`, the Go backend. Embeds NATS + JetStream and SQLite. The only thing that mutates system state, and only via the universal Job model.
- `agent/` — `rasputin-agent`, the Go binary that runs on every node (including the control plane node itself). Dials NATS outbound, executes commands, emits events.
- `proto/` — Wire schemas shared between `api` and `agent`.
- `ui/` — Next.js (App Router, TypeScript) frontend. Talks to `rasputin-api` over REST + WebSocket on localhost.
- `deploy/` — systemd units, RAUC bundle recipes, sidecar compose files (VictoriaMetrics, Loki, Grafana, Headscale).
- `docs/` — Repo-local engineering notes. Architectural source of truth lives in the geekdojo-wiki at `projects/rasputin/design/control-plane/`.

## Build

```sh
# Go side (api + agent share go.work).
# Name the modules explicitly — `./...` from the workspace root doesn't
# expand into workspace submodules when the root itself isn't a module.
go build ./api/... ./agent/...

# UI
cd ui && npm install && npm run dev
```

## See also

- Architecture: `projects/rasputin/design/control-plane/architecture.md` in the geekdojo-wiki.
- Project-level context: `Claude.md` in the parent `rasputin/` folder.
