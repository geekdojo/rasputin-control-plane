# rasputin-api

The Go backend for Rasputin's control plane. Single binary; embeds NATS + JetStream and SQLite. Owns the universal Job ledger and the Saga runner.

## Subsystems

| Package | Purpose |
|---|---|
| `internal/bus` | Embedded NATS server + JetStream config + subject registry |
| `internal/jobs` | Job ledger, Saga runner, retry/restart logic |
| `internal/inventory` | Nodes, slots, identities |
| `internal/bmc` | Onboard BMC bridge (power, reset, serial-over-LAN) |
| `internal/updater` | RAUC bundle hosting + update orchestration |
| `internal/apps` | Docker Compose app catalog + deploy logic |
| `internal/firewall` | OpenWrt intent → UCI reconciliation |
| `internal/obs` | VictoriaMetrics / Loki / Grafana lifecycle |
| `internal/auth` | WebAuthn / passkey auth, sessions |
| `internal/api` | HTTP handlers, WebSocket upgrades |

## Run

```sh
go run ./cmd/rasputin-api
```

## Dev opt-ins

Two subsystems refuse to work rather than invent an answer when their
prerequisites are absent, and both are reached in dev by NAMING the fallback —
never by inference, because an inferred fallback on real hardware produces a
confident, plausible, wrong answer (`agent/internal/configfault` has the
incident that settled this):

| Variable | Default | Dev value | Without it |
|---|---|---|---|
| `RASPUTIN_MESH_BACKEND` | `auto` | `mock` | With no Headscale and no Docker the mesh is *unavailable*; the api boots, mesh verbs refuse |
| `RASPUTIN_UPDATE_TRUST` | `require` | `dev-permissive` | With no `$RASPUTIN_TRUST_DIR/root-ca.pem` OS update bundles are *refused* (503); the api boots, everything else works |

`RASPUTIN_UPDATE_TRUST=dev-permissive` accepts bundles without checking any
signature and records them `SignedBy "<unverified>"`. It exists for a laptop
that has never run `scripts/pki-init.sh`. It must never be set on hardware —
and on a box that has a `root-ca.pem` it changes nothing, because the root is
loaded and enforced either way. See [`../docs/pki.md`](../docs/pki.md).
