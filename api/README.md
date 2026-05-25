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
