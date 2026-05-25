# rasputin-agent

The Go agent binary that runs on every Rasputin node — including the control plane node itself. Outbound-only NATS connection; never listens.

## Build targets

- `linux/arm64` — Pi CM5 (Node A)
- `linux/amd64` — N100 nodes (Node X, Node N)
- `linux/arm64-musl` — OpenWrt static build for the firewall node

## Subsystems

| Package | Purpose |
|---|---|
| `internal/bus` | NATS client, subject dispatch, ack/dedup |
| `internal/host` | Host facts, RAUC slot control, reboot |
| `internal/docker` | Compose ops (compute nodes only) |
| `internal/openwrt` | ubus / UCI client (firewall node only) |
| `internal/ipmi` | BMC client for adjacent slots (control plane node only) |

## Run

```sh
go run ./cmd/rasputin-agent
```
