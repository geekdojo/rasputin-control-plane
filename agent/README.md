# rasputin-agent

The Go agent binary that runs on every Rasputin node — including the control plane node itself. Outbound-only NATS connection; never listens.

## Build targets

- `linux/arm64` — Pi CM5 (Node A)
- `linux/amd64` — N100 nodes (Node X, Node N)
- `linux/arm64-musl` — OpenWrt static build for the firewall node

## Subsystems

| Package | Purpose |
|---|---|
| `internal/bus` | NATS connection (outbound-only, join-token creds) + shared reply helper. No dispatch, no ack/dedup — each subsystem subscribes its own subjects |
| `internal/host` | Host facts, RAUC slot control, reboot |
| `internal/docker` | Compose ops (compute nodes only) |
| `internal/openwrt` | ubus / UCI client (firewall node only) |
| `internal/ipmi` | BMC client for adjacent slots (control plane node only) |

## Run

```sh
go run ./cmd/rasputin-agent
```

On a machine with none of the real tooling (a laptop), that comes up with the
hardware-backed subsystems **disabled** — each logs what it is missing and
reports it to the control plane. That is deliberate: `mock` is a development
fixture and is never autodetected, because a mock that is inferred on real
hardware answers with fixture disks, fixture slots and a fixture tailnet, and
nothing in the reply says the answer is fiction. See
`internal/configfault` for the incident that settled this.

Ask for the mocks explicitly — one variable per subsystem, so a stray setting
can only ever fake the one thing it names:

```sh
RASPUTIN_DOCKER_BACKEND=mock \
RASPUTIN_UPDATE_BACKEND=mock \
RASPUTIN_STORAGE_BACKEND=mock \
RASPUTIN_TAILSCALE_BACKEND=mock \
RASPUTIN_UCI_BACKEND=mock \
go run ./cmd/rasputin-agent
```

There is deliberately **no single "mock everything" switch**: one variable that
turns on five mocks is one variable away from an OS image that fakes the whole
node, which is the failure this design exists to prevent. Set only the
subsystems you are actually working on and leave the rest honestly disabled.

`RASPUTIN_UCI_BACKEND` carries one extra meaning on a firewall-role agent: it is
also the opt-in for the post-update health gate (`diag.health`). A firewall-role
node with no `/etc/config/firewall` is **unhealthy** — that is a firewall with no
firewall configuration, and the `node.update` saga commits or rolls back on this
verdict — unless `RASPUTIN_UCI_BACKEND=mock` says a human knows this box is not a
real OpenWrt firewall, in which case the gate degrades to the baseline liveness
check and says so in the check detail. Absence of the file is never taken as
evidence of a dev box on its own.
