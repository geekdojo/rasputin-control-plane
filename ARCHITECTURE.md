# Rasputin — System Architecture

> **Status: pre-alpha.** Rasputin is in its commodity-hardware proof phase.
> Everything described here is under active development; APIs, wire formats,
> and image layouts change without notice.

This document is the system-level overview for the Rasputin open-source repos.
It describes how the pieces fit together; each repo's README covers its own
build and layout.

## What Rasputin is

Rasputin is a modular, node-based homelab system: a small cluster of compute
nodes plus a dedicated firewall node, managed from one web UI. It targets
intermediate homelab enthusiasts — people who live in Docker Compose, are
comfortable with SSH but would rather not need it, and know what a VLAN is.

The design principle throughout is **opinionated-but-open**: strong defaults
that work in the first hour (firewall, updates, observability, app catalog),
with documented escape hatches everywhere (root shell, LuCI, the whole OS
image build is reproducible from these repos).

The name is a nod to Grigori Rasputin — the machine that wouldn't die.
Atomic A/B updates with automatic rollback are the load-bearing feature, not
an afterthought.

## Node roles

Role is **runtime configuration, not a separate image**. A freshly flashed
node reads a small seed file on first boot and becomes whatever the seed says.

| Role | Architectures | What it runs |
|---|---|---|
| `controlplane` | amd64 (Intel N100 class) or arm64 (Raspberry Pi 4 / 5 / CM5) | `rasputin-api` (web UI, job engine, embedded NATS) + `rasputin-agent` + mesh coordinator |
| `compute` | amd64 or arm64 | `rasputin-agent` + Docker (the app substrate) |
| `firewall` | **amd64 only** (N100 + dual Intel i226-V) | OpenWrt + `rasputin-agent` |

The firewall is deliberately x86-only: a Raspberry Pi can't be the firewall
node (one PCIe lane, a 5 W PCIe budget, single 1GbE PHY). The compute and
controlplane roles run on either architecture.

## The repos

| Repo | Produces |
|---|---|
| [`rasputin-control-plane`](https://github.com/geekdojo/rasputin-control-plane) | `rasputin-api` (Go), `rasputin-agent` (Go), `rasputin-ui` (Next.js static export) |
| [`rasputin-os`](https://github.com/geekdojo/rasputin-os) | Buildroot-based OS images for compute/controlplane nodes (one per arch) |
| [`rasputin-openwrt-firewall`](https://github.com/geekdojo/rasputin-openwrt-firewall) | OpenWrt-based firewall image (A/B disk + OTA rootfs artifact) |

The image repos don't build the Go code — they vendor the statically-linked
release binaries published by this repo's CI. Pure Go (`modernc.org/sqlite`,
embedded NATS, no cgo) means one `CGO_ENABLED=0` binary per arch runs on both
the glibc-based Buildroot OS and the musl-based OpenWrt firewall.

## api + agent split

- **`rasputin-api`** runs only on the controlplane node. Single Go binary: it
  embeds the NATS server, the SQLite job ledger, the workflow engine, and
  serves the web UI (a baked Next.js static export) on one origin. No
  external broker, no Postgres, no Redis, no reverse proxy.
- **`rasputin-agent`** runs on every node, including the controlplane itself.
  It dials the bus **outbound-only** — agents never listen on a port — and
  executes commands: Docker Compose operations, OS update installs, firewall
  config application (on OpenWrt, via ubus/UCI), health probes, heartbeats.

Auth to the UI is **WebAuthn/passkey only** — there is no password login.

## The bus: NATS + JetStream, node-bound join tokens

All control traffic is NATS with JetStream persistence, embedded in the api
process. Subjects are human-readable (`rasputin.node.<id>.cmd.…`,
`rasputin.node.<id>.evt.…`, `rasputin.job.<id>.…`), so `nats sub '>'` gives a
live view of everything the system is doing.

Agents authenticate with a **join token bound to their node id**. The api
validates the token against a hashed store and mints a short-lived user JWT
scoped to that node's own subject subtree — a compromised compute node cannot
impersonate the firewall or read another node's command stream. Revocation is
a store delete; the next reconnect fails. The controlplane's own co-located
agent connects over loopback and needs no token (it's already on the box that
is the authority).

JetStream work-queue semantics mean an agent that goes offline drains its
queued commands when it reconnects, with dedup keys making redelivery safe.

## The Job model

**Every state-changing operation is a Job.** UI buttons, scheduled
reconciles, event handlers — all of them create a Job row in SQLite and drive
a linear saga (steps with retries and compensation) whose progress streams to
the UI's Tasks panel over NATS. There is no hidden background magic: if the
system is doing something, it's visible as a job. Read-only operations are
plain HTTP.

Periodic reconcile jobs (firewall, apps, mesh) compare declared intent
against observed reality and surface drift instead of silently clobbering it.

## OS and updates: Buildroot + RAUC A/B

Compute and controlplane nodes boot **Rasputin OS**: a Buildroot-built,
read-only squashfs image with two rootfs slots (A/B) and a persistent data
partition. Updates are **RAUC signed bundles**: the update saga stages the
bundle to the inactive slot, reboots into it, runs a role-aware health check,
and **commits on success or rolls back to the previous slot on failure**.
Bundles are verified against a CA baked into every image; fleet updates roll
node-by-node, never in parallel, with the firewall last.

Bootloader integration differs per arch, honestly:

- **amd64:** GRUB with a real boot counter — bootloader-level rollback even
  for a slot that was already committed.
- **arm64 (Raspberry Pi):** the Pi firmware's one-shot `tryboot` flag via a
  custom RAUC backend. The firmware cannot count boot attempts and will not
  auto-fall-back from a *committed* slot, so the Pi relies on
  defense-in-depth: the one-shot bootloader trial, a systemd watchdog on the
  agent, and the saga's post-reboot health check.

Provisioning is a laptop-editable seed file on a FAT partition (role, bus
URL, join token). The first controlplane self-initializes with no token.

## Firewall: OpenWrt with a declarative intent API

The firewall node runs an OpenWrt-based image. The control plane owns
**intent** (port forwards, firewall rules, VPN peers), compiles it to UCI
deltas, and ships them to the firewall agent as jobs. The agent applies them
and reports a hash of resulting state; periodic reconciliation detects
out-of-band edits and asks the operator to adopt or revert — SSH and LuCI
remain first-class escape hatches, not violations.

Firewall updates don't use RAUC (it isn't in the OpenWrt package feeds).
Instead the image reproduces the same contract with OpenWrt parts: an A/B
GPT disk with the identical GRUB boot-counter config as the amd64 OS image, a
rootfs-only OTA artifact, and an agent backend that flips GRUB environment
variables the way RAUC would. The same update saga drives both node types;
only the agent-side backend differs.

**IDS is honest about hardware limits:** snort3 runs in **tap mode,
detection-only** (alerts, never inline blocking), because an N100 cannot do
inline IPS at 1 Gbps line rate. Claiming otherwise would be marketing;
alerts flow into the observability stack and the UI instead.

## Mesh: Headscale

Every node joins a self-hosted WireGuard mesh (Headscale) at bootstrap;
inter-node traffic and remote UI access ride the tailnet. The coordinator
runs as a container on the controlplane, with its image baked into the OS so
the mesh forms with zero internet — important because the controlplane
usually gets its internet *through* the firewall it's bootstrapping.

The stack is deliberately **IPv4-only** for now; IPv6 is disabled across the
OS, firewall, and APIs. (One inert exception: Headscale currently requires a
v6 prefix in its config; the addresses it records are unreachable by design.)

## Observability

Grafana + **VictoriaMetrics** + Loki, with Grafana Alloy as the per-node
collector. VictoriaMetrics over Prometheus is a deliberate default — 5–10×
lower RAM at homelab scale, PromQL-compatible. Tier 1 (agent-native metrics,
ring buffer, UI sparklines) is implemented; the full sidecar stack runs as
containers on the controlplane, managed like any other app. The firewall is
the one node without a local collector (OpenWrt, no Docker); its logs and
IDS alerts ship over the bus.

## Apps

The user-facing primitive is **Docker Compose behind a catalog UI** — not
Kubernetes. A curated first-party catalog plus user-defined Compose stacks,
deployed through the agent. k3s as an opt-in advanced mode and Incus for VMs
are on the roadmap, not shipped.

## What works today, what doesn't

Working end-to-end on bench hardware: two-arch signed image pipeline, seed
provisioning, bus auth with node-bound tokens, the job/saga engine, A/B OS
updates with health-check rollback (both bootloader backends,
hardware-validated), firewall intent apply + drift detection, IDS alert
pipeline, mesh bootstrap, Tier 1 observability, app deploys, and the web UI.

Not there yet (non-exhaustive): dm-verity rootfs integrity, signature
verification of the firewall OTA artifact (SHA-over-mesh-TLS is the current
integrity gate), a general resumable-saga engine, k3s/Incus advanced modes,
HA control plane. Expect sharp edges everywhere.
