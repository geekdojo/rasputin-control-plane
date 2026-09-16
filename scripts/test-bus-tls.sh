#!/usr/bin/env bash
# test-bus-tls.sh — the bus TLS functional test (geekdojo/geekdojo-brain#448),
# run alone and verbosely. CI runs the same tests with the rest of ./api/...
#
# What runs (api/internal/bustls/functional_test.go): the real embedded bus
# with auth callout enforced, the real inventory, job store/runner and bustls
# service with its real commit check, and the REAL rasputin-agent binary
# (built from this workspace) as subprocesses:
#
#   * the automatic ladder, no operator action — offer while the controlplane's
#     build is an uncommitted trial and a self-update is in flight (each half
#     proven on its own); commit → migrate → pins delivered → both agents
#     (the controlplane's own and a compute node) re-dial over TLS and report
#     busTls=true; a job in flight holds require back; the job ends → require
#     recorded, job intake closed, one restart request; the controlplane
#     restarts TLS-required, the agents rejoin over TLS (and again from their
#     saved pin with none in their env); an unpinned node is refused;
#   * a pinned offer (RASPUTIN_BUS_TLS) — right pin TLS, wrong pin refused, no
#     pin plaintext, and the pinned mode does not move;
#   * clock independence — a bus certificate not valid until decades from now,
#     and one expired in 1991, both accepted by a pinned agent.
#
# No bench, no hardware, no root. What it does NOT cover: the OS firstboot and
# firewall apply-seed consumers, mDNS, real hardware clocks — see the PR's
# bench plan.
#
# Usage: scripts/test-bus-tls.sh [extra go test flags]

set -euo pipefail
cd "$(dirname "$0")/.."

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.4}"
exec go test -count=1 -race -v -run 'TestFunctional' ./api/internal/bustls/ "$@"
