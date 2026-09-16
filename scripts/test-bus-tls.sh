#!/usr/bin/env bash
# test-bus-tls.sh — the bus TLS functional test (geekdojo/geekdojo-brain#448),
# run alone and verbosely. CI runs the same tests with the rest of ./api/...
#
# What runs (api/internal/bustls/functional_test.go): the real embedded bus
# with auth callout enforced, the real inventory and bustls services, and the
# REAL rasputin-agent binary (built from this workspace) as subprocesses:
#
#   * offer mode — the right pin connects over TLS and registers busTls=true;
#     a wrong pin is refused by the agent and never registers; no pin still
#     connects in plaintext and is listed as what holds require back;
#   * migrate → require — the controlplane's loopback agent and a compute node,
#     both enrolled without a pin, get it delivered, save it, re-dial over TLS
#     and register busTls=true; require is refused before that and accepted
#     after; the controlplane restarts TLS-required, both agents restart with
#     no pin in their environment and come back over TLS from the saved pin;
#     an unpinned node is refused;
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
