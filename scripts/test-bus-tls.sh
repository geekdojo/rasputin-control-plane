#!/usr/bin/env bash
# test-bus-tls.sh — the bus TLS functional test (geekdojo/geekdojo-brain#448),
# run alone and verbosely. CI runs the same tests with the rest of ./api/...
#
# What runs (api/internal/bustls/functional_test.go and functional_api_test.go):
# the real embedded bus with auth callout enforced, the real inventory, job
# store/runner and bustls service with its real commit check, and the REAL
# rasputin-agent binary (built from this workspace) as subprocesses:
#
#   * the automatic ladder, no operator action — offer while the controlplane's
#     build is an uncommitted trial and a self-update is in flight (each half
#     proven on its own); commit → migrate → pins delivered → both agents
#     (the controlplane's own and a compute node) re-dial over TLS and report
#     busTls=true; a job in flight holds require back; the job ends → require
#     recorded, job intake closed, and the bus server replaced IN-PROCESS (same
#     bus.Server, same api connection) — a job submitted before and after the
#     server swap is refused with jobs.ErrQuiesced, then accepted and run over
#     the new bus to both agents, which rejoined over TLS by themselves;
#     plaintext refused on the wire; an unpinned node refused; the agents
#     rejoin again from their saved pin; a later restart comes up in require;
#   * the REAL rasputin-api binary (built with -race under -race) on a fresh
#     controlplane: it reaches require by itself with the SAME process — one
#     PID, never exits, GET /healthz answered on every back-to-back poll across
#     the switch — pin delivered to its loopback agent, both agents back over
#     TLS, a job submitted at the decision answered 503+Retry-After (or 201 if
#     the switch had already finished) and jobs running afterwards, plaintext
#     refused, an unpinned node refused;
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
