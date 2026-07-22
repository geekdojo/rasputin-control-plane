// Package bmc lives on the BMC-host agent. It receives power and
// serial-over-LAN commands from the api and translates them into
// hardware operations against each target node's BMC chip.
//
// BMC is HARD on/off (decided 2026-07-21): by default no backend exists,
// no handlers register, nothing is advertised, and the api refuses every
// BMC verb. It turns on only when RASPUTIN_BMC_BACKEND explicitly
// selects a backend from the registry in registry.go (see
// design/control-plane/bmc.md §2a):
//   - MockBackend ("mock") — an explicit dev selection, never a
//     fallback; plays by the same strict rules as real drivers
//     (advertises only its configured RASPUTIN_BMC_MOCK_TARGETS list).
//     File-backed power state; SOL emits a canned banner + uptime line.
//   - BitScopeBackend ("bitscope") — the CB04B blade BMC over the rack's
//     RS-485 bus via the manager Pi's /dev/serial0. Power verbs + status
//   - SoL (bus-wide single session with cross-target take-over; verbs
//     interrupt an open console — see bitscope_sol.go). Framing and the
//     console-exit escape are bench-validation pending — see bitscope.go.
//   - "turingpi" (contemplated) — the Turing Pi BMC over its REST API.
//   - the Phase 3 chassis driver — I²C / IPMI / Redfish against the
//     Rasputin backplane.
//
// Selecting a backend is also the host opt-in: whichever agent has it
// set hosts the bus (the BitScope bench manager is a compute node).
// Operator-facing selection from the control plane's Settings is the
// planned product surface; the env var is the dev/bench bootstrap.
package bmc
