// Package bmc lives on the BMC-host agent (the controlplane node, in MVS).
// It receives power and serial-over-LAN commands from the api and
// translates them into hardware operations against each target node's BMC
// chip.
//
// Backends are pluggable through the registry in registry.go, selected
// by RASPUTIN_BMC_BACKEND (see design/control-plane/bmc-bitscope.md §2a):
//   - MockBackend ("mock", the default) — file-backed per-target power
//     state; SOL emits a canned banner + a periodic uptime line. Lets the
//     api saga + UI be exercised end-to-end without a real BMC.
//   - BitScopeBackend ("bitscope") — the CB04B blade BMC over the rack's
//     RS-485 bus via the manager Pi's /dev/serial0 (power verbs + status;
//     SoL pending). Framing is bench-validation pending — see bitscope.go.
//   - "turingpi" (contemplated) — the Turing Pi BMC over its REST API.
//   - the Phase 3 chassis driver — I²C / IPMI / Redfish against the
//     Rasputin backplane.
//
// Only registered on agents whose role is controlplane (or when the env
// override RASPUTIN_BMC_HOST=1 forces it on any agent — the BitScope
// bench rack's manager node is a compute agent).
package bmc
