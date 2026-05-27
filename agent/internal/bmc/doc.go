// Package bmc lives on the BMC-host agent (the controlplane node, in MVS).
// It receives power and serial-over-LAN commands from the api and
// translates them into hardware operations against each target node's BMC
// chip.
//
// Two backends:
//   - RealBackend (TODO v1) — talks to the I²C / Redfish / IPMI surface
//     exposed by the chassis backplane. Deferred until hardware lands.
//   - MockBackend — file-backed per-target power state; SOL emits a
//     canned banner + a periodic uptime line. Lets the api saga + UI be
//     exercised end-to-end on dev machines without a real BMC.
//
// Only registered on agents whose role is controlplane (or when the env
// override RASPUTIN_BMC_HOST=1 forces it on any agent for testing).
package bmc
