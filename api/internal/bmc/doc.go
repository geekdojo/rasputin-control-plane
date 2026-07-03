// Package bmc bridges to the onboard BMC. Provides power on/off/cycle,
// reset, and serial-over-LAN tunneled to the UI.
//
// Routing: BMC commands target a specific node, but they're delivered to
// the **BMC host** node's agent (in MVS, the controlplane node). The host
// owns the I²C/serial bus to every node's BMC chip. Routing through the
// target node directly is wrong — if the target is powered off, its agent
// isn't running, which is exactly when you need the BMC.
//
// Components:
//   - Store: SQLite ledger of per-target power state + last command audit.
//   - Service: holds the configured BMC-host node id, dispatches commands.
//   - jobs: the bmc.power workflow (validate, dispatch, record).
//   - sol: long-lived SOL session manager — owns the NATS subscriptions
//     for each open session, wires bytes between the api's WebSocket and
//     the agent's serial port.
//
// See projects/rasputin/design/control-plane/bmc.md in the geekdojo-brain.
package bmc
