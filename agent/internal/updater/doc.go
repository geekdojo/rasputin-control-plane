// Package updater implements the agent side of OS updates.
//
// Two backends:
//
//   - RAUCBackend shells out to the `rauc` CLI for real bundle install,
//     slot inspection, and mark-good/bad. Only available on hardware
//     where rauc is on PATH.
//
//   - MockBackend simulates the lifecycle with file-backed state under
//     <stateDir>/updater/. A dev/CI fixture, and EXPLICIT-ONLY.
//
// Backend is selected at startup via RASPUTIN_UPDATE_BACKEND
// (rauc|openwrt-ab|mock). The real backends are autodetected from what the node
// has; mock never is. A node with no usable updater has OS updates disabled and
// says so, because MockBackend.Install reports success for an image it never
// wrote — which would carry a node.update saga to COMMIT and let a fleet run go
// green having installed nothing. See agent/internal/configfault.
//
// See projects/rasputin/design/control-plane/updates.md
//
//	in the geekdojo-brain.
package updater
