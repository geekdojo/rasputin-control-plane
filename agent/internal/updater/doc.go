// Package updater implements the agent side of OS updates.
//
// Two backends:
//
//   - RAUCBackend shells out to the `rauc` CLI for real bundle install,
//     slot inspection, and mark-good/bad. Only available on hardware
//     where rauc is on PATH.
//
//   - MockBackend simulates the lifecycle with file-backed state under
//     <stateDir>/updater/. Used in dev and CI where there's no rauc.
//
// Backend is selected at startup via RASPUTIN_UPDATE_BACKEND
// (rauc|mock), with mock as the default when the rauc binary is absent.
//
// See projects/rasputin/design/control-plane/updates.md
//
//	in the geekdojo-wiki.
package updater
