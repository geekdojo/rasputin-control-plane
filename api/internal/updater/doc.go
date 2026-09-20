// Package updater orchestrates atomic A/B OS updates for every Rasputin
// node. Bundles are produced offline (build pipeline), signed by a leaf
// cert under the Rasputin Root CA, uploaded to the api, and dispatched to
// agents via the node.update saga.
//
// Components:
//   - Store: SQLite ledger of bundles + per-node update history.
//   - Verifier: the shared artifactsig detached-CMS check against the trusted
//     root cert, bound to the release signing purpose; rejects an artifact
//     whose `.sig` doesn't validate or whose leaf was not issued to sign
//     releases. A MISSING trust root is a refusal, not a downgrade — see the
//     fail-closed note on Verifier. There is no unverified mode.
//   - UpdateWorkflow: the 7-step saga (validate, precheck, download,
//     install, reboot, wait-online-and-verify-slot, health-check-and-commit).
//
// Bundle delivery is HTTPS over the tailnet; the agent fetches by hash
// from /api/bundles/{sha256}. The api never streams the bundle bytes
// through NATS — bundles are large.
//
// See projects/rasputin/design/control-plane/updates.md
//
//	in the geekdojo-brain.
package updater
