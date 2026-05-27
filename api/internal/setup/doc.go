// Package setup hosts the first-run wizard's backend. The wizard is the
// operator's "first hour" experience — passkey registration, naming the
// installation, opt-in remote access, PKI trust verification.
//
// Design choice: **the wizard's step state is derived, not stored.** Each
// step's "done" status is computed by looking at the relevant subsystem
// (auth has users? mesh has enrolled this node? PKI has a trust root?).
// This makes the wizard idempotent and re-runnable. The operator can
// revisit /setup any time and see the current state.
//
// The only stored state is:
//   - `install_name` (operator-chosen label for this Rasputin instance)
//   - `wizard_completed_at` (set when the operator clicks Finish; gates
//     the "Finish setup" banner on other pages)
//
// Both live in a small key/value `settings` table; this package owns it.
package setup
