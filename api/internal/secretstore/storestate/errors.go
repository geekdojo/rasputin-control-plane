package storestate

import "errors"

// Code is the stable code every not-ready refusal carries, whatever the state.
const Code = "secret_store_not_ready"

// ErrNotReady matches every *NotReadyError through errors.Is.
var ErrNotReady = errors.New("storestate: the secret store is not ready")

// NotReadyError is the Gate's refusal of a secret-bearing deploy while the
// store is not ready. Its Error() is the sentence the failed job records, so
// it names no store, path or vendor, and carries the code.
type NotReadyError struct {
	State State
}

// Error is one fixed sentence per state. It is true for every workflow that
// reaches the push step: none has touched a container by then, and for an
// edit, upgrade or revert whose new compose is already saved, deploying the
// app again is what applies it (geekdojo/geekdojo-brain#760, F-760-04).
func (e *NotReadyError) Error() string {
	return "The secret store " + Clause(e.State) +
		", so this app's secrets could not be resolved and the app was not deployed. " +
		"Its running containers are unchanged; deploy the app again once the store is ready. " +
		"Error code: " + Code + "."
}

// Code is the stable refusal code.
func (e *NotReadyError) Code() string { return Code }

// Is matches ErrNotReady.
func (e *NotReadyError) Is(target error) bool { return target == ErrNotReady }

// Clause is how a refusal sentence says what the store is doing, after "The
// secret store": the deploy gate's and the backup's (#765).
func Clause(s State) string {
	switch s {
	case Sealed:
		return "is sealed"
	case Uninitialised:
		return "has not been set up"
	case Unreachable:
		return "cannot be reached"
	case AuditBlocked:
		return "is not accepting audit records"
	case Quiesced:
		return "is paused for a backup, a seal-key rotation or an OS update"
	case Blank:
		return "is empty although this cluster was set up"
	}
	return "is not ready"
}
