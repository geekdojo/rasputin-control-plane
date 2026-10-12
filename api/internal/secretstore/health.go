package secretstore

import "errors"

// InactiveReason names why the store is not active, from a Health call's
// answer, or returns "" when it is initialised and unsealed. The reasons are
// sealed, uninitialised, unreachable, disabled and error (any other failure).
//
// It is the one reading of a Health answer: the audit rotator (storeaudit)
// and the readiness monitor (storestate) both classify through it
// (geekdojo/geekdojo-brain#760, F-760-05).
func InactiveReason(h Health, err error) string {
	switch {
	case errors.Is(err, ErrSealed):
		return "sealed"
	case errors.Is(err, ErrUninitialised):
		return "uninitialised"
	case errors.Is(err, ErrUnreachable):
		return "unreachable"
	case errors.Is(err, ErrDisabled):
		return "disabled"
	case err != nil:
		return "error"
	case !h.Initialized:
		return "uninitialised"
	case h.Sealed:
		return "sealed"
	}
	return ""
}
