package identitystate

import "errors"

// Code is the stable code every not-ready refusal carries, whatever the
// state. The first identity route maps it with writeCodedError.
const Code = "identity_not_ready"

// ErrNotReady matches every *NotReadyError through errors.Is.
var ErrNotReady = errors.New("identitystate: the identity service is not ready")

// NotReadyError is the refusal of identity work while the service is not
// ready. Its Error() is the state's sentence and the code: it names no unit,
// path or vendor.
type NotReadyError struct {
	State State
}

// Error is the state's §5.1 sentence followed by the code.
func (e *NotReadyError) Error() string {
	return e.State.sentence() + " Error code: " + Code + "."
}

// Code is the stable refusal code.
func (e *NotReadyError) Code() string { return Code }

// Is matches ErrNotReady.
func (e *NotReadyError) Is(target error) bool { return target == ErrNotReady }
