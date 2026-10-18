package secrets

import "errors"

// The service's own refusals. Every store failure is returned as the store's
// own secretstore.Err* kind, wrapped, so a caller matches either with
// errors.Is.
var (
	// ErrInvalidRef: the reference did not parse, or is the zero Ref.
	ErrInvalidRef = errors.New("secrets: invalid reference")
	// ErrForbidden: the actor may not perform the operation on the reference.
	// The store was not called.
	ErrForbidden = errors.New("secrets: forbidden")
	// ErrNoSuchApp: an operator write names an app that does not exist.
	ErrNoSuchApp = errors.New("secrets: no such app")
	// ErrExists: Create found the secret already set.
	ErrExists = errors.New("secrets: already exists")
	// ErrConflict: Replace lost a race with another write. It is not retried,
	// since a retry would silently overwrite the other writer's value.
	ErrConflict = errors.New("secrets: concurrent change")
)
