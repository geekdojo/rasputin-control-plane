package move

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
)

// pending is the move's pending fact (*State).
type pending interface {
	Pending(ctx context.Context) (bool, error)
}

// converged is the realm's desired and stored state (*converge.Converger),
// so the user profile that holds rasputin_app_role is in place before the
// import.
type converged interface {
	Pending(ctx context.Context) (desired, stored string, err error)
}

// Cond is the move's trigger condition, read only while the service is
// ready: a move is pending and the realm has converged. Every read error
// is not due, returned for the trigger's once-per-outage record.
func Cond(state pending, conv converged) converge.Cond {
	return func(ctx context.Context) (bool, string, string, error) {
		p, err := state.Pending(ctx)
		if err != nil || !p {
			return false, "", "", err
		}
		desired, stored, err := conv.Pending(ctx)
		if err != nil || desired != stored {
			return false, "", "", err
		}
		return true, "the accounts from before the update are not yet moved", "", nil
	}
}
