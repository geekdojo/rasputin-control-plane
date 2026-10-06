package apps

import (
	"context"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// SecretSource resolves the `${secret:<name>}` tokens in an app's compose.
// The push step is its only caller (ARCH-ISP: the consumer declares it), and
// it is called there and nowhere else, on the way out to the target agent.
//
// The contract every implementation keeps:
//
//   - ResolveCompose returns the compose with every `${secret:}` token
//     resolved, or it refuses. It never returns a compose with a token left in.
//   - On any error it returns the zero secret.Value.
//   - An error never carries a resolved value, or any part of one.
//
// The context lets a source that reads a store, or that is not ready yet,
// honour the step's deadline.
type SecretSource interface {
	ResolveCompose(ctx context.Context, appID, compose string) (secret.Value, error)
}

// requireSecretSource refuses a nil source for the named workflow kind. Every
// deploy-family constructor calls it: without a source the push step could
// not resolve a token, and finding that out at push would strand the job
// halfway, so the wiring is refused instead.
func requireSecretSource(kind string, s SecretSource) error {
	if s == nil {
		return fmt.Errorf("apps: %s workflow: a secret source is required; without one the push step cannot resolve ${secret:} tokens", kind)
	}
	return nil
}
