package apps

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// SecretSource resolves the `${secret:<name>}` tokens in an app's compose.
// The push step is its only caller (ARCH-ISP: the consumer declares it), and
// it is called there and nowhere else, on the way out to the target agent.
//
// The contract every implementation keeps:
//
//   - ResolveCompose returns the compose with every `${secret:}` token
//     replaced by its Compose interpolation reference
//     `${RASPUTIN_SECRET_<NAME>}` (proto.SecretEnvName), and the map from each
//     reference's variable to its value, or it refuses. It never returns a
//     compose with a token left in, and never one holding a value
//     (geekdojo/geekdojo-brain#776).
//   - A compose with no token comes back as the same bytes with an empty map.
//   - The caller owns the map's values and destroys them.
//   - On any error it returns the zero secret.Value and a nil map.
//   - An error never carries a resolved value, or any part of one.
//
// The context lets a source that reads a store, or that is not ready yet,
// honour the step's deadline.
type SecretSource interface {
	ResolveCompose(ctx context.Context, appID, compose string) (secret.Value, map[string]secret.Value, error)
}

// refuseAgentWithoutSecrets refuses a secret-bearing deploy of app to a node
// whose agent cannot take one: below proto.AppDeploySecretsVerb's floor, or
// with a version that is unreported or does not parse
// (geekdojo/geekdojo-brain#776). It returns nil when the agent is at or above
// the floor. The refusal is the sentence a person reads: the node, its agent
// version, the floor, and what to do.
//
// It fails closed (ERR-CLOSED). There is no downgrade path: a compose holding
// references and no values would deploy blank credentials, and the inline
// shape is the plaintext copy on the node this channel exists to close.
//
// The pull step calls it before a compose change marks the app DEPLOYING and
// before the change is persisted; the push step calls it again as the only
// check on a plain deploy, which has no pull step.
func refuseAgentWithoutSecrets(ctx context.Context, inv *inventory.Store, app *App) error {
	floor, _ := proto.VerbMinAgentVersion(proto.AppDeploySecretsVerb)
	r := &secretsAgentRefusal{node: app.TargetNode, app: app.Name, floor: floor}
	node, err := inv.Get(ctx, app.TargetNode)
	if err != nil {
		r.lookup = err
		return r
	}
	if node != nil {
		r.version = strings.TrimSpace(node.AgentVersion)
	}
	if inventory.AgentAtLeast(r.version, floor) {
		return nil
	}
	return r
}

// secretsAgentRefusal is refuseAgentWithoutSecrets' refusal. A type rather
// than a format string so the one sentence is built in one place.
type secretsAgentRefusal struct {
	node, app, version, floor string
	// lookup is why the node's agent version could not be read, if it could
	// not.
	lookup error
}

func (r *secretsAgentRefusal) Error() string {
	reported := "has not reported its agent version"
	switch {
	case r.lookup != nil:
		reported = fmt.Sprintf("has an agent version that could not be read (%v)", r.lookup)
	case r.version != "":
		reported = "runs agent v" + strings.TrimPrefix(r.version, "v")
	}
	return fmt.Sprintf("node %s %s, and an app with ${secret:} values needs agent v%s or later, so %q was not sent to it. Update the node.",
		r.node, reported, r.floor, r.app)
}

// codedRefusal is a source's refusal that is already the sentence a person
// reads, carrying a stable code (the secret store's not-ready refusal,
// geekdojo/geekdojo-brain#760). The push step returns it as it is, so the
// job's recorded error is that sentence and nothing is prefixed to it.
type codedRefusal interface {
	error
	Code() string
}

// resolveError is the push step's error for a source that refused appID's
// compose: a coded refusal unchanged, and any other error wrapped with the
// app it was for.
func resolveError(appID string, err error) error {
	var coded codedRefusal
	if errors.As(err, &coded) {
		return coded
	}
	return fmt.Errorf("apps: resolve compose for %s: %w", appID, err)
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
