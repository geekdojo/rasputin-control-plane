package apps

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// CodeOperatorSecretUnset is the stable code of the refusal a deploy gets
// while a secret its owner must supply is not set
// (geekdojo/geekdojo-brain#780).
const CodeOperatorSecretUnset = "operator_secret_unset"

// appReader is the apps row as OperatorSecretGate reads it (*Store).
type appReader interface {
	Get(ctx context.Context, id string) (*App, error)
}

// operatorSecretReader is the secrets service as OperatorSecretGate calls it
// (*secrets.Service): a deploy job's read, used only to learn whether a value
// is set.
type operatorSecretReader interface {
	Read(ctx context.Context, a secrets.Actor, r secrets.Ref) (secrets.Secret, error)
}

// OperatorSecretGateDeps is everything an OperatorSecretGate needs.
// NewOperatorSecretGate refuses a nil one.
type OperatorSecretGateDeps struct {
	// Next is the source that resolves the compose once every declared value
	// is known to be set.
	Next SecretSource
	// Apps reads the app's row, which carries its declarations.
	Apps appReader
	// Secrets answers whether each declared value is set.
	Secrets operatorSecretReader
	Log     *slog.Logger
}

// OperatorSecretGate is the secret source placed in front of the deploy
// family's resolver (geekdojo/geekdojo-brain#780). It refuses a compose that
// uses a secret the app's tile declares its OWNER supplies while that value
// is not set, and otherwise delegates to Next unchanged.
//
// Without it, the resolver behind it would treat the name like any other
// ${secret:} token: derive a random value, store it, and hand it to the app
// as the owner's API key. Every deploy-family job (deploy, edit, revert and
// upgrade) resolves through the push step's one call to its source, so
// wrapping that source gates all four.
//
// It reads only the declared names the compose actually uses. A value read
// to learn that it is set is destroyed at once; Next reads it again to
// deliver it.
type OperatorSecretGate struct {
	next    SecretSource
	apps    appReader
	secrets operatorSecretReader
	log     *slog.Logger
}

// NewOperatorSecretGate checks d and returns a gate. It does no I/O.
func NewOperatorSecretGate(d OperatorSecretGateDeps) (*OperatorSecretGate, error) {
	switch {
	case d.Next == nil:
		return nil, errors.New("apps: NewOperatorSecretGate: Deps.Next is nil")
	case d.Apps == nil:
		return nil, errors.New("apps: NewOperatorSecretGate: Deps.Apps is nil")
	case d.Secrets == nil:
		return nil, errors.New("apps: NewOperatorSecretGate: Deps.Secrets is nil")
	case d.Log == nil:
		return nil, errors.New("apps: NewOperatorSecretGate: Deps.Log is nil")
	}
	return &OperatorSecretGate{next: d.Next, apps: d.Apps, secrets: d.Secrets, log: d.Log}, nil
}

// ResolveCompose refuses compose while a declared operator secret it uses is
// unset or cannot be checked, and otherwise returns Next's answer unchanged.
// A compose with no token, or with a malformed one, goes straight to Next,
// which resolves the first and refuses the second.
func (g *OperatorSecretGate) ResolveCompose(ctx context.Context, appID, compose string) (secret.Value, map[string]secret.Value, error) {
	tokens, err := tileschema.ScanSecretTokens(compose)
	if err != nil || len(tokens) == 0 {
		return g.next.ResolveCompose(ctx, appID, compose)
	}
	app, err := g.apps.Get(ctx, appID)
	if err != nil {
		return secret.Value{}, nil, fmt.Errorf("apps: checking the operator secrets of %s: %w", appID, err)
	}
	if app == nil {
		return secret.Value{}, nil, fmt.Errorf("apps: checking the operator secrets of %s: the app does not exist", appID)
	}

	used := make(map[string]bool, len(tokens))
	for _, tok := range tokens {
		used[tok.Name] = true
	}
	actor := secrets.DeployActor(appID, app.TargetNode)
	var unset []tileschema.OperatorSecret
	for _, decl := range app.OperatorSecrets {
		if !used[decl.Name] {
			continue
		}
		set, err := g.isSet(ctx, actor, appID, decl.Name)
		if err != nil {
			return secret.Value{}, nil, err
		}
		if !set {
			unset = append(unset, decl)
		}
	}
	if len(unset) > 0 {
		names := make([]string, len(unset))
		for i, u := range unset {
			names[i] = u.Name
		}
		g.log.LogAttrs(ctx, slog.LevelWarn, "deploy refused: an operator secret is not set",
			slog.String("component", "apps"),
			slog.String("event", "apps.operator_secret_unset"),
			slog.String("app_id", appID),
			slog.Any("names", names),
			slog.String("job_id", jobs.JobIDFromContext(ctx)))
		return secret.Value{}, nil, operatorSecretsUnset(unset)
	}
	return g.next.ResolveCompose(ctx, appID, compose)
}

// isSet reports whether appID's secret name holds a value. Not found is
// (false, nil); any other failure is the store-unavailable refusal, logged
// here, because "could not check" must never read as either answer.
func (g *OperatorSecretGate) isSet(ctx context.Context, actor secrets.Actor, appID, name string) (bool, error) {
	ref, err := secrets.AppSecret(appID, name)
	if err != nil {
		return false, fmt.Errorf("apps: checking the operator secrets of %s: %w", appID, err)
	}
	got, err := g.secrets.Read(ctx, actor, ref)
	got.Value.Destroy()
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, secretstore.ErrNotFound):
		return false, nil
	}
	attrs := []slog.Attr{
		slog.String("component", "apps"),
		slog.String("event", "apps.operator_secret_check_failed"),
		slog.String("app_id", appID),
		slog.String("ref", ref.String()),
		slog.String("job_id", jobs.JobIDFromContext(ctx)),
	}
	var se *secretstore.Error
	if errors.As(err, &se) {
		attrs = append(attrs, se.LogAttrs()...)
	} else {
		// Not a store error (the service's own refusal, such as ErrForbidden):
		// its text names the reference and the reason, never a value.
		attrs = append(attrs, slog.String("err", err.Error()))
	}
	g.log.LogAttrs(ctx, slog.LevelWarn, "deploy refused: an operator secret could not be checked", attrs...)
	return false, operatorSecretCheckFailed(err)
}

// operatorSecretRefusal is OperatorSecretGate's refusal: a fixed sentence a
// person reads and a stable code, which the push step records as it is (it
// satisfies codedRefusal). Unwrap returns the store error behind a failed
// check, so errors.Is still reaches its kind; the readiness Gate's
// audit-blocked probe relies on that to tell a client timeout, as it does for
// appsecret.Refusal.
type operatorSecretRefusal struct {
	code     string
	sentence string
	err      error
}

func (r *operatorSecretRefusal) Error() string { return r.sentence }

// Code is the stable refusal code.
func (r *operatorSecretRefusal) Code() string { return r.code }

// Unwrap is the error behind a failed check, or nil.
func (r *operatorSecretRefusal) Unwrap() error { return r.err }

// operatorSecretsUnset is the refusal for declared values that are not set.
// It lists each by label and name, so the owner knows what to set.
func operatorSecretsUnset(unset []tileschema.OperatorSecret) *operatorSecretRefusal {
	list := make([]string, len(unset))
	for i, u := range unset {
		list[i] = fmt.Sprintf("%s (%s)", u.Label, u.Name)
	}
	return &operatorSecretRefusal{code: CodeOperatorSecretUnset, sentence: "This app needs secrets that only its owner can supply, " +
		"and these are not set: " + strings.Join(list, ", ") + ". The app was not deployed, and its running containers are unchanged. " +
		"Set them, then deploy the app again. Error code: " + CodeOperatorSecretUnset + "."}
}

// operatorSecretCheckFailed is the refusal for a presence check that could
// not finish. The sentence is appsecret's store-unavailable one: the owner's
// remedy is the same. The cause goes to the log only.
func operatorSecretCheckFailed(err error) *operatorSecretRefusal {
	return &operatorSecretRefusal{code: appsecret.CodeStoreUnavailable, err: err, sentence: "The secret store could not serve this app's secrets, " +
		"so the app was not deployed. Its running containers are unchanged; deploy the app again once the store is working. " +
		"The api log names the cause. Error code: " + appsecret.CodeStoreUnavailable + "."}
}
