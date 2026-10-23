package appsecret

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Secrets is the secrets service as StoreSource calls it: a deploy job's read
// and create-only write (secrets.Service).
type Secrets interface {
	Read(ctx context.Context, a secrets.Actor, r secrets.Ref) (secrets.Secret, error)
	Create(ctx context.Context, a secrets.Actor, r secrets.Ref, value secret.Value) (int, error)
}

// AppNodes answers which node an app is deployed to, and whether it exists.
type AppNodes interface {
	TargetNode(ctx context.Context, appID string) (node string, found bool, err error)
}

// RefRecorder records that the store holds app appID's secret name
// (apps.Store.RecordSecretRef), so the reference check can tell an entry
// created and then lost from one never created
// (geekdojo/geekdojo-brain#800, F-800-01).
type RefRecorder interface {
	RecordSecretRef(ctx context.Context, appID, name string) error
}

// StoreSourceDeps is everything a StoreSource needs. NewStoreSource refuses a
// nil one.
type StoreSourceDeps struct {
	Secrets Secrets
	Apps    AppNodes
	// Refs records each entry once it is confirmed in the store.
	Refs RefRecorder
	// Seed derives the value an absent entry is created with.
	Seed *Seed
	Log  *slog.Logger
}

// StoreSource resolves an app's compose from the secret store, through the
// secrets service, as the app's deploy job on its target node
// (geekdojo/geekdojo-brain#762, S14).
//
// For each distinct ${secret:<name>} token it reads apps/<appID>/<name>. A
// stored entry is used as stored: once an entry exists the store is the
// source. An absent entry is derived from the seed at InitialVersion, created
// with check-and-set 0, and read back; the value read back must equal the
// derived one (compared in constant time), or the compose is refused with
// CodeValueConflict. Because the derivation is frozen, the entry an upgraded
// cluster creates holds the value the app already runs with.
//
// Each entry, once confirmed (read, or created and read back), is recorded
// through Refs. The entry is written before the row that names it (S15 write
// order); a record that fails refuses the resolve, because an unrecorded
// entry would escape a later reference check (ERR-CLOSED).
//
// Every failure returns the zero Value. A store failure is a *Refusal with
// CodeStoreUnavailable; any other failure (authorization, a reference that
// does not parse, the app lookup) is a wrapped error. Neither carries a value
// or the store's own text.
type StoreSource struct {
	secrets Secrets
	apps    AppNodes
	refs    RefRecorder
	seed    *Seed
	log     *slog.Logger
}

// NewStoreSource checks d and returns a StoreSource. It does no I/O.
func NewStoreSource(d StoreSourceDeps) (*StoreSource, error) {
	switch {
	case d.Secrets == nil:
		return nil, errors.New("appsecret: NewStoreSource: Deps.Secrets is nil")
	case d.Apps == nil:
		return nil, errors.New("appsecret: NewStoreSource: Deps.Apps is nil")
	case d.Refs == nil:
		return nil, errors.New("appsecret: NewStoreSource: Deps.Refs is nil")
	case d.Seed == nil:
		return nil, errors.New("appsecret: NewStoreSource: Deps.Seed is nil")
	case d.Log == nil:
		return nil, errors.New("appsecret: NewStoreSource: Deps.Log is nil")
	}
	return &StoreSource{secrets: d.Secrets, apps: d.Apps, refs: d.Refs, seed: d.Seed, log: d.Log}, nil
}

// ResolveCompose returns compose with every token replaced by its stored
// value. A compose with no token is returned as the same bytes, with no store
// call and no app lookup.
func (s *StoreSource) ResolveCompose(ctx context.Context, appID, compose string) (secret.Value, error) {
	tokens, err := tileschema.ScanSecretTokens(compose)
	if err != nil {
		return secret.Value{}, fmt.Errorf("appsecret: resolve %s: %w", appID, err)
	}
	if len(tokens) == 0 {
		return secret.New([]byte(compose)), nil
	}
	node, found, err := s.apps.TargetNode(ctx, appID)
	if err != nil {
		return secret.Value{}, s.failed(ctx, appID, "", fmt.Errorf("appsecret: resolve %s: looking up the app's target node: %w", appID, err))
	}
	if !found {
		return secret.Value{}, s.failed(ctx, appID, "", fmt.Errorf("appsecret: resolve %s: the app does not exist", appID))
	}
	actor := secrets.DeployActor(appID, node)
	values := map[string]secret.Value{}
	defer func() {
		for _, v := range values {
			v.Destroy()
		}
	}()
	for _, tok := range tokens {
		if _, ok := values[tok.Name]; ok {
			continue
		}
		v, err := s.value(ctx, actor, appID, tok.Name)
		if err != nil {
			return secret.Value{}, err
		}
		values[tok.Name] = v
	}
	return splice(compose, tokens, func(name string) ([]byte, error) {
		return values[name].Reveal(), nil
	})
}

// value is the stored value of appID's secret name, creating it from the
// derived value when it is absent. The caller destroys it.
func (s *StoreSource) value(ctx context.Context, actor secrets.Actor, appID, name string) (secret.Value, error) {
	ref, err := secrets.AppSecret(appID, name)
	if err != nil {
		return secret.Value{}, s.failed(ctx, appID, "", fmt.Errorf("appsecret: resolve %s: %w", appID, err))
	}
	got, err := s.secrets.Read(ctx, actor, ref)
	if err == nil {
		return s.recorded(ctx, appID, name, ref, got.Value)
	}
	if !errors.Is(err, secretstore.ErrNotFound) {
		return secret.Value{}, s.refuse(ctx, appID, ref, "read", err)
	}
	derived, err := s.seed.Derive(appID, name, InitialVersion)
	if err != nil {
		return secret.Value{}, s.failed(ctx, appID, ref.String(), fmt.Errorf("appsecret: resolve %s: %w", appID, err))
	}
	defer derived.Destroy()
	// ErrExists is another deploy of the same app creating the entry first.
	// Either way the entry is read back and must hold the derived value.
	if _, err := s.secrets.Create(ctx, actor, ref, derived); err != nil && !errors.Is(err, secrets.ErrExists) {
		return secret.Value{}, s.refuse(ctx, appID, ref, "create", err)
	}
	back, err := s.secrets.Read(ctx, actor, ref)
	if err != nil {
		return secret.Value{}, s.refuse(ctx, appID, ref, "read-back", err)
	}
	if !sameValue(back.Value, derived) {
		back.Value.Destroy()
		s.log.LogAttrs(ctx, slog.LevelError, "secret refused: the stored value does not match the derived value",
			s.attrs(ctx, appID, ref.String(), CodeValueConflict, slog.String("step", "read-back"))...)
		return secret.Value{}, valueConflict()
	}
	return s.recorded(ctx, appID, name, ref, back.Value)
}

// recorded records ref, an entry confirmed in the store, and returns v; a
// record that fails destroys v and refuses with the zero Value.
func (s *StoreSource) recorded(ctx context.Context, appID, name string, ref secrets.Ref, v secret.Value) (secret.Value, error) {
	if err := s.refs.RecordSecretRef(ctx, appID, name); err != nil {
		v.Destroy()
		return secret.Value{}, s.failed(ctx, appID, ref.String(), fmt.Errorf("appsecret: resolve %s: recording %s: %w", appID, ref, err))
	}
	return v, nil
}

// refuse maps a failed service call at op. A store failure is the coded
// refusal, logged at WARN with the store error's own fields; anything else
// (ErrForbidden, ErrInvalidRef, the service's app lookup) is wrapped.
func (s *StoreSource) refuse(ctx context.Context, appID string, ref secrets.Ref, op string, err error) error {
	var se *secretstore.Error
	if !errors.As(err, &se) {
		return s.failed(ctx, appID, ref.String(), fmt.Errorf("appsecret: resolve %s: %s %s: %w", appID, op, ref, err))
	}
	attrs := append(s.attrs(ctx, appID, ref.String(), CodeStoreUnavailable), se.LogAttrs()...)
	attrs = append(attrs, slog.String("step", op))
	s.log.LogAttrs(ctx, slog.LevelWarn, "secret refused: the store call failed", attrs...)
	return storeUnavailable(err)
}

// failed logs a refusal that is not a store failure at WARN and returns err.
// err carries no value: the service's and the reference's errors name the
// reference only.
func (s *StoreSource) failed(ctx context.Context, appID, ref string, err error) error {
	attrs := append(s.attrs(ctx, appID, ref, "failed"), slog.String("err", err.Error()))
	s.log.LogAttrs(ctx, slog.LevelWarn, "secret refused", attrs...)
	return err
}

// attrs are the fields every refusal record carries.
func (s *StoreSource) attrs(ctx context.Context, appID, ref, outcome string, extra ...slog.Attr) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("component", "appsecret"),
		slog.String("event", "appsecret.resolve_refused"),
		slog.String("app_id", appID),
		slog.String("ref", ref),
		slog.String("outcome", outcome),
		slog.String("job_id", jobs.JobIDFromContext(ctx)),
	}
	return append(attrs, extra...)
}

// sameValue reports whether a and b hold the same bytes, in time that does
// not depend on where they differ. No byte leaves.
func sameValue(a, b secret.Value) bool {
	return subtle.ConstantTimeCompare(a.Reveal(), b.Reveal()) == 1
}
