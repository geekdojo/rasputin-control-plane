package storestate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Source is the deploy family's secret source (apps.SecretSource), declared
// here with the one method the Gate calls.
type Source interface {
	ResolveCompose(ctx context.Context, appID, compose string) (secret.Value, map[string]secret.Value, error)
}

// Gate is the secret source a requested store puts in front of the inner
// source: it refuses a secret-bearing compose until the store reads ready,
// and then delegates.
type Gate struct {
	inner Source
	m     *Monitor
	log   *slog.Logger
}

// NewGate returns a Gate around inner. It refuses a nil collaborator.
func NewGate(inner Source, m *Monitor, log *slog.Logger) (*Gate, error) {
	switch {
	case inner == nil:
		return nil, errors.New("storestate: NewGate: the inner source is nil")
	case m == nil:
		return nil, errors.New("storestate: NewGate: the monitor is nil")
	case log == nil:
		return nil, errors.New("storestate: NewGate: the logger is nil")
	}
	return &Gate{inner: inner, m: m, log: log}, nil
}

// ResolveCompose resolves compose through the inner source when it carries no
// ${secret:} token, or when the store reads ready, and returns the inner
// source's compose and value map unchanged. A malformed token is refused
// without asking the store. Any other state refuses with a *NotReadyError,
// the zero Value and a nil map, except AuditBlocked, where the inner source is
// called once as the probe that can clear it: an answered read returns its
// result, and a read that times out again refuses.
func (g *Gate) ResolveCompose(ctx context.Context, appID, compose string) (secret.Value, map[string]secret.Value, error) {
	tokens, err := tileschema.ScanSecretTokens(compose)
	if err != nil {
		return secret.Value{}, nil, fmt.Errorf("storestate: scanning the compose for secret tokens: %w", err)
	}
	if len(tokens) == 0 {
		return g.inner.ResolveCompose(ctx, appID, compose)
	}
	st, err := g.m.State(ctx)
	if err != nil {
		return secret.Value{}, nil, err
	}
	switch st {
	case Ready:
		return g.inner.ResolveCompose(ctx, appID, compose)
	case AuditBlocked:
		v, env, err := g.inner.ResolveCompose(ctx, appID, compose)
		if err == nil {
			return v, env, nil
		}
		if ctx.Err() == nil && isClientTimeout(err) {
			return g.refuse(ctx, appID, st)
		}
		return secret.Value{}, nil, err
	}
	return g.refuse(ctx, appID, st)
}

// refuse logs the refusal under the job's id and returns it.
func (g *Gate) refuse(ctx context.Context, appID string, st State) (secret.Value, map[string]secret.Value, error) {
	g.log.LogAttrs(ctx, slog.LevelWarn, "secret-bearing deploy refused",
		slog.String("component", "secretstore"), slog.String("app_id", appID),
		slog.String("state", string(st)), slog.String("job_id", jobs.JobIDFromContext(ctx)))
	return secret.Value{}, nil, &NotReadyError{State: st}
}
