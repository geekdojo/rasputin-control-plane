package storestate

import (
	"context"
	"errors"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// KVStore is the store ObservedStore wraps: the composition root's store.
type KVStore interface {
	Health(ctx context.Context) (secretstore.Health, error)
	Read(ctx context.Context, token secret.Value, p secretstore.KVPath, version int) (secretstore.KV, error)
	Write(ctx context.Context, token secret.Value, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error)
	Versions(ctx context.Context, token secret.Value, p secretstore.KVPath) (secretstore.Metadata, error)
}

// Observer takes each audited call's outcome (Monitor.ObserveAudited).
type Observer interface {
	ObserveAudited(ctx context.Context, err error)
}

// ObservedStore forwards every call to the store it wraps unchanged, and
// reports the outcome of each audited one (Read, Write, Versions) to the
// Observer with the caller's own ctx. Health is not audited, so it passes
// straight through.
type ObservedStore struct {
	inner KVStore
	obs   Observer
}

// NewObservedStore wraps inner. It refuses a nil collaborator.
func NewObservedStore(inner KVStore, obs Observer) (*ObservedStore, error) {
	switch {
	case inner == nil:
		return nil, errors.New("storestate: NewObservedStore: the store is nil")
	case obs == nil:
		return nil, errors.New("storestate: NewObservedStore: the observer is nil")
	}
	return &ObservedStore{inner: inner, obs: obs}, nil
}

// Health forwards to the store.
func (o *ObservedStore) Health(ctx context.Context) (secretstore.Health, error) {
	return o.inner.Health(ctx)
}

// Read forwards to the store and reports the outcome.
func (o *ObservedStore) Read(ctx context.Context, token secret.Value, p secretstore.KVPath, version int) (secretstore.KV, error) {
	kv, err := o.inner.Read(ctx, token, p, version)
	o.obs.ObserveAudited(ctx, err)
	return kv, err
}

// Write forwards to the store and reports the outcome.
func (o *ObservedStore) Write(ctx context.Context, token secret.Value, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error) {
	v, err := o.inner.Write(ctx, token, p, data, cas)
	o.obs.ObserveAudited(ctx, err)
	return v, err
}

// Versions forwards to the store and reports the outcome.
func (o *ObservedStore) Versions(ctx context.Context, token secret.Value, p secretstore.KVPath) (secretstore.Metadata, error) {
	m, err := o.inner.Versions(ctx, token, p)
	o.obs.ObserveAudited(ctx, err)
	return m, err
}
