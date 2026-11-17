package secretstoretest

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// NoTransit is a token-free Transit store (secrets.TransitStore) that refuses
// every call with secretstore.ErrDisabled, as the composition root's key
// session over a store that is off does. Tests that never touch an app key
// pass it as secrets.Deps.Transit (geekdojo/geekdojo-brain#1084).
type NoTransit struct{}

func (NoTransit) TransitCreateKey(_ context.Context, k secretstore.TransitKey) error {
	return secretstore.Disabled{}.TransitCreateKey(context.Background(), secret.Value{}, k)
}

func (NoTransit) TransitEncrypt(_ context.Context, k secretstore.TransitKey, v secret.Value) (secret.Value, error) {
	return secretstore.Disabled{}.TransitEncrypt(context.Background(), secret.Value{}, k, v)
}

func (NoTransit) TransitDecrypt(_ context.Context, k secretstore.TransitKey, v secret.Value) (secret.Value, error) {
	return secretstore.Disabled{}.TransitDecrypt(context.Background(), secret.Value{}, k, v)
}

func (NoTransit) TransitDestroyKey(_ context.Context, k secretstore.TransitKey) error {
	return secretstore.Disabled{}.TransitDestroyKey(context.Background(), secret.Value{}, k)
}
