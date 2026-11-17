package secretstore

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Disabled is the store of a configuration that has none, or whose store
// settings were refused. Every method returns ErrDisabled and makes no network
// call, so a consumer is never handed a nil store and never mistakes "off" for
// an empty one.
type Disabled struct{}

// Health returns ErrDisabled.
func (Disabled) Health(context.Context) (Health, error) {
	return Health{}, &Error{Op: "health", Kind: ErrDisabled}
}

// Read returns ErrDisabled.
func (Disabled) Read(_ context.Context, _ secret.Value, p KVPath, _ int) (KV, error) {
	return KV{}, fail("read", p, ErrDisabled, nil)
}

// Write returns ErrDisabled.
func (Disabled) Write(_ context.Context, _ secret.Value, p KVPath, _ map[string]secret.Value, _ int) (int, error) {
	return 0, fail("write", p, ErrDisabled, nil)
}

// Versions returns ErrDisabled.
func (Disabled) Versions(_ context.Context, _ secret.Value, p KVPath) (Metadata, error) {
	return Metadata{}, fail("versions", p, ErrDisabled, nil)
}

// Delete returns ErrDisabled.
func (Disabled) Delete(_ context.Context, _ secret.Value, p KVPath) error {
	return fail("delete", p, ErrDisabled, nil)
}

// CertLogin returns ErrDisabled, so a login session built over a store that is
// off refuses every call with no I/O (geekdojo/geekdojo-brain#759).
func (Disabled) CertLogin(context.Context, string) (secret.Value, error) {
	return secret.Value{}, &Error{Op: "login", Kind: ErrDisabled}
}

// TransitCreateKey returns ErrDisabled.
func (Disabled) TransitCreateKey(_ context.Context, _ secret.Value, k TransitKey) error {
	return fail("transit_create", k.kvPath(), ErrDisabled, nil)
}

// TransitEncrypt returns ErrDisabled.
func (Disabled) TransitEncrypt(_ context.Context, _ secret.Value, k TransitKey, _ secret.Value) (secret.Value, error) {
	return secret.Value{}, fail("transit_encrypt", k.kvPath(), ErrDisabled, nil)
}

// TransitDecrypt returns ErrDisabled.
func (Disabled) TransitDecrypt(_ context.Context, _ secret.Value, k TransitKey, _ secret.Value) (secret.Value, error) {
	return secret.Value{}, fail("transit_decrypt", k.kvPath(), ErrDisabled, nil)
}

// TransitDestroyKey returns ErrDisabled.
func (Disabled) TransitDestroyKey(_ context.Context, _ secret.Value, k TransitKey) error {
	return fail("transit_destroy", k.kvPath(), ErrDisabled, nil)
}
