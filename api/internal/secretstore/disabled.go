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

// CertLogin returns ErrDisabled, so a login session built over a store that is
// off refuses every call with no I/O (geekdojo/geekdojo-brain#759).
func (Disabled) CertLogin(context.Context, string) (secret.Value, error) {
	return secret.Value{}, &Error{Op: "login", Kind: ErrDisabled}
}
