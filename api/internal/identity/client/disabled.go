package idclient

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Disabled is the client of a configuration with no identity service (Kind
// ErrDisabled), or whose backend is the explicitly chosen local mock (Kind
// ErrMock: refuses every call, geekdojo/geekdojo-brain#982). Every call
// returns Kind and makes no network call, so a consumer is never handed a nil
// client and never mistakes "off" for an empty service.
type Disabled struct{ Kind error }

// ClientCredentials refuses with Kind.
func (d Disabled) ClientCredentials(context.Context, string, string, *secret.Value) (secret.Value, error) {
	return secret.Value{}, &Error{Op: "token", Kind: d.Kind}
}

// Admin refuses with Kind.
func (d Disabled) Admin(_ context.Context, _ secret.Value, _, path string, _, _ any) (Response, error) {
	return Response{}, &Error{Op: "admin", Path: path, Kind: d.Kind}
}

// Ready refuses with Kind.
func (d Disabled) Ready(context.Context) error {
	return &Error{Op: "ready", Kind: d.Kind}
}

// Health refuses with Kind.
func (d Disabled) Health(context.Context) (HealthReport, error) {
	return HealthReport{}, &Error{Op: "health", Kind: d.Kind}
}
