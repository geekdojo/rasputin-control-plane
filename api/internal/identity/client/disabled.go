package idclient

import (
	"context"
	"net/http"

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

// ExchangeCode refuses with Kind.
func (d Disabled) ExchangeCode(context.Context, CodeExchange) (secret.Value, error) {
	return secret.Value{}, &Error{Op: "token", Kind: d.Kind}
}

// ExchangeAccessToken refuses with Kind.
func (d Disabled) ExchangeAccessToken(context.Context, CodeExchange) (secret.Value, error) {
	return secret.Value{}, &Error{Op: "token", Kind: d.Kind}
}

// Forwarding is a client that refuses every request with Kind.
func (d Disabled) Forwarding(func(http.Header)) *http.Client {
	return &http.Client{Transport: refusingTransport{kind: d.Kind}}
}

type refusingTransport struct{ kind error }

func (t refusingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, &Error{Op: "keys", Path: r.URL.Path, Kind: t.kind}
}
