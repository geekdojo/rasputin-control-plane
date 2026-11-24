package idclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The console's authorization-code exchange and the key fetch beside it
// (geekdojo/geekdojo-brain#989, Identity 4.7). Both go to the identity
// service on loopback over the api's own client leaf, carrying a sign-in
// door's forwarded headers, so every address the service builds (the ID
// token's issuer, the key set's URL) is the door's, exactly as a browser at
// that door sees it.

// CodeExchange is one authorization-code exchange.
type CodeExchange struct {
	// Realm and ClientID name the client the code was issued to; the client
	// authenticates by client-x509 (the api's leaf), so no secret is sent.
	Realm, ClientID string
	// Code and Verifier are the authorization code and its PKCE verifier.
	// Neither is logged, and both travel only in the form body.
	Code, Verifier secret.Value
	// RedirectURI is the redirect URI the authorization request named.
	RedirectURI string
	// Forward writes the door's forwarded headers (doors.Door.SetForwarded).
	Forward func(http.Header)
}

// ExchangeCode posts x to the token endpoint and returns the answer's ID
// token; every other field of the answer (the access and refresh tokens) is
// read only to be cleared. It fails with the token endpoint's kinds
// (tokenField): a spent, forged or mismatched code is ErrProtocol with OAuth
// error invalid_grant, and a service that does not answer is ErrUnreachable.
func (c *Client) ExchangeCode(ctx context.Context, x CodeExchange) (secret.Value, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	path := "/realms/" + url.PathEscape(x.Realm) + "/protocol/openid-connect/token"
	if x.Realm == "" || x.ClientID == "" || x.RedirectURI == "" || x.Code.Len() == 0 || x.Verifier.Len() == 0 || x.Forward == nil {
		return secret.Value{}, c.failed(ctx, &Error{Op: "token", Path: path, Kind: ErrInvalidValue,
			Err: errors.New("the exchange is missing its realm, client, redirect URI, code, verifier or door")})
	}
	tok, e := c.tokenField(ctx, path, codeForm(x), "id_token", x.Forward)
	if e != nil {
		return secret.Value{}, c.failed(ctx, e)
	}
	return tok, nil
}

// codeForm is the exchange's form body, built in one buffer sized up front so
// no copy of the code or the verifier is left behind by a grow.
func codeForm(x CodeExchange) []byte {
	id, redirect := url.QueryEscape(x.ClientID), url.QueryEscape(x.RedirectURI)
	const head = "grant_type=authorization_code&client_id="
	size := len(head) + len(id) + len("&redirect_uri=") + len(redirect) +
		len("&code=") + 3*x.Code.Len() + len("&code_verifier=") + 3*x.Verifier.Len()
	b := make([]byte, 0, size)
	b = append(b, head...)
	b = append(b, id...)
	b = append(b, "&redirect_uri="...)
	b = append(b, redirect...)
	b = append(b, "&code="...)
	b = appendQueryEscaped(b, x.Code.Reveal())
	b = append(b, "&code_verifier="...)
	b = appendQueryEscaped(b, x.Verifier.Reveal())
	return b
}

// Forwarding is an HTTP client over the client's own connection pool (the
// api's leaf) that sends every request to the identity service's loopback
// listener whatever its URL names, with the URL's host as the Host header
// and forward's headers written: the key set at a door's issuer is fetched
// as that door's browser would see it, without leaving loopback. It follows
// no redirect. Only a URL whose path is under /realms/ is sent.
func (c *Client) Forwarding(forward func(http.Header)) *http.Client {
	base, _ := url.Parse(c.base) // New checked it
	return &http.Client{
		Transport:     forwardingTransport{base: base, inner: c.transport, forward: forward},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
		Timeout:       c.timeout,
	}
}

type forwardingTransport struct {
	base    *url.URL
	inner   http.RoundTripper
	forward func(http.Header)
}

func (f forwardingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(r.URL.Path, "/realms/") {
		return nil, &Error{Op: "keys", Path: r.URL.Path, Kind: ErrInvalidValue, Err: errors.New("the path is not under /realms/")}
	}
	out := r.Clone(r.Context())
	out.Host = r.URL.Host
	u := *r.URL
	u.Scheme, u.Host = f.base.Scheme, f.base.Host
	out.URL = &u
	if f.forward != nil {
		f.forward(out.Header)
	}
	return f.inner.RoundTrip(out)
}
