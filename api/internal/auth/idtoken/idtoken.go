// Package idtoken verifies the identity service's ID tokens and back-channel
// logout tokens for one client at one issuer (geekdojo/geekdojo-brain#989,
// Identity 4.7). It wraps github.com/coreos/go-oidc/v3 (capability row
// T160): the signature against the issuer's key set, re-fetched once for a
// key id it does not hold, and the issuer, audience and expiry, RS256 only.
// Nothing here hand-verifies a JWT (SEC-CRYPTO).
//
// The key set is fetched through the http.Client the composition root
// gives, which reaches the identity service on loopback over the api's own
// leaf with the door's forwarded headers (idclient.Client.Forwarding), so
// the keys are the ones the door's issuer publishes.
//
// A token is never logged and never put in an error.
package idtoken

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// ErrUnavailable is a verification that could not finish because the
// issuer's key set could not be fetched: the identity service is not
// answering, which is not the token's fault.
var ErrUnavailable = errors.New("idtoken: the issuer's keys could not be fetched")

// ErrInvalid is every refusal of the token itself: its signature, issuer,
// audience, expiry or shape.
var ErrInvalid = errors.New("idtoken: the token was refused")

// backchannelEvent is the back-channel logout event's member name.
const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// Claims are the ID token claims the console reads.
type Claims struct {
	Issuer   string
	Subject  string
	Audience []string
	// AuthorizedParty is azp: the client the token was issued to.
	AuthorizedParty string
	Nonce           string
	// SessionID is sid: the identity service's session.
	SessionID string
	// AuthTime is auth_time: when the person last authenticated; the zero
	// time when the token carries none.
	AuthTime time.Time
	Expiry   time.Time
	// PreferredUsername is preferred_username, for display only.
	PreferredUsername string
	// Roles are the console roles, rasputin_roles.
	Roles []string
}

// Verifier verifies tokens for one client at one issuer.
type Verifier struct {
	v *oidc.IDTokenVerifier
}

// New is the verifier for clientID at issuer, whose key set it fetches from
// <issuer>/protocol/openid-connect/certs through client, with now as the
// clock expiry is checked on. It does no I/O.
func New(ctx context.Context, issuer, clientID string, client *http.Client, now func() time.Time) (*Verifier, error) {
	switch {
	case issuer == "" || clientID == "":
		return nil, errors.New("idtoken: the issuer or the client id is empty")
	case client == nil:
		return nil, errors.New("idtoken: the key client is nil")
	case now == nil:
		return nil, errors.New("idtoken: the clock is nil")
	}
	keyClient := &http.Client{Transport: statusTransport{inner: client.Transport}, CheckRedirect: client.CheckRedirect, Timeout: client.Timeout}
	remote := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, keyClient), issuer+"/protocol/openid-connect/certs")
	return &Verifier{v: oidc.NewVerifier(issuer, probedKeys{inner: remote}, &oidc.Config{ClientID: clientID, Now: now})}, nil
}

// IDToken verifies raw as an ID token and returns its claims. The caller
// checks what is particular to its flow: azp, nonce, auth_time, sid.
func (v *Verifier) IDToken(ctx context.Context, raw secret.Value) (Claims, error) {
	ctx, probe := withProbe(ctx)
	tok, err := v.v.Verify(ctx, string(raw.Reveal()))
	if err != nil {
		return Claims{}, classify(probe, err)
	}
	var extra struct {
		AZP      string   `json:"azp"`
		SID      string   `json:"sid"`
		AuthTime *int64   `json:"auth_time"`
		Name     string   `json:"preferred_username"`
		Roles    []string `json:"rasputin_roles"`
	}
	if err := tok.Claims(&extra); err != nil {
		return Claims{}, fmt.Errorf("%w: its claims do not decode", ErrInvalid)
	}
	c := Claims{
		Issuer: tok.Issuer, Subject: tok.Subject, Audience: tok.Audience, AuthorizedParty: extra.AZP,
		Nonce: tok.Nonce, SessionID: extra.SID, Expiry: tok.Expiry, PreferredUsername: extra.Name, Roles: extra.Roles,
	}
	if extra.AuthTime != nil {
		c.AuthTime = time.Unix(*extra.AuthTime, 0).UTC()
	}
	return c, nil
}

// LogoutToken verifies raw as a back-channel logout token (go-oidc's
// VerifyLogout: the signature, issuer, audience and expiry, the logout
// event present, a jti, and no nonce, so an ID token is never read as one)
// and returns its sid, which it also requires.
func (v *Verifier) LogoutToken(ctx context.Context, raw secret.Value) (string, error) {
	ctx, probe := withProbe(ctx)
	tok, err := v.v.VerifyLogout(ctx, string(raw.Reveal()))
	if err != nil {
		return "", classify(probe, err)
	}
	var events struct {
		Events map[string]any `json:"events"`
	}
	if err := tok.Claims(&events); err != nil || events.Events == nil {
		return "", fmt.Errorf("%w: it carries no events member", ErrInvalid)
	}
	if _, ok := events.Events[backchannelEvent]; !ok {
		return "", fmt.Errorf("%w: it carries no back-channel logout event", ErrInvalid)
	}
	if tok.SessionID == "" {
		return "", fmt.Errorf("%w: it names no session", ErrInvalid)
	}
	return tok.SessionID, nil
}

// classify is a verification error as ErrUnavailable, when the key fetch
// failed, or ErrInvalid. go-oidc formats the key set's error with %v, so
// the probe, not the chain, says which.
func classify(p *probe, err error) error {
	if p.unreachable {
		return ErrUnavailable
	}
	var expired *oidc.TokenExpiredError
	if errors.As(err, &expired) {
		return fmt.Errorf("%w: it has expired", ErrInvalid)
	}
	return fmt.Errorf("%w: %v", ErrInvalid, err)
}

// errKeysUnreachable marks a key fetch that got no usable answer.
var errKeysUnreachable = errors.New("idtoken: key set unreachable")

// statusTransport turns a key fetch that failed or answered other than 200
// into errKeysUnreachable, so go-oidc's error chain carries it.
type statusTransport struct{ inner http.RoundTripper }

func (s statusTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	inner := s.inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	resp, err := inner.RoundTrip(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errKeysUnreachable, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: status %d", errKeysUnreachable, resp.StatusCode)
	}
	return resp, nil
}

// probe records whether a verification's key fetch was unreachable.
type probe struct{ unreachable bool }

type probeKey struct{}

func withProbe(ctx context.Context) (context.Context, *probe) {
	p := &probe{}
	return context.WithValue(ctx, probeKey{}, p), p
}

// probedKeys is the remote key set, recording an unreachable fetch on the
// verification's probe.
type probedKeys struct{ inner oidc.KeySet }

func (k probedKeys) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	payload, err := k.inner.VerifySignature(ctx, jwt)
	if err != nil && errors.Is(err, errKeysUnreachable) {
		if p, ok := ctx.Value(probeKey{}).(*probe); ok {
			p.unreachable = true
		}
	}
	return payload, err
}
