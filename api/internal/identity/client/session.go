package idclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tokensession"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TokenSource is the login the session makes: *Client and Disabled.
type TokenSource interface {
	ClientCredentials(ctx context.Context, realm, clientID string, clientSecret *secret.Value) (secret.Value, error)
}

// AdminCaller is the token-taking Admin API call: *Client and Disabled.
type AdminCaller interface {
	Admin(ctx context.Context, token secret.Value, method, path string, in, out any) (Response, error)
}

// SessionConfig is everything a Session needs. NewSession refuses an
// incomplete one.
type SessionConfig struct {
	// Login gets the token, by client-x509 (no secret).
	Login TokenSource
	// Admin serves the Admin API calls.
	Admin AdminCaller
	// Realm and ClientID are the administrator client the session logs in
	// as: rasputin-admin in realm rasputin.
	Realm, ClientID string
	// Log receives one INFO record per successful login.
	Log *slog.Logger
}

// Session is the api's Admin API session at the identity service (register
// row C28). It holds the token in memory only and gets it lazily: the first
// call logs in. When the Admin API answers 401 (ErrTokenRefused) to a token
// an earlier call obtained, the session logs in once more and retries the
// call once. Each call makes at most one login; it never reads the token's
// exp and starts no timer (tokensession, the C24 shape). It is safe for
// concurrent use.
type Session struct {
	login    TokenSource
	admin    AdminCaller
	realm    string
	clientID string
	log      *slog.Logger
	tokens   *tokensession.Holder
}

// NewSession checks cfg and returns a Session holding no token. It does no
// I/O.
func NewSession(cfg SessionConfig) (*Session, error) {
	switch {
	case cfg.Login == nil:
		return nil, errors.New("idclient: SessionConfig.Login is nil")
	case cfg.Admin == nil:
		return nil, errors.New("idclient: SessionConfig.Admin is nil")
	case cfg.Realm == "" || cfg.ClientID == "":
		return nil, errors.New("idclient: SessionConfig.Realm or ClientID is empty")
	case cfg.Log == nil:
		return nil, errors.New("idclient: SessionConfig.Log is nil")
	}
	s := &Session{login: cfg.Login, admin: cfg.Admin, realm: cfg.Realm, clientID: cfg.ClientID, log: cfg.Log}
	tokens, err := tokensession.New(tokensession.Config{
		Login:   s.clientLogin,
		Refused: func(err error) bool { return errors.Is(err, ErrTokenRefused) },
		WaitEnded: func(ctxErr error) error {
			return s.loginError(&Error{Op: "login", Kind: ErrUnreachable, Err: ctxErr})
		},
		LoggedIn: s.loggedIn,
	})
	if err != nil {
		return nil, fmt.Errorf("idclient: %w", err)
	}
	s.tokens = tokens
	return s, nil
}

// Admin sends one Admin API request under the session's token (Client.Admin).
func (s *Session) Admin(ctx context.Context, method, path string, in, out any) (Response, error) {
	return tokensession.Call(s.tokens, ctx, func(tok secret.Value) (Response, error) {
		return s.admin.Admin(ctx, tok, method, path, in, out)
	})
}

// clientLogin is the session's one login. A failure has already been logged
// by the client.
func (s *Session) clientLogin(ctx context.Context) (secret.Value, error) {
	tok, err := s.login.ClientCredentials(ctx, s.realm, s.clientID, nil)
	if err != nil {
		return secret.Value{}, s.loginError(err)
	}
	return tok, nil
}

// loggedIn writes the one INFO record of a successful login.
func (s *Session) loggedIn(ctx context.Context, reason string) {
	s.log.LogAttrs(ctx, slog.LevelInfo, "identity service login",
		slog.String("component", "identity"), slog.String("event", "identity.login"),
		slog.String("realm", s.realm), slog.String("client_id", s.clientID), slog.String("reason", reason))
}

// loginError is the error of a login that did not complete.
func (s *Session) loginError(err error) error {
	return fmt.Errorf("idclient: log in as %s: %w", s.clientID, err)
}
