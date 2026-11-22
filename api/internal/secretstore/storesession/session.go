// Package storesession is the api's login session at the secret store
// (geekdojo/geekdojo-brain#759, Secrets 3.2).
//
// A Session holds the api's store token in memory only and gets it lazily:
// the first call that needs a token logs in through the store's cert auth
// method. When the store refuses (secretstore.ErrDenied) a token that an
// earlier call obtained, the session drops it, logs in once more and retries
// the call once. Each call makes at most one login, and every other outcome
// is returned unchanged with the token kept.
//
// The session reads no clock and no TTL, and starts no timer: the store's
// refusal is the only fact that makes it log in again (ARCH-FACTS). The token
// never leaves this package; consumers call Read, Write, Versions and Delete,
// and a key session the Transit calls (geekdojo/geekdojo-brain#1084).
package storesession

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tokensession"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Login is the store's cert login: *secretstore.Client, secretstore.Mock and
// secretstore.Disabled.
type Login interface {
	CertLogin(ctx context.Context, role string) (secret.Value, error)
}

// Store is the token-taking store the session calls: the composition root's
// observed store.
type Store interface {
	Read(ctx context.Context, token secret.Value, p secretstore.KVPath, version int) (secretstore.KV, error)
	Write(ctx context.Context, token secret.Value, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error)
	Versions(ctx context.Context, token secret.Value, p secretstore.KVPath) (secretstore.Metadata, error)
	Delete(ctx context.Context, token secret.Value, p secretstore.KVPath) error
}

// Transit is the token-taking Transit store a key session calls
// (geekdojo/geekdojo-brain#1084): the key identity's own client.
type Transit interface {
	TransitCreateKey(ctx context.Context, token secret.Value, k secretstore.TransitKey) error
	TransitEncrypt(ctx context.Context, token secret.Value, k secretstore.TransitKey, plaintext secret.Value) (secret.Value, error)
	TransitDecrypt(ctx context.Context, token secret.Value, k secretstore.TransitKey, ciphertext secret.Value) (secret.Value, error)
	TransitDestroyKey(ctx context.Context, token secret.Value, k secretstore.TransitKey) error
}

// Observer takes each login's outcome, with the caller's ctx
// (storestate.Monitor.ObserveAudited). The KV calls are reported by the
// observed store itself.
type Observer interface {
	ObserveAudited(ctx context.Context, err error)
}

// Config is everything a Session needs. New refuses an incomplete one.
type Config struct {
	// Role is the store cert role the session logs in as.
	Role string
	// Login logs in. The client's own per-call bound limits each login.
	Login Login
	// Store serves the KV calls, and Transit the key calls
	// (geekdojo/geekdojo-brain#1084). A session needs at least one: the api's
	// kv session has a Store, its key session a Transit. A call whose backend
	// the session was not given is refused with ErrDisabled.
	Store   Store
	Transit Transit
	// Observer is told the outcome of every login.
	Observer Observer
	// Log receives one INFO record per successful login.
	Log *slog.Logger
}

// Session is a lazily obtained store token and the calls that use it. It is
// safe for concurrent use.
type Session struct {
	role    string
	login   Login
	store   Store
	transit Transit
	obs     Observer
	log     *slog.Logger

	// tokens is the held token and the one retry rule
	// (tokensession, shared with the identity session).
	tokens *tokensession.Holder
}

// New checks cfg and returns a Session holding no token. It does no I/O.
func New(cfg Config) (*Session, error) {
	switch {
	case cfg.Role == "":
		return nil, errors.New("storesession: Config.Role is empty")
	case cfg.Login == nil:
		return nil, errors.New("storesession: Config.Login is nil")
	case cfg.Store == nil && cfg.Transit == nil:
		return nil, errors.New("storesession: Config.Store and Config.Transit are both nil")
	case cfg.Observer == nil:
		return nil, errors.New("storesession: Config.Observer is nil")
	case cfg.Log == nil:
		return nil, errors.New("storesession: Config.Log is nil")
	}
	s := &Session{role: cfg.Role, login: cfg.Login, store: cfg.Store, transit: cfg.Transit, obs: cfg.Observer, log: cfg.Log}
	tokens, err := tokensession.New(tokensession.Config{
		Login:   s.certLogin,
		Refused: func(err error) bool { return errors.Is(err, secretstore.ErrDenied) },
		WaitEnded: func(ctxErr error) error {
			return s.loginError(&secretstore.Error{
				Op: "login", Mount: "auth/cert", Path: "login", Kind: secretstore.ErrUnreachable, Err: ctxErr,
			})
		},
		LoggedIn: s.loggedIn,
	})
	if err != nil {
		return nil, fmt.Errorf("storesession: %w", err)
	}
	s.tokens = tokens
	return s, nil
}

// Read returns version of the secret at p, or the latest when version is 0.
func (s *Session) Read(ctx context.Context, p secretstore.KVPath, version int) (secretstore.KV, error) {
	if s.store == nil {
		return secretstore.KV{}, noBackend("read")
	}
	return tokensession.Call(s.tokens, ctx, func(tok secret.Value) (secretstore.KV, error) {
		return s.store.Read(ctx, tok, p, version)
	})
}

// Write stores data at p as a new version under check-and-set cas and
// returns its number.
func (s *Session) Write(ctx context.Context, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error) {
	if s.store == nil {
		return 0, noBackend("write")
	}
	return tokensession.Call(s.tokens, ctx, func(tok secret.Value) (int, error) {
		return s.store.Write(ctx, tok, p, data, cas)
	})
}

// Versions returns the version history of the secret at p.
func (s *Session) Versions(ctx context.Context, p secretstore.KVPath) (secretstore.Metadata, error) {
	if s.store == nil {
		return secretstore.Metadata{}, noBackend("versions")
	}
	return tokensession.Call(s.tokens, ctx, func(tok secret.Value) (secretstore.Metadata, error) {
		return s.store.Versions(ctx, tok, p)
	})
}

// Delete removes the secret at p with every version
// (geekdojo/geekdojo-brain#761).
func (s *Session) Delete(ctx context.Context, p secretstore.KVPath) error {
	if s.store == nil {
		return noBackend("delete")
	}
	_, err := tokensession.Call(s.tokens, ctx, func(tok secret.Value) (struct{}, error) {
		return struct{}{}, s.store.Delete(ctx, tok, p)
	})
	return err
}

// TransitCreateKey creates key k.
func (s *Session) TransitCreateKey(ctx context.Context, k secretstore.TransitKey) error {
	if s.transit == nil {
		return noBackend("transit_create")
	}
	_, err := tokensession.Call(s.tokens, ctx, func(tok secret.Value) (struct{}, error) {
		return struct{}{}, s.transit.TransitCreateKey(ctx, tok, k)
	})
	return err
}

// TransitEncrypt encrypts plaintext, standard base64, under k.
func (s *Session) TransitEncrypt(ctx context.Context, k secretstore.TransitKey, plaintext secret.Value) (secret.Value, error) {
	if s.transit == nil {
		return secret.Value{}, noBackend("transit_encrypt")
	}
	return tokensession.Call(s.tokens, ctx, func(tok secret.Value) (secret.Value, error) {
		return s.transit.TransitEncrypt(ctx, tok, k, plaintext)
	})
}

// TransitDecrypt decrypts ciphertext under k.
func (s *Session) TransitDecrypt(ctx context.Context, k secretstore.TransitKey, ciphertext secret.Value) (secret.Value, error) {
	if s.transit == nil {
		return secret.Value{}, noBackend("transit_decrypt")
	}
	return tokensession.Call(s.tokens, ctx, func(tok secret.Value) (secret.Value, error) {
		return s.transit.TransitDecrypt(ctx, tok, k, ciphertext)
	})
}

// TransitDestroyKey destroys key k.
func (s *Session) TransitDestroyKey(ctx context.Context, k secretstore.TransitKey) error {
	if s.transit == nil {
		return noBackend("transit_destroy")
	}
	_, err := tokensession.Call(s.tokens, ctx, func(tok secret.Value) (struct{}, error) {
		return struct{}{}, s.transit.TransitDestroyKey(ctx, tok, k)
	})
	return err
}

// noBackend is the refusal of a call this session was not given a backend
// for: a wiring mistake, which fails closed with no login.
func noBackend(op string) error {
	return &secretstore.Error{Op: op, Kind: secretstore.ErrDisabled, Err: errors.New("this session has no backend for the call")}
}

// certLogin is the session's one login: the store's cert login as the role,
// its outcome told to the observer. A failure has already been logged by the
// client.
func (s *Session) certLogin(ctx context.Context) (secret.Value, error) {
	tok, err := s.login.CertLogin(ctx, s.role)
	s.obs.ObserveAudited(ctx, err)
	if err != nil {
		return secret.Value{}, s.loginError(err)
	}
	return tok, nil
}

// loggedIn writes the one INFO record of a successful login.
func (s *Session) loggedIn(ctx context.Context, reason string) {
	s.log.LogAttrs(ctx, slog.LevelInfo, "secret store login",
		slog.String("component", "secretstore"), slog.String("event", "secretstore.login"),
		slog.String("role", s.role), slog.String("reason", reason))
}

// loginError is the error of a login that did not complete.
func (s *Session) loginError(err error) error {
	return fmt.Errorf("storesession: log in as %s: %w", s.role, err)
}
