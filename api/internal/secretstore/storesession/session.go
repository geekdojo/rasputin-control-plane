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
// never leaves this package; consumers call Read, Write, Versions and Delete.
package storesession

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
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
	// Store serves the KV calls.
	Store Store
	// Observer is told the outcome of every login.
	Observer Observer
	// Log receives one INFO record per successful login.
	Log *slog.Logger
}

// The reasons a login record gives.
const (
	reasonNoToken = "no-token"
	reasonRefused = "refused"
)

// Session is a lazily obtained store token and the calls that use it. It is
// safe for concurrent use.
type Session struct {
	role  string
	login Login
	store Store
	obs   Observer
	log   *slog.Logger

	// loginSlot is held by the one login in flight: a call takes it by sending
	// and gives it back by receiving. A call waiting for it also watches its
	// own ctx, so a stalled login never holds a caller past that caller's ctx
	// (F-759-01).
	loginSlot chan struct{}

	// mu guards the fields below. It is held only to read or swap them,
	// never across I/O.
	mu   sync.Mutex
	tok  secret.Value
	held bool
	// gen counts successful logins. A refused call names the generation of
	// the token it carried, so a re-login that finds a newer one knows
	// another call has already logged in again.
	gen uint64
}

// New checks cfg and returns a Session holding no token. It does no I/O.
func New(cfg Config) (*Session, error) {
	switch {
	case cfg.Role == "":
		return nil, errors.New("storesession: Config.Role is empty")
	case cfg.Login == nil:
		return nil, errors.New("storesession: Config.Login is nil")
	case cfg.Store == nil:
		return nil, errors.New("storesession: Config.Store is nil")
	case cfg.Observer == nil:
		return nil, errors.New("storesession: Config.Observer is nil")
	case cfg.Log == nil:
		return nil, errors.New("storesession: Config.Log is nil")
	}
	return &Session{
		role:      cfg.Role,
		login:     cfg.Login,
		store:     cfg.Store,
		obs:       cfg.Observer,
		log:       cfg.Log,
		loginSlot: make(chan struct{}, 1),
	}, nil
}

// Read returns version of the secret at p, or the latest when version is 0.
func (s *Session) Read(ctx context.Context, p secretstore.KVPath, version int) (secretstore.KV, error) {
	return call(s, ctx, func(tok secret.Value) (secretstore.KV, error) {
		return s.store.Read(ctx, tok, p, version)
	})
}

// Write stores data at p as a new version under check-and-set cas and
// returns its number.
func (s *Session) Write(ctx context.Context, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error) {
	return call(s, ctx, func(tok secret.Value) (int, error) {
		return s.store.Write(ctx, tok, p, data, cas)
	})
}

// Versions returns the version history of the secret at p.
func (s *Session) Versions(ctx context.Context, p secretstore.KVPath) (secretstore.Metadata, error) {
	return call(s, ctx, func(tok secret.Value) (secretstore.Metadata, error) {
		return s.store.Versions(ctx, tok, p)
	})
}

// Delete removes the secret at p with every version
// (geekdojo/geekdojo-brain#761).
func (s *Session) Delete(ctx context.Context, p secretstore.KVPath) error {
	_, err := call(s, ctx, func(tok secret.Value) (struct{}, error) {
		return struct{}{}, s.store.Delete(ctx, tok, p)
	})
	return err
}

// call is the one retry rule. It runs f with the held token, logging in first
// when none is held. A refusal of a token an earlier call obtained gets one
// re-login and one retry; a refusal of the token this call minted, and every
// other outcome, is returned as it is.
func call[T any](s *Session, ctx context.Context, f func(tok secret.Value) (T, error)) (T, error) {
	var zero T
	tok, gen, minted, err := s.token(ctx)
	if err != nil {
		return zero, err
	}
	v, err := f(tok)
	if err == nil || minted || !errors.Is(err, secretstore.ErrDenied) {
		return v, err
	}
	tok, err = s.relogin(ctx, gen)
	if err != nil {
		return zero, err
	}
	return f(tok)
}

// token returns the held token and its generation, logging in when none is
// held. minted reports whether this call made the login.
func (s *Session) token(ctx context.Context) (tok secret.Value, gen uint64, minted bool, err error) {
	return s.obtain(ctx, reasonNoToken, func(held bool, _ uint64) bool { return held })
}

// relogin replaces the token of generation gen, which the store refused. If
// the generation has already moved, another call has logged in again since,
// and its token is returned with no login. Otherwise the refused token is
// dropped and the session logs in once. A failed login leaves no token held,
// so the next call logs in before it sends anything.
func (s *Session) relogin(ctx context.Context, gen uint64) (secret.Value, error) {
	tok, _, _, err := s.obtain(ctx, reasonRefused, func(held bool, cur uint64) bool { return held && cur != gen })
	return tok, err
}

// obtain returns the held token when usable says it may be used, and
// otherwise takes the login slot, checks again, and logs in. The wait for the
// slot ends with the caller's ctx: a caller whose ctx ends first makes no
// login and gets an ErrUnreachable carrying ctx.Err(), as a client call
// whose ctx ends does.
//
// A replaced token is dropped, not destroyed: another call may still be
// revealing it, and a Value forbids a Destroy concurrent with a Reveal.
func (s *Session) obtain(ctx context.Context, reason string, usable func(held bool, gen uint64) bool) (secret.Value, uint64, bool, error) {
	if tok, gen, ok := s.current(usable); ok {
		return tok, gen, false, nil
	}
	select {
	case s.loginSlot <- struct{}{}:
	case <-ctx.Done():
		return secret.Value{}, 0, false, s.loginError(&secretstore.Error{
			Op: "login", Mount: "auth/cert", Path: "login", Kind: secretstore.ErrUnreachable, Err: ctx.Err(),
		})
	}
	defer func() { <-s.loginSlot }()
	if tok, gen, ok := s.current(usable); ok {
		return tok, gen, false, nil
	}
	s.mu.Lock()
	s.tok, s.held = secret.Value{}, false
	s.mu.Unlock()

	tok, err := s.login.CertLogin(ctx, s.role)
	s.obs.ObserveAudited(ctx, err)
	if err != nil {
		// The client has already logged this failure.
		return secret.Value{}, 0, false, s.loginError(err)
	}
	s.mu.Lock()
	s.tok, s.held = tok, true
	s.gen++
	gen := s.gen
	s.mu.Unlock()
	s.log.LogAttrs(ctx, slog.LevelInfo, "secret store login",
		slog.String("component", "secretstore"), slog.String("event", "secretstore.login"),
		slog.String("role", s.role), slog.String("reason", reason))
	return tok, gen, true, nil
}

// current returns the held token and its generation when usable accepts them.
func (s *Session) current(usable func(held bool, gen uint64) bool) (secret.Value, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !usable(s.held, s.gen) {
		return secret.Value{}, 0, false
	}
	return s.tok, s.gen, true
}

// loginError is the error of a login that did not complete.
func (s *Session) loginError(err error) error {
	return fmt.Errorf("storesession: log in as %s: %w", s.role, err)
}
