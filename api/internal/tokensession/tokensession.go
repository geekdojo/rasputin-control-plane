// Package tokensession is the one login-and-retry rule the api's token
// sessions share: a token held in memory only and got lazily, and one
// re-login and one retry when the service refuses a token an earlier call
// obtained. The secret store's session (storesession,
// geekdojo/geekdojo-brain#759) was its first user and the identity service's
// (#978) its second; each gives its own login, refusal test and records.
//
// It reads no clock and no token lifetime, and starts no timer: the service's
// refusal is the only fact that makes it log in again (ARCH-FACTS).
package tokensession

import (
	"context"
	"errors"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The reasons a login is made, which LoggedIn is given.
const (
	ReasonNoToken = "no-token"
	ReasonRefused = "refused"
)

// Config is everything a Holder needs. New refuses an incomplete one.
type Config struct {
	// Login makes one login and returns its token. Its error is returned to
	// the caller as it is, so it carries the session's own context.
	Login func(ctx context.Context) (secret.Value, error)
	// Refused reports whether a call's error is the service refusing the
	// token it carried.
	Refused func(error) bool
	// WaitEnded is the error a caller gets when its ctx ends while it waits
	// for another call's login; it is given ctx.Err().
	WaitEnded func(ctxErr error) error
	// LoggedIn is told of each successful login and its reason.
	LoggedIn func(ctx context.Context, reason string)
}

// Holder is a lazily obtained token. It is safe for concurrent use.
type Holder struct {
	cfg Config

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

// New checks cfg and returns a Holder holding no token. It does no I/O.
func New(cfg Config) (*Holder, error) {
	if cfg.Login == nil || cfg.Refused == nil || cfg.WaitEnded == nil || cfg.LoggedIn == nil {
		return nil, errors.New("tokensession: a Config function is nil")
	}
	return &Holder{cfg: cfg, loginSlot: make(chan struct{}, 1)}, nil
}

// Call is the one retry rule. It runs f with the held token, logging in first
// when none is held. A refusal of a token an earlier call obtained gets one
// re-login and one retry; a refusal of the token this call minted, and every
// other outcome, is returned as it is.
func Call[T any](h *Holder, ctx context.Context, f func(tok secret.Value) (T, error)) (T, error) {
	var zero T
	tok, gen, minted, err := h.obtain(ctx, ReasonNoToken, func(held bool, _ uint64) bool { return held })
	if err != nil {
		return zero, err
	}
	v, err := f(tok)
	if err == nil || minted || !h.cfg.Refused(err) {
		return v, err
	}
	// The refused token is replaced unless the generation has already moved,
	// in which case another call has logged in again since and its token is
	// used with no login. A failed login leaves no token held, so the next
	// call logs in before it sends anything.
	tok, _, _, err = h.obtain(ctx, ReasonRefused, func(held bool, cur uint64) bool { return held && cur != gen })
	if err != nil {
		return zero, err
	}
	return f(tok)
}

// obtain returns the held token when usable says it may be used, and
// otherwise takes the login slot, checks again, and logs in. The wait for the
// slot ends with the caller's ctx: a caller whose ctx ends first makes no
// login and gets WaitEnded's error.
//
// A replaced token is dropped, not destroyed: another call may still be
// revealing it, and a Value forbids a Destroy concurrent with a Reveal.
func (h *Holder) obtain(ctx context.Context, reason string, usable func(held bool, gen uint64) bool) (secret.Value, uint64, bool, error) {
	if tok, gen, ok := h.current(usable); ok {
		return tok, gen, false, nil
	}
	select {
	case h.loginSlot <- struct{}{}:
	case <-ctx.Done():
		return secret.Value{}, 0, false, h.cfg.WaitEnded(ctx.Err())
	}
	defer func() { <-h.loginSlot }()
	if tok, gen, ok := h.current(usable); ok {
		return tok, gen, false, nil
	}
	h.mu.Lock()
	h.tok, h.held = secret.Value{}, false
	h.mu.Unlock()

	tok, err := h.cfg.Login(ctx)
	if err != nil {
		return secret.Value{}, 0, false, err
	}
	h.mu.Lock()
	h.tok, h.held = tok, true
	h.gen++
	gen := h.gen
	h.mu.Unlock()
	h.cfg.LoggedIn(ctx, reason)
	return tok, gen, true, nil
}

// current returns the held token and its generation when usable accepts them.
func (h *Holder) current(usable func(held bool, gen uint64) bool) (secret.Value, uint64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !usable(h.held, h.gen) {
		return secret.Value{}, 0, false
	}
	return h.tok, h.gen, true
}
