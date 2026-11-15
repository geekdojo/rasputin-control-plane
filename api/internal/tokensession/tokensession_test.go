package tokensession

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

var errRefused = errors.New("refused")

// harness is a Holder whose logins mint tok-1, tok-2, … and record their
// reasons.
type harness struct {
	h       *Holder
	logins  atomic.Int64
	reasons []string
	fail    error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	x := &harness{}
	h, err := New(Config{
		Login: func(context.Context) (secret.Value, error) {
			n := x.logins.Add(1)
			if x.fail != nil {
				return secret.Value{}, x.fail
			}
			return secret.New(fmt.Appendf(nil, "tok-%d", n)), nil
		},
		Refused:   func(err error) bool { return errors.Is(err, errRefused) },
		WaitEnded: func(ctxErr error) error { return fmt.Errorf("wait ended: %w", ctxErr) },
		LoggedIn:  func(_ context.Context, reason string) { x.reasons = append(x.reasons, reason) },
	})
	if err != nil {
		t.Fatal(err)
	}
	x.h = h
	return x
}

// TC-978-18: the extracted rule directly: a lazy login, one re-login and one
// retry on a refused earlier token, no second login for a refused fresh
// token, no token held after a failed login, and a waiter released by its
// ctx with WaitEnded's error.
func TestCall(t *testing.T) {
	x := newHarness(t)
	refuse := map[string]bool{}
	call := func(ctx context.Context) (string, error) {
		return Call(x.h, ctx, func(tok secret.Value) (string, error) {
			s := string(tok.Reveal())
			if refuse[s] {
				return "", errRefused
			}
			return s, nil
		})
	}
	if got, err := call(t.Context()); got != "tok-1" || err != nil {
		t.Fatalf("first call = %q, %v", got, err)
	}
	refuse["tok-1"] = true
	if got, err := call(t.Context()); got != "tok-2" || err != nil {
		t.Fatalf("after a refusal = %q, %v; want the retry with tok-2", got, err)
	}
	if fmt.Sprint(x.reasons) != "[no-token refused]" {
		t.Errorf("reasons = %v", x.reasons)
	}
	refuse["tok-2"], refuse["tok-3"] = true, true
	if _, err := call(t.Context()); !errors.Is(err, errRefused) || x.logins.Load() != 3 {
		t.Errorf("a refused fresh token: %v after %d logins, want the refusal after 3", err, x.logins.Load())
	}
	x.fail = errors.New("login failed")
	refuse["tok-3"] = true
	if _, err := call(t.Context()); err == nil {
		t.Error("a failed re-login returned no error")
	}
	x.fail = nil
	if got, err := call(t.Context()); got != "tok-5" || err != nil {
		t.Errorf("after a failed login = %q, %v; want a fresh login first", got, err)
	}

	x.h.loginSlot <- struct{}{} // another call's login is in flight
	x.h.mu.Lock()
	x.h.held = false
	x.h.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := x.logins.Load()
	if _, err := call(ctx); !errors.Is(err, context.Canceled) || x.logins.Load() != before {
		t.Errorf("waiter: %v with %d new logins, want WaitEnded's error and none", err, x.logins.Load()-before)
	}
	<-x.h.loginSlot
}

// New refuses a Config with a nil function.
func TestNew_RefusesAnIncompleteConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New(Config{}) succeeded")
	}
}
