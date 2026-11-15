package idclient

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// expiredJWT is a token whose exp is in 2001: a session that read exp would
// refuse to send it.
var expiredJWT = "eyJhbGciOiJSUzI1NiJ9." +
	base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1000000000}`)) + ".sig"

// fakeLogin mints tokens: expiredJWT first, then tok-2, tok-3, … . fail, when
// set, is returned instead. block, when set, is waited on before minting.
type fakeLogin struct {
	n     atomic.Int64
	fail  atomic.Pointer[error]
	block chan struct{}
	// entered is closed when the first login starts.
	entered chan struct{}
	once    sync.Once
	gotID   atomic.Pointer[string]
	gotS    atomic.Bool
}

func (f *fakeLogin) ClientCredentials(ctx context.Context, realm, clientID string, s *secret.Value) (secret.Value, error) {
	id := realm + "/" + clientID
	f.gotID.Store(&id)
	if s != nil {
		f.gotS.Store(true)
	}
	if f.entered != nil {
		f.once.Do(func() { close(f.entered) })
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return secret.Value{}, &Error{Op: "token", Kind: ErrUnreachable, Err: ctx.Err()}
		}
	}
	if e := f.fail.Load(); e != nil {
		f.n.Add(1)
		return secret.Value{}, *e
	}
	n := f.n.Add(1)
	if n == 1 {
		return secret.New([]byte(expiredJWT)), nil
	}
	return secret.New(fmt.Appendf(nil, "tok-%d", n)), nil
}

// fakeAdmin answers each call by the token it carried: refuse holds the
// tokens it answers 401 to, and errFor any other error by token.
type fakeAdmin struct {
	mu     sync.Mutex
	calls  []string
	refuse map[string]bool
	errFor map[string]error
}

func (f *fakeAdmin) Admin(_ context.Context, tok secret.Value, _, _ string, _, _ any) (Response, error) {
	t := string(tok.Reveal())
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, t)
	if f.refuse[t] {
		return Response{}, &Error{Op: "admin", Status: 401, Kind: ErrTokenRefused}
	}
	if err := f.errFor[t]; err != nil {
		return Response{}, err
	}
	return Response{Status: http.StatusOK}, nil
}

func (f *fakeAdmin) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func newTestSession(t *testing.T, l TokenSource, a AdminCaller) (*Session, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	s, err := NewSession(SessionConfig{Login: l, Admin: a, Realm: "rasputin", ClientID: "rasputin-admin", Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return s, rec
}

func reasons(rec *logkittest.Recorder) []string {
	var out []string
	for _, r := range rec.Matching(slog.LevelInfo, "identity service login") {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "reason" {
				out = append(out, a.Value.String())
			}
			return true
		})
	}
	return out
}

// TC-978-15: the first call logs in (reason no-token) by client-x509 as
// rasputin-admin; a token whose exp has passed is still sent; when a later
// call's token gets 401 the session logs in exactly once more (reason
// refused), retries exactly once and returns the retry's result.
func TestSession_ReLogsInOnceOnRefusal(t *testing.T) {
	l := &fakeLogin{}
	a := &fakeAdmin{refuse: map[string]bool{}}
	s, rec := newTestSession(t, l, a)
	if _, err := s.Admin(t.Context(), http.MethodGet, adminRead, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Admin(t.Context(), http.MethodGet, adminRead, nil, nil); err != nil {
		t.Fatal(err)
	}
	if l.n.Load() != 1 {
		t.Fatalf("logins = %d after two calls with an expired-exp token, want 1 (exp is never read)", l.n.Load())
	}
	if *l.gotID.Load() != "rasputin/rasputin-admin" || l.gotS.Load() {
		t.Errorf("login as %s with a secret %v, want rasputin/rasputin-admin by client-x509", *l.gotID.Load(), l.gotS.Load())
	}
	a.mu.Lock()
	a.refuse[expiredJWT] = true
	a.mu.Unlock()
	resp, err := s.Admin(t.Context(), http.MethodGet, adminRead, nil, nil)
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("after a refusal: %v, %v; want the retry's 200", resp, err)
	}
	if got := a.got(); len(got) != 4 || got[2] != expiredJWT || got[3] != "tok-2" {
		t.Errorf("Admin calls = %v, want two with the first token, its refusal, and one retry with tok-2", got)
	}
	if l.n.Load() != 2 {
		t.Errorf("logins = %d, want 2", l.n.Load())
	}
	if r := reasons(rec); len(r) != 2 || r[0] != "no-token" || r[1] != "refused" {
		t.Errorf("login reasons = %v, want [no-token refused]", r)
	}
}

// TC-978-16: a 401 on the token this same call obtained is returned with no
// second login; a failed login holds no token, so the next call logs in
// first; 403, 404, 409 and ErrUnreachable keep the token with no login.
func TestSession_KeepsOrDropsTheToken(t *testing.T) {
	t.Run("refused fresh token", func(t *testing.T) {
		l := &fakeLogin{}
		a := &fakeAdmin{refuse: map[string]bool{expiredJWT: true}}
		s, _ := newTestSession(t, l, a)
		if _, err := s.Admin(t.Context(), http.MethodGet, adminRead, nil, nil); !errors.Is(err, ErrTokenRefused) {
			t.Errorf("err = %v, want ErrTokenRefused", err)
		}
		if l.n.Load() != 1 {
			t.Errorf("logins = %d, want 1", l.n.Load())
		}
	})
	t.Run("failed login holds nothing", func(t *testing.T) {
		l := &fakeLogin{}
		denied := error(&Error{Op: "token", Status: 401, Kind: ErrDenied})
		l.fail.Store(&denied)
		a := &fakeAdmin{}
		s, _ := newTestSession(t, l, a)
		if _, err := s.Admin(t.Context(), http.MethodGet, adminRead, nil, nil); !errors.Is(err, ErrDenied) {
			t.Fatalf("err = %v, want ErrDenied", err)
		}
		l.fail.Store(nil)
		if _, err := s.Admin(t.Context(), http.MethodGet, adminRead, nil, nil); err != nil {
			t.Fatal(err)
		}
		if l.n.Load() != 2 || len(a.got()) != 1 {
			t.Errorf("logins %d, Admin calls %d; want 2 and 1 (nothing sent without a token)", l.n.Load(), len(a.got()))
		}
	})
	for _, kind := range []error{ErrForbidden, ErrNotFound, ErrConflict, ErrUnreachable} {
		t.Run(kindName(kind), func(t *testing.T) {
			l := &fakeLogin{}
			a := &fakeAdmin{errFor: map[string]error{expiredJWT: &Error{Op: "admin", Kind: kind}}}
			s, _ := newTestSession(t, l, a)
			for range 2 {
				if _, err := s.Admin(t.Context(), http.MethodGet, adminRead, nil, nil); !errors.Is(err, kind) {
					t.Fatalf("err = %v, want %v", err, kind)
				}
			}
			if l.n.Load() != 1 {
				t.Errorf("logins = %d, want 1: the token is kept", l.n.Load())
			}
		})
	}
}

// TC-978-17: N concurrent calls that each get 401 on the same held token make
// exactly one login and all retry with the new token; a caller waiting for
// the login slot whose ctx ends gets ErrUnreachable matching its ctx error
// and makes no login.
func TestSession_Concurrency(t *testing.T) {
	l := &fakeLogin{}
	a := &fakeAdmin{refuse: map[string]bool{}}
	s, _ := newTestSession(t, l, a)
	if _, err := s.Admin(t.Context(), http.MethodGet, adminRead, nil, nil); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.refuse[expiredJWT] = true
	a.mu.Unlock()
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			_, err := s.Admin(t.Context(), http.MethodGet, adminRead, nil, nil)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a concurrent call failed: %v", err)
		}
	}
	if l.n.Load() != 2 {
		t.Errorf("logins = %d, want 2 (one at the start, one for all %d refusals)", l.n.Load(), n)
	}

	t.Run("waiter released by its ctx", func(t *testing.T) {
		bl := &fakeLogin{block: make(chan struct{}), entered: make(chan struct{})}
		s, _ := newTestSession(t, bl, &fakeAdmin{})
		first := make(chan error, 1)
		go func() {
			_, err := s.Admin(t.Context(), http.MethodGet, adminRead, nil, nil)
			first <- err
		}()
		// The first call holds the login slot once its login has started.
		<-bl.entered
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := s.Admin(ctx, http.MethodGet, adminRead, nil, nil)
		if !errors.Is(err, ErrUnreachable) || !errors.Is(err, context.Canceled) {
			t.Errorf("waiter err = %v, want ErrUnreachable matching context.Canceled", err)
		}
		close(bl.block)
		if err := <-first; err != nil {
			t.Errorf("the first call: %v", err)
		}
		if bl.n.Load() != 1 {
			t.Errorf("logins = %d, want 1: the released waiter made none", bl.n.Load())
		}
	})
}

// NewSession refuses an incomplete config.
func TestNewSession_RefusesAnIncompleteConfig(t *testing.T) {
	l, a, log := &fakeLogin{}, &fakeAdmin{}, slog.New(slog.DiscardHandler)
	for name, cfg := range map[string]SessionConfig{
		"no login":  {Admin: a, Realm: "r", ClientID: "c", Log: log},
		"no admin":  {Login: l, Realm: "r", ClientID: "c", Log: log},
		"no realm":  {Login: l, Admin: a, ClientID: "c", Log: log},
		"no client": {Login: l, Admin: a, Realm: "r", Log: log},
		"no log":    {Login: l, Admin: a, Realm: "r", ClientID: "c"},
	} {
		if _, err := NewSession(cfg); err == nil {
			t.Errorf("%s: NewSession accepted it", name)
		}
	}
}

// fakeReadier answers not ready until its nth call.
type fakeReadier struct {
	n, readyAt int
	gotWait    bool
}

func (f *fakeReadier) Ready(ctx context.Context) error {
	f.n++
	f.gotWait = f.gotWait || inWait(ctx)
	if f.readyAt > 0 && f.n >= f.readyAt {
		return nil
	}
	return &Error{Op: "ready", Status: 503, Kind: ErrUnreachable}
}

// WaitReady ends on ready, on the unit no longer active, on an unreadable
// unit state, and on the caller's ctx.
func TestWaitReady(t *testing.T) {
	active := func(context.Context) (bool, error) { return true, nil }
	r := &fakeReadier{readyAt: 2}
	if err := WaitReady(t.Context(), r, active); err != nil || r.n != 2 || !r.gotWait {
		t.Errorf("ready on the second answer: err %v after %d answers (in wait %v)", err, r.n, r.gotWait)
	}
	if err := WaitReady(t.Context(), &fakeReadier{}, func(context.Context) (bool, error) { return false, nil }); !errors.Is(err, errNotActive) || !errors.Is(err, ErrUnreachable) {
		t.Errorf("inactive unit: err = %v, want errNotActive carrying the last answer", err)
	}
	boom := errors.New("systemctl failed")
	if err := WaitReady(t.Context(), &fakeReadier{}, func(context.Context) (bool, error) { return false, boom }); !errors.Is(err, boom) {
		t.Errorf("unreadable unit: err = %v, want the read error", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := WaitReady(ctx, &fakeReadier{}, active); !errors.Is(err, context.Canceled) {
		t.Errorf("ended ctx: err = %v, want context.Canceled", err)
	}
}
