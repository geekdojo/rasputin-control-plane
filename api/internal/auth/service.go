package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/secret"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config drives the WebAuthn relying-party setup of the pre-update passkey
// ceremony and names the console's session store. Every console cookie is a
// __Host- cookie (cookies.go), so no setting governs its Secure flag or
// domain (geekdojo/geekdojo-brain#989 retired RASPUTIN_SECURE_COOKIES).
type Config struct {
	RPDisplayName string   // "Rasputin"
	RPID          string   // effective domain — "localhost" in dev
	RPOrigins     []string // allowed browser origins
	// Sessions is the console session store. Without one no request
	// resolves to a person: every gated route answers 401.
	Sessions *ConsoleSessions
}

// Service is the auth layer: WebAuthn server + session manager + middleware.
type Service struct {
	store *Store
	web   *webauthn.WebAuthn
	cfg   Config
	// origins is cfg.RPOrigins normalized: the one browser-origin allowlist
	// (see OriginAllowlist).
	origins *OriginAllowlist

	mu      sync.Mutex
	pending map[string]*pendingAuth // keyed by random pending-token

	hookMu    sync.RWMutex
	loginHook LoginHook
	// adminHook runs after a sign-in that minted a session holding admin
	// (SetAdminSignInHook).
	adminHook func(ctx context.Context)

	// control is the control lock's gate (controllock.go).
	control controlGate

	// sessions is the console session store (Config.Sessions).
	sessions *ConsoleSessions
	// signIn is the console's sign-in, installed by SetSignIn only when the
	// identity service and the doors are on; nil means sign-in is
	// unavailable.
	signInMu sync.RWMutex
	signIn   *SignIn

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// LoginHook runs after a successful console sign-in, before the session
// cookie is written, with the account's preferred_username. It is invoked
// synchronously so callers that depend on its side effects (mesh.EnsureUser
// provisioning a Headscale user) can rely on them having happened when
// /api/auth/me returns. Its error is logged and never blocks the sign-in:
// auth stays usable when downstream subsystems are unhealthy.
//
// auth does not import mesh; the wiring lives in cmd/main, which is where
// both subsystems already meet.
type LoginHook func(ctx context.Context, name string) error

type pendingAuth struct {
	kind    string // "register"
	user    *User
	session *webauthn.SessionData
	expires time.Time
}

const (
	// sessionLifetime bounds a console session (register rows E3 and C72)
	// and a legacy one.
	sessionLifetime = 7 * 24 * time.Hour
	// pendingLifetime bounds an unfinished WebAuthn ceremony. A ceremony is
	// consumed at finish, but one the browser abandons produces no fact the
	// api could observe, so this bound is what frees its memory and ends its
	// authority. It is a safety net, not a state transition (principles.md's
	// clock rule; exception register row E5).
	pendingLifetime = 5 * time.Minute
	// maxPending caps the in-memory ceremony map. login/begin is
	// unauthenticated, so without a cap the map grows with every request
	// until the janitor catches up. At the cap, expired entries are pruned
	// first, then the entry closest to expiry is evicted.
	maxPending = 1024
)

// SessionLifetime is sessionLifetime for the sessions other packages bound
// the same way: the break-glass repair session takes the console session's
// seven days (register row C72, D22; geekdojo/geekdojo-brain#321). The
// unexported name stays the one register row E3 and timer-audit L01 cite.
const SessionLifetime = sessionLifetime

// NewService constructs an auth Service. The store must be opened separately
// (see OpenStore).
func NewService(store *Store, cfg Config) (*Service, error) {
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "Rasputin"
	}
	if cfg.RPID == "" {
		cfg.RPID = "localhost"
	}
	if len(cfg.RPOrigins) == 0 {
		cfg.RPOrigins = []string{"http://localhost:3000"}
	}
	origins, err := NewOriginAllowlist(cfg.RPOrigins)
	if err != nil {
		return nil, fmt.Errorf("auth: RP origins: %w", err)
	}
	cfg.RPOrigins = origins.Origins()
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
		// Passkeys require user verification (Face ID, Touch ID, Windows
		// Hello, PIN) at registration, sign-in and step-up alike
		// (geekdojo-brain decision #561). One setting drives all three: the
		// library asks for UV and refuses a response without the UV flag.
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired},
	})
	if err != nil {
		return nil, fmt.Errorf("auth: webauthn config: %w", err)
	}
	return &Service{
		store:    store,
		web:      w,
		cfg:      cfg,
		origins:  origins,
		pending:  make(map[string]*pendingAuth),
		sessions: cfg.Sessions,
	}, nil
}

// SetSignIn installs the console's sign-in. The composition root builds it
// only when the identity service is keycloak and the doors are on; until it
// is installed, /api/auth/signin answers unavailable and status says
// ready:false. Safe to call before or after Start.
func (s *Service) SetSignIn(si *SignIn) {
	s.signInMu.Lock()
	defer s.signInMu.Unlock()
	s.signIn = si
}

// signin is the installed sign-in, or nil.
func (s *Service) signin() *SignIn {
	s.signInMu.RLock()
	defer s.signInMu.RUnlock()
	return s.signIn
}

// Origins returns the browser-origin allowlist every origin decision in the
// api reads: CORS, cross-origin protection, the WebSocket upgrade and
// RequireSession.
func (s *Service) Origins() *OriginAllowlist { return s.origins }

// SetLoginHook installs (or replaces) the post-login hook. Safe to call
// before or after Start; concurrent with Service operation. Pass nil to
// uninstall.
func (s *Service) SetLoginHook(h LoginHook) {
	s.hookMu.Lock()
	s.loginHook = h
	s.hookMu.Unlock()
}

// SetAdminSignInHook installs (or replaces) the hook that runs after a
// console sign-in mints a session holding the admin role: an administrator's
// normal sign-in, the fact that ends a break-glass repair session and
// retires its outstanding code (geekdojo/geekdojo-brain#321). It is called
// synchronously before the session cookie is written and returns nothing:
// the hook's own owner logs what it did. Pass nil to uninstall.
func (s *Service) SetAdminSignInHook(h func(ctx context.Context)) {
	s.hookMu.Lock()
	s.adminHook = h
	s.hookMu.Unlock()
}

// runAdminSignInHook invokes the installed admin sign-in hook, if any.
func (s *Service) runAdminSignInHook(ctx context.Context) {
	s.hookMu.RLock()
	hook := s.adminHook
	s.hookMu.RUnlock()
	if hook != nil {
		hook(ctx)
	}
}

// runLoginHook invokes the installed hook with a request-scoped context.
// Its error is logged at the auth boundary so handlers don't have to think
// about it. No-op when no hook is installed.
func (s *Service) runLoginHook(ctx context.Context, name string) {
	s.hookMu.RLock()
	hook := s.loginHook
	s.hookMu.RUnlock()
	if hook == nil {
		return
	}
	if err := hook(ctx, name); err != nil {
		if si := s.signin(); si != nil {
			si.log.LogAttrs(ctx, slog.LevelWarn, "The sign-in's follow-up step failed; the sign-in proceeds.",
				slog.String("event", "signin.hook_failed"), slog.String("err", err.Error()))
		}
	}
}

// Start launches the janitor that prunes expired pending-auth entries and
// expired sessions.
func (s *Service) Start(ctx context.Context) {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(1)
	go s.janitor()
}

// Stop terminates the janitor.
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *Service) janitor() {
	defer s.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			s.sweep(s.ctx, now)
		}
	}
}

// sweep is one janitor pass: expired pre-update ceremonies and legacy
// session rows (so #745's plaintext rows are gone within sessionLifetime,
// and nothing writes new ones), expired console sessions and expired
// pending sign-ins. Each is a tidy-up of state its own reader already
// refuses once expired, so a failed delete changes no decision.
func (s *Service) sweep(ctx context.Context, now time.Time) {
	s.cleanupPending(now)
	_ = s.store.DeleteExpiredSessions(ctx, now.UTC())
	if s.sessions != nil {
		_ = s.sessions.DeleteExpired(ctx)
	}
	if si := s.signin(); si != nil {
		si.prune()
	}
}

func (s *Service) cleanupPending(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, p := range s.pending {
		if now.After(p.expires) {
			delete(s.pending, token)
		}
	}
}

// ----- first run ------------------------------------------------------------

// FirstRun reports whether the installation is at first run: no operator has
// registered yet. It is the one predicate every first-run surface reads
// (register/begin, auth/status, the restore routes, the setup probe), and it
// fails closed: an error returns (false, err), never "first run".
func (s *Service) FirstRun(ctx context.Context) (bool, error) {
	return s.store.FirstRun(ctx)
}

// ----- pending-auth state -------------------------------------------------

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Service) storePending(p *pendingAuth) (string, error) {
	token, err := randomToken(16)
	if err != nil {
		return "", err
	}
	now := time.Now()
	p.expires = now.Add(pendingLifetime)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) >= maxPending {
		s.evictPendingLocked(now)
	}
	s.pending[token] = p
	return token, nil
}

// evictPendingLocked makes room for one entry: it drops every expired entry,
// and if none had expired, the one closest to expiry. Caller holds s.mu.
func (s *Service) evictPendingLocked(now time.Time) {
	var (
		oldest    string
		oldestExp time.Time
		pruned    bool
	)
	for token, p := range s.pending {
		if now.After(p.expires) {
			delete(s.pending, token)
			pruned = true
			continue
		}
		if oldest == "" || p.expires.Before(oldestExp) {
			oldest, oldestExp = token, p.expires
		}
	}
	if !pruned && oldest != "" {
		delete(s.pending, oldest)
	}
}

func (s *Service) takePending(token string) *pendingAuth {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[token]
	if !ok {
		return nil
	}
	delete(s.pending, token)
	if time.Now().After(p.expires) {
		return nil
	}
	return p
}

// ----- cookies ------------------------------------------------------------

// setCeremonyCookie names a pre-update passkey ceremony in flight.
func (s *Service) setCeremonyCookie(w http.ResponseWriter, token string) {
	setCookie(w, ceremonyCookieName, token, pendingLifetime)
}

func (s *Service) clearCeremonyCookie(w http.ResponseWriter) { clearCookie(w, ceremonyCookieName) }

// setSessionCookie writes the console session's cookie.
func setSessionCookie(w http.ResponseWriter, cookie secret.Value) {
	setCookie(w, SessionCookieName, string(cookie.Reveal()), sessionLifetime)
}

// ----- session resolve / context ------------------------------------------

// sessionOutcome is what resolve found on a request.
type sessionOutcome int

const (
	sessionNone sessionOutcome = iota
	sessionFound
	sessionDuplicate
)

// resolve reads the request's console session cookie and resolves it. A
// legacy rasputin-session cookie is never read: the legacy sessions table no
// longer authenticates anything (geekdojo/geekdojo-brain#989).
func (s *Service) resolve(r *http.Request) (Principal, secret.Value, sessionOutcome, error) {
	c, err := oneCookie(r, SessionCookieName)
	switch {
	case errors.Is(err, errDuplicateCookie):
		return Principal{}, secret.Value{}, sessionDuplicate, nil
	case err != nil, s.sessions == nil:
		return Principal{}, secret.Value{}, sessionNone, nil
	}
	cookie := secret.New([]byte(c.Value))
	p, ok, err := s.sessions.Resolve(r.Context(), cookie)
	if err != nil || !ok {
		cookie.Destroy()
		return Principal{}, secret.Value{}, sessionNone, err
	}
	return p, cookie, sessionFound, nil
}

// RequireSession wraps an http.Handler so it answers 403 when the request
// carries an Origin that is not on the allowlist, 400 when it carries the
// session cookie twice, 401 unless it carries a live console session, and
// 423 when it uses a control capability while the control lock's gate
// refuses (controllock.go). Otherwise the handler runs with the Principal in
// its context, and the session is touched.
//
// The Origin check covers what the other layers do not: WebSocket upgrades
// are GETs, which http.CrossOriginProtection lets through, and the WebSocket
// library matches an Origin by host alone when it equals the request's Host.
// This check compares the whole origin, scheme included, on every gated
// request, before the session is looked up.
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.origins.requestOriginAllowed(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"origin not allowed"}`))
			return
		}
		p, cookie, outcome, err := s.resolve(r)
		switch {
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		case outcome == sessionDuplicate:
			writeDuplicateCookie(w, SessionCookieName)
			return
		case outcome != sessionFound:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"auth required"}`))
			return
		}
		defer cookie.Destroy()
		if s.controlLocked(w, r) {
			return
		}
		_ = s.sessions.Touch(r.Context(), cookie) // last-active is display only; a failed write changes no decision
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// RequireSessionFunc is the http.HandlerFunc-flavored variant.
func (s *Service) RequireSessionFunc(next http.HandlerFunc) http.HandlerFunc {
	wrapped := s.RequireSession(next)
	return wrapped.ServeHTTP
}

// ----- helpers ------------------------------------------------------------

// makeUser creates a User with a fresh 16-byte WebAuthn handle.
func makeUser(name, displayName string) (*User, error) {
	if displayName == "" {
		displayName = name
	}
	if !validUserName(name) {
		return nil, errors.New("invalid user name")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &User{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

func validUserName(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return !strings.HasPrefix(s, "-") && !strings.HasPrefix(s, ".")
}

// ownCookiePrefix starts the name of every cookie the api sets, once an
// optional __Host- or __Secure- prefix is removed (signin-origin.md §5.3).
const ownCookiePrefix = "rasputin-"

// IsOwnCookie reports whether name is one of the api's own cookies: with an
// optional __Host- or __Secure- prefix removed, it starts with rasputin-
// (the session, the pending ceremony, the repair session and any later
// one). The sign-in doors strip these both ways, and StripCookies drops
// them before a request is forwarded (geekdojo/geekdojo-brain#985).
func IsOwnCookie(name string) bool {
	if rest, ok := strings.CutPrefix(name, "__Host-"); ok {
		name = rest
	} else if rest, ok := strings.CutPrefix(name, "__Secure-"); ok {
		name = rest
	}
	return strings.HasPrefix(name, ownCookiePrefix)
}

// StripCookies removes the api's own cookies (IsOwnCookie) from the Cookie
// header of a request about to be forwarded to another service (the Grafana
// proxy). The other service has no use for them, and a credential it never
// sees is one it cannot log, store or leak. Every other cookie is kept, so
// the upstream's own cookies still work.
func StripCookies(h http.Header) {
	if len(h.Values("Cookie")) == 0 {
		return
	}
	kept := make([]string, 0)
	for _, c := range (&http.Request{Header: h}).Cookies() {
		if IsOwnCookie(c.Name) {
			continue
		}
		kept = append(kept, c.String())
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}
