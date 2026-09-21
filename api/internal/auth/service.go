package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config drives the WebAuthn relying-party setup and cookie behavior.
type Config struct {
	RPDisplayName string   // "Rasputin"
	RPID          string   // effective domain — "localhost" in dev
	RPOrigins     []string // allowed browser origins
	CookieDomain  string   // optional explicit cookie domain
	SecureCookies bool     // set Secure flag on cookies (production HTTPS)
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

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// LoginHook runs after a successful login or first-credential registration,
// before the session cookie is written. The hook receives the authenticated
// User and a request-scoped context. It is invoked synchronously so callers
// that depend on side-effects (e.g. mesh.EnsureUser provisioning a Headscale
// user) can rely on the side-effect having occurred when /api/auth/me
// returns. Errors are logged but never block the login response — auth
// remains usable when downstream subsystems are unhealthy.
//
// auth does not import mesh; the wiring lives in cmd/main, which is where
// both subsystems already meet.
type LoginHook func(ctx context.Context, user *User) error

type pendingAuth struct {
	kind    string // "register" or "login"
	user    *User
	session *webauthn.SessionData
	expires time.Time
	// basis records what authorized a registration ceremony at begin, so
	// finish re-checks that same fact rather than trusting that it still
	// holds. Unset for login.
	basis registerBasis
	// stepUp is the assertion challenge a signed-in registration must
	// answer with one of the user's existing passkeys. It is bound to this
	// ceremony and spent by the first register/step-up call (nil after).
	stepUp *webauthn.SessionData
	// stepUpVerified is set when that assertion verified; register/finish
	// refuses a signed-in registration without it.
	stepUpVerified bool
	// authenticator is the kind of authenticator the operator picked at
	// register/begin. A signed-in ceremony does not mint its creation
	// options until register/step-up, so the choice has to survive the gap;
	// it is an option on the new credential, not an authorization fact,
	// which is why it sits here and not in basis.
	authenticator authenticatorChoice
}

// registerBasis is the fact a registration ceremony was begun on.
type registerBasis struct {
	// firstRun: no operator existed at begin. Finish commits only if that
	// is still true (Store.CreateFirstUser's conditional insert).
	firstRun bool
	// byUserID: the ID of the signed-in user who began the ceremony, whose
	// own account the new passkey is added to. Finish requires a verified
	// step-up and a live session for that same user.
	byUserID []byte
}

const (
	sessionCookie   = "rasputin-session"
	pendingCookie   = "rasputin-pending"
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
		store:   store,
		web:     w,
		cfg:     cfg,
		origins: origins,
		pending: make(map[string]*pendingAuth),
	}, nil
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

// runLoginHook invokes the installed hook with a request-scoped context.
// Errors are logged at the auth boundary so handlers don't have to think
// about it. No-op when no hook is installed.
func (s *Service) runLoginHook(ctx context.Context, u *User) {
	s.hookMu.RLock()
	hook := s.loginHook
	s.hookMu.RUnlock()
	if hook == nil {
		return
	}
	if err := hook(ctx, u); err != nil {
		log.Printf("auth: login hook for %q: %v (login proceeds)", u.Name, err)
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
			s.cleanupPending(now)
			_ = s.store.DeleteExpiredSessions(s.ctx, now.UTC())
		}
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

// takeStepUp spends the step-up challenge of the ceremony under token and
// returns it with the ceremony. The challenge is removed before it is
// verified, so it can be answered at most once. Returns nil if there is no
// live registration awaiting a step-up.
func (s *Service) takeStepUp(token string) (*pendingAuth, *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[token]
	if !ok || p.kind != "register" || p.stepUp == nil {
		return nil, nil
	}
	if time.Now().After(p.expires) {
		delete(s.pending, token)
		return nil, nil
	}
	challenge := p.stepUp
	p.stepUp = nil
	return p, challenge
}

// completeStepUp records a verified step-up and the creation challenge it
// unlocked, if the ceremony is still the one under token (not finished,
// dropped or evicted meanwhile).
func (s *Service) completeStepUp(token string, p *pendingAuth, target *User, creation *webauthn.SessionData) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.pending[token]; !ok || cur != p {
		return false
	}
	p.user = target
	p.session = creation
	p.stepUpVerified = true
	return true
}

func (s *Service) dropPending(token string) {
	s.mu.Lock()
	delete(s.pending, token)
	s.mu.Unlock()
}

// ----- cookies ------------------------------------------------------------

func (s *Service) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) setPendingCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     pendingCookie,
		Value:    token,
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		MaxAge:   int(pendingLifetime.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) clearPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     pendingCookie,
		Value:    "",
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// ----- session resolve / context ------------------------------------------

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxSession
)

// UserFromContext returns the authenticated User attached by RequireSession.
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(ctxUser).(*User)
	return u, ok
}

// WithUser returns a derived context carrying user as if RequireSession
// had been called. Intended for tests that need to drive a handler
// directly without going through the cookie middleware — production
// code MUST go through RequireSession instead.
func WithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, ctxUser, user)
}

func (s *Service) resolveSession(r *http.Request) (*Session, *User, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, nil, nil
	}
	sess, err := s.store.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, nil, err
	}
	if sess == nil {
		return nil, nil, nil
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		_ = s.store.DeleteSession(r.Context(), sess.Token)
		return nil, nil, nil
	}
	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, nil, nil
	}
	return sess, user, nil
}

// RequireSession wraps an http.Handler so it returns 401 unless a valid
// session cookie is present, and 403 when the request carries an Origin that
// is not on the allowlist.
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
		sess, user, err := s.resolveSession(r)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if sess == nil || user == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"auth required"}`))
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, user)
		ctx = context.WithValue(ctx, ctxSession, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
		// touch session async; best-effort
		go func(token string) {
			bg, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.store.TouchSession(bg, token, time.Now().UTC())
		}(sess.Token)
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

func (s *Service) createSession(ctx context.Context, userID []byte) (*Session, error) {
	token, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &Session{
		Token:        token,
		UserID:       userID,
		CreatedAt:    now,
		ExpiresAt:    now.Add(sessionLifetime),
		LastActiveAt: now,
	}
	if err := s.store.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	return sess, nil
}

// StripCookies removes the api's own cookies — the session and the pending
// WebAuthn ceremony — from the Cookie header of a request about to be
// forwarded to another service (the Grafana proxy). The other service has no
// use for them, and a credential it never sees is one it cannot log, store or
// leak. Every other cookie is kept, so the upstream's own cookies still work.
func StripCookies(h http.Header) {
	if len(h.Values("Cookie")) == 0 {
		return
	}
	kept := make([]string, 0)
	for _, c := range (&http.Request{Header: h}).Cookies() {
		if c.Name == sessionCookie || c.Name == pendingCookie {
			continue
		}
		kept = append(kept, c.String())
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}
