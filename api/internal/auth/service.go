package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

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

	mu      sync.Mutex
	pending map[string]*pendingAuth // keyed by random pending-token

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type pendingAuth struct {
	kind    string // "register" or "login"
	user    *User
	session *webauthn.SessionData
	expires time.Time
}

const (
	sessionCookie   = "rasputin-session"
	pendingCookie   = "rasputin-pending"
	sessionLifetime = 7 * 24 * time.Hour
	pendingLifetime = 5 * time.Minute
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
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: webauthn config: %w", err)
	}
	return &Service{
		store:   store,
		web:     w,
		cfg:     cfg,
		pending: make(map[string]*pendingAuth),
	}, nil
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
	p.expires = time.Now().Add(pendingLifetime)
	s.mu.Lock()
	s.pending[token] = p
	s.mu.Unlock()
	return token, nil
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
// session cookie is present.
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
