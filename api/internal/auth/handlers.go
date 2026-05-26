package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// RegisterRoutes installs auth-related routes onto mux. Path-prefixed with
// /api/auth/ so the api.Server can mount them at the right place.
func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/status", s.handleStatus)
	mux.HandleFunc("GET /api/auth/me", s.handleMe)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("POST /api/auth/register/begin", s.handleRegisterBegin)
	mux.HandleFunc("POST /api/auth/register/finish", s.handleRegisterFinish)
	mux.HandleFunc("POST /api/auth/login/begin", s.handleLoginBegin)
	mux.HandleFunc("POST /api/auth/login/finish", s.handleLoginFinish)
}

// ----- status / me / logout -----------------------------------------------

// GET /api/auth/status — open. Reports whether any users exist (drives the
// first-run flow) and the current user if logged in.
func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{"hasUsers": n > 0, "userCount": n}
	if _, user, _ := s.resolveSession(r); user != nil {
		resp["user"] = publicUser(user)
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/auth/me — open, but returns 401 if not authenticated.
func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	_, user, err := s.resolveSession(r)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user == nil {
		writeErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	writeJSON(w, http.StatusOK, publicUser(user))
}

// POST /api/auth/logout — invalidates the current session.
func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = s.store.DeleteSession(r.Context(), cookie.Value)
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ----- registration -------------------------------------------------------

// POST /api/auth/register/begin
// Body: { "name": "alice", "displayName": "Alice" }
// Allowed when:
//   - No users exist yet (first-run), OR
//   - The caller is authenticated (an existing user is creating a new one).
func (s *Service) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}

	n, err := s.store.CountUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n > 0 {
		if _, user, _ := s.resolveSession(r); user == nil {
			writeErr(w, http.StatusUnauthorized,
				"only an authenticated user can register a new user")
			return
		}
	}

	existing, err := s.store.GetUserByName(r.Context(), req.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing != nil {
		writeErr(w, http.StatusConflict, "user with that name already exists")
		return
	}

	user, err := makeUser(req.Name, req.DisplayName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	options, sessionData, err := s.web.BeginRegistration(user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	token, err := s.storePending(&pendingAuth{
		kind:    "register",
		user:    user,
		session: sessionData,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.setPendingCookie(w, token)
	writeJSON(w, http.StatusOK, options)
}

// POST /api/auth/register/finish
// Body: the PublicKeyCredential attestation response from the browser.
func (s *Service) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(pendingCookie)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing pending cookie")
		return
	}
	p := s.takePending(cookie.Value)
	s.clearPendingCookie(w)
	if p == nil || p.kind != "register" || p.user == nil {
		writeErr(w, http.StatusBadRequest, "no pending registration")
		return
	}

	cred, err := s.web.FinishRegistration(p.user, *p.session, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Persist user + credential atomically-ish (no transactions across our
	// thin wrappers; create user first, then credential. If credential save
	// fails the user lingers — accept this for v0).
	if err := s.store.CreateUser(r.Context(), p.user); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	dbCred := fromWebAuthn(cred, p.user.ID)
	dbCred.CreatedAt = time.Now().UTC()
	if err := s.store.CreateCredential(r.Context(), dbCred); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess, err := s.createSession(r.Context(), p.user.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.UpdateLastLogin(r.Context(), p.user.ID, sess.CreatedAt)
	s.setSessionCookie(w, sess.Token, sess.ExpiresAt)
	writeJSON(w, http.StatusOK, publicUser(p.user))
}

// ----- login (discoverable / usernameless) --------------------------------

// POST /api/auth/login/begin — open, returns CredentialAssertion options.
func (s *Service) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	options, sessionData, err := s.web.BeginDiscoverableLogin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, err := s.storePending(&pendingAuth{
		kind:    "login",
		session: sessionData,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.setPendingCookie(w, token)
	writeJSON(w, http.StatusOK, options)
}

// POST /api/auth/login/finish — body is the assertion response.
func (s *Service) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(pendingCookie)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing pending cookie")
		return
	}
	p := s.takePending(cookie.Value)
	s.clearPendingCookie(w)
	if p == nil || p.kind != "login" {
		writeErr(w, http.StatusBadRequest, "no pending login")
		return
	}

	ctx := r.Context()
	cred, err := s.web.FinishDiscoverableLogin(
		func(rawID, userHandle []byte) (webauthn.User, error) {
			u, err := s.store.GetUserByID(ctx, userHandle)
			if err != nil {
				return nil, err
			}
			if u == nil {
				return nil, errAuthFailed
			}
			return u, nil
		},
		*p.session,
		r,
	)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}

	now := time.Now().UTC()
	if err := s.store.UpdateCredentialAfterLogin(ctx, cred, now); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// We need the user (UserHandle == userID) for the session.
	userID, err := s.store.UserHandleForCredential(ctx, cred.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		writeErr(w, http.StatusInternalServerError, "post-login: user not found")
		return
	}
	sess, err := s.createSession(ctx, user.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.UpdateLastLogin(ctx, user.ID, sess.CreatedAt)
	s.setSessionCookie(w, sess.Token, sess.ExpiresAt)
	writeJSON(w, http.StatusOK, publicUser(user))
}

// ----- helpers ------------------------------------------------------------

type publicUserView struct {
	ID          string     `json:"id"`           // hex of user handle
	Name        string     `json:"name"`
	DisplayName string     `json:"displayName"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
}

func publicUser(u *User) publicUserView {
	return publicUserView{
		ID:          bytesToHex(u.ID),
		Name:        u.Name,
		DisplayName: u.DisplayName,
		CreatedAt:   u.CreatedAt,
		LastLoginAt: u.LastLoginAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

var errAuthFailed = httpError("authentication failed")

type httpError string

func (e httpError) Error() string { return string(e) }

// bytesToHex avoids importing encoding/hex twice; uses the same hex.EncodeToString
// path via the standard library.
func bytesToHex(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}

// ensureCtx is here so we can drop a SoftPing-style helper later without the
// linter complaining about unused imports during the v0 build.
var _ = context.Background
