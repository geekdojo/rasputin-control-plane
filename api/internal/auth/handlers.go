package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// RegisterRoutes installs auth-related routes onto mux. Path-prefixed with
// /api/auth/ so the api.Server can mount them at the right place.
func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/status", s.handleStatus)
	mux.HandleFunc("GET /api/auth/me", s.handleMe)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("POST /api/auth/register/begin", s.handleRegisterBegin)
	mux.HandleFunc("POST /api/auth/register/step-up", s.handleRegisterStepUp)
	mux.HandleFunc("POST /api/auth/register/finish", s.handleRegisterFinish)
	mux.HandleFunc("POST /api/auth/login/begin", s.handleLoginBegin)
	mux.HandleFunc("POST /api/auth/login/finish", s.handleLoginFinish)
}

// ----- status / me / logout -----------------------------------------------

// GET /api/auth/status — open. Reports whether any users exist (drives the
// first-run flow) and the current user if logged in. An error reading
// FirstRun is a 500, never hasUsers=false.
func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	firstRun, err := s.FirstRun(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	n, err := s.store.CountUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{"hasUsers": !firstRun, "userCount": n}
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
//
// Two ways in, recorded in the ceremony's basis and re-checked at finish:
//
//   - First run (no users exist). register/begin returns creation options
//     directly; register/finish commits only if no operator exists by then.
//
//   - Signed in. A session alone does not add a passkey. register/begin
//     returns a step-up assertion challenge for the signed-in user's own
//     passkeys; register/step-up verifies it (single use: the challenge is
//     consumed on the first attempt, pass or fail) and only then issues the
//     creation options; register/finish refuses unless that step-up verified
//     for THIS ceremony and the same user's session is still live.
//
// The step-up assertion uses the same user-verification setting as sign-in
// (the relying party's default; login passes no override), so it is no
// stronger and no weaker than signing in.

// POST /api/auth/register/begin
// Body: { "name": "alice", "displayName": "Alice" }
//
// First run: creates the first operator; returns creation options.
//
// Signed in: an empty name adds a passkey to the signed-in user's own
// account; a new name creates another user. Either way the response is
// { "stepUp": <assertion options> } and the ceremony continues at
// register/step-up.
func (s *Service) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}

	firstRun, err := s.FirstRun(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if firstRun {
		s.beginFirstRunRegistration(w, r, req.Name, req.DisplayName)
		return
	}

	_, by, err := s.resolveSession(r)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if by == nil {
		writeErr(w, http.StatusUnauthorized,
			"only an authenticated user can register a new user")
		return
	}

	p := &pendingAuth{kind: "register", basis: registerBasis{byUserID: by.ID}}
	if req.Name == "" {
		p.addToSelf = true
	} else {
		existing, err := s.store.GetUserByName(r.Context(), req.Name)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if existing != nil {
			writeErr(w, http.StatusConflict, "user with that name already exists")
			return
		}
		if p.user, err = makeUser(req.Name, req.DisplayName); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if len(by.WebAuthnCredentials()) == 0 {
		writeErr(w, http.StatusConflict,
			"this account has no passkey to confirm with")
		return
	}
	// No login options: the same user-verification setting as sign-in.
	assertion, stepUp, err := s.web.BeginLogin(by)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	p.stepUp = stepUp
	token, err := s.storePending(p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.setPendingCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{"stepUp": assertion})
}

func (s *Service) beginFirstRunRegistration(w http.ResponseWriter, r *http.Request, name, displayName string) {
	user, err := makeUser(name, displayName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	options, sessionData, err := s.beginCreation(user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, err := s.storePending(&pendingAuth{
		kind:    "register",
		user:    user,
		session: sessionData,
		basis:   registerBasis{firstRun: true},
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.setPendingCookie(w, token)
	writeJSON(w, http.StatusOK, options)
}

// beginCreation issues WebAuthn creation options for user, excluding the
// credentials it already has.
//
// Require a discoverable credential (resident key). Login is
// BeginDiscoverableLogin — it sends an empty allowCredentials list, so an
// authenticator that stored a non-discoverable credential can never be
// offered at sign-in. Without this the two halves disagree: registration
// succeeds and login is then impossible, with nothing in the UI to explain
// why. Platform authenticators (Touch ID, Windows Hello) create
// discoverable credentials whether or not they're asked, which is why this
// stayed hidden — a USB security key, the only authenticator a Linux
// desktop can use, is the case that exposes it. WithResidentKeyRequirement
// also sets the legacy requireResidentKey flag for older authenticators.
func (s *Service) beginCreation(user *User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	creds := user.WebAuthnCredentials()
	excl := make([]protocol.CredentialDescriptor, 0, len(creds))
	for i := range creds {
		excl = append(excl, creds[i].Descriptor())
	}
	return s.web.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(excl))
}

// POST /api/auth/register/step-up
// Body: the assertion response for the challenge register/begin returned.
// Verifies it against the signed-in user's own passkeys and, on success,
// returns the creation options for the new passkey.
func (s *Service) handleRegisterStepUp(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(pendingCookie)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing pending cookie")
		return
	}
	token := cookie.Value
	p, challenge := s.takeStepUp(token)
	if p == nil {
		writeErr(w, http.StatusBadRequest, "no registration awaiting confirmation")
		return
	}
	// Any failure below ends the ceremony: its challenge is already spent.
	fail := func(status int, msg string) {
		s.dropPending(token)
		s.clearPendingCookie(w)
		writeErr(w, status, msg)
	}

	_, by, err := s.resolveSession(r)
	if err != nil {
		fail(http.StatusInternalServerError, err.Error())
		return
	}
	if by == nil || !bytes.Equal(by.ID, p.basis.byUserID) {
		fail(http.StatusUnauthorized, "the session that began this registration is no longer signed in")
		return
	}
	cred, err := s.web.FinishLogin(by, *challenge, r)
	if err != nil {
		fail(http.StatusUnauthorized, "confirming with an existing passkey failed: "+err.Error())
		return
	}
	if err := s.store.UpdateCredentialAfterLogin(r.Context(), cred, time.Now().UTC()); err != nil {
		fail(http.StatusInternalServerError, err.Error())
		return
	}

	target := p.user
	if p.addToSelf {
		target = by
	}
	options, creation, err := s.beginCreation(target)
	if err != nil {
		fail(http.StatusInternalServerError, err.Error())
		return
	}
	if !s.completeStepUp(token, p, target, creation) {
		fail(http.StatusBadRequest, "no registration awaiting confirmation")
		return
	}
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
	if p == nil || p.kind != "register" {
		writeErr(w, http.StatusBadRequest, "no pending registration")
		return
	}

	if !p.basis.firstRun {
		// A signed-in registration needs its own step-up to have verified,
		// and the user who began it still signed in.
		if !p.stepUpVerified {
			writeErr(w, http.StatusForbidden,
				"confirm with an existing passkey before adding a new one")
			return
		}
		_, by, err := s.resolveSession(r)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if by == nil || len(p.basis.byUserID) == 0 || !bytes.Equal(by.ID, p.basis.byUserID) {
			writeErr(w, http.StatusUnauthorized,
				"the session that began this registration is no longer signed in")
			return
		}
	}
	if p.user == nil || p.session == nil {
		writeErr(w, http.StatusBadRequest, "no pending registration")
		return
	}

	cred, err := s.web.FinishRegistration(p.user, *p.session, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	dbCred := fromWebAuthn(cred, p.user.ID)
	dbCred.CreatedAt = time.Now().UTC()

	if p.addToSelf {
		// A new passkey on the signed-in account: the session carries on.
		if err := s.store.CreateCredential(r.Context(), dbCred); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, publicUser(p.user))
		return
	}

	// User and credential commit in one transaction. A ceremony begun at
	// first run commits only if no operator exists now, checked in the same
	// statement as the insert.
	if err := s.store.CreateUserWithCredential(r.Context(), p.user, dbCred, p.basis.firstRun); err != nil {
		if errors.Is(err, ErrNotFirstRun) {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess, err := s.createSession(r.Context(), p.user.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.UpdateLastLogin(r.Context(), p.user.ID, sess.CreatedAt)
	s.runLoginHook(r.Context(), p.user)
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
	s.runLoginHook(ctx, user)
	s.setSessionCookie(w, sess.Token, sess.ExpiresAt)
	writeJSON(w, http.StatusOK, publicUser(user))
}

// ----- helpers ------------------------------------------------------------

type publicUserView struct {
	ID          string     `json:"id"` // hex of user handle
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
