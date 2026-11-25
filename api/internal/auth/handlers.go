package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// RouteRegistrar is the one method RegisterRoutes needs from a mux. An
// *http.ServeMux satisfies it; so does the api's recording mux, which is how
// the route-enumeration auth test sees these routes without a copied list.
type RouteRegistrar interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// RegisterRoutes installs auth-related routes onto mux. Path-prefixed with
// /api/auth/ so the api.Server can mount them at the right place.
func (s *Service) RegisterRoutes(mux RouteRegistrar) {
	mux.HandleFunc("GET /api/auth/status", s.handleStatus)
	mux.HandleFunc("GET /api/auth/me", s.handleMe)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/auth/signin", s.handleSignin)
	mux.HandleFunc("GET /api/auth/signup", s.handleSignup)
	mux.HandleFunc("GET /api/auth/callback", s.handleCallback)
	mux.HandleFunc("GET "+ResetDonePath, s.handleResetDone)
	mux.HandleFunc("POST /api/identity/backchannel/{client}", s.handleBackchannel)
	mux.HandleFunc("POST /api/auth/login/begin", s.handleLoginGone)
	mux.HandleFunc("POST /api/auth/login/finish", s.handleLoginGone)
}

// ----- status / me / logout -----------------------------------------------

// meView is the signed-in person as the console reads it. Capabilities is
// what the session may do (authz.Set.List: a fixed order, never null); it
// reports and decides nothing.
type meView struct {
	Sub          string   `json:"sub"`
	Name         string   `json:"name"`
	Roles        []string `json:"roles"`
	Capabilities []string `json:"capabilities"`
}

func viewOf(p Principal) meView {
	return meView{Sub: p.Sub, Name: p.Name, Roles: nonNil(p.Roles), Capabilities: p.Capabilities().List()}
}

// GET /api/auth/status — open. firstRun drives the launcher's CREATE THE
// FIRST ACCOUNT and the restore page (no first-run claim and no pre-update
// operator exist, C03); ready says whether a sign-in can start now;
// user is the signed-in person, only with a live console session. It never
// reports how many accounts exist. An error reading firstRun is a 500.
func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	firstRun, err := s.FirstRun(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	si := s.signin()
	resp := map[string]any{"firstRun": firstRun, "ready": si != nil && si.Ready(r.Context())}
	p, cookie, outcome, err := s.resolve(r)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if outcome == sessionFound {
		cookie.Destroy()
		resp["user"] = viewOf(p)
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/auth/me — open, but 401 without a console session.
func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	p, cookie, outcome, err := s.resolve(r)
	switch {
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	case outcome == sessionDuplicate:
		writeDuplicateCookie(w, SessionCookieName)
		return
	case outcome != sessionFound:
		writeErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	cookie.Destroy()
	writeJSON(w, http.StatusOK, viewOf(p))
}

// POST /api/auth/logout — ends the console session, clears its cookie, then
// ends the identity session it was signed in under. It answers 200 even
// when that last step fails (SignIn.EndSession logs it).
func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	sid := ""
	if c, err := oneCookie(r, SessionCookieName); err == nil && s.sessions != nil {
		cookie := secret.New([]byte(c.Value))
		sid, err = s.sessions.Delete(r.Context(), cookie)
		cookie.Destroy()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "The session could not be ended.")
			return
		}
	}
	clearCookie(w, SessionCookieName)
	if si := s.signin(); si != nil && sid != "" {
		si.EndSession(r.Context(), sid)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GET /api/auth/signin — open. Starts a sign-in at the home door, or sends
// the browser back to the launcher when sign-in is not installed. With
// ?action= it starts a prepared action's fresh sign-in instead, for the
// caller's own console session only: without one it answers 401.
func (s *Service) handleSignin(w http.ResponseWriter, r *http.Request) {
	si := s.signin()
	if si == nil {
		http.Redirect(w, r, signinUnavailable, http.StatusSeeOther)
		return
	}
	if q := r.URL.Query(); q.Has("action") {
		kind := q.Get("action")
		s.RequireSessionFunc(func(w http.ResponseWriter, r *http.Request) { si.StartAction(w, r, kind) })(w, r)
		return
	}
	si.Begin(w, r)
}

// GET /api/auth/signup — open. Starts account creation at the home door
// (prompt=create), whose return is an ordinary sign-in at the callback, or
// sends the browser back to the launcher when sign-in is not installed
// (geekdojo/geekdojo-brain#990). It only redirects and stores a pending
// record; the door decides who may create an account.
func (s *Service) handleSignup(w http.ResponseWriter, r *http.Request) {
	si := s.signin()
	if si == nil {
		http.Redirect(w, r, signinUnavailable, http.StatusSeeOther)
		return
	}
	si.BeginCreate(w, r)
}

// GET /api/auth/reset-done — open. The home door's reset client returns
// here: ResetDone ends the person's sessions and mints none.
func (s *Service) handleResetDone(w http.ResponseWriter, r *http.Request) {
	rd := s.reset()
	if rd == nil {
		http.Redirect(w, r, resetFailedLocation, http.StatusSeeOther)
		return
	}
	rd.ServeHTTP(w, r)
}

// GET /api/auth/callback — open. The home door's return: SignIn.Complete
// decides, and this writes its answer. The pending cookie is cleared
// whatever the outcome.
func (s *Service) handleCallback(w http.ResponseWriter, r *http.Request) {
	si := s.signin()
	if si == nil {
		http.Redirect(w, r, signinUnavailable, http.StatusSeeOther)
		return
	}
	key := ""
	switch c, err := oneCookie(r, pendingCookieName); {
	case errors.Is(err, errDuplicateCookie):
		writeDuplicateCookie(w, pendingCookieName)
		return
	case err == nil:
		key = c.Value
	}
	clearCookie(w, pendingCookieName)
	res := si.Complete(r.Context(), CallbackInput{PendingKey: key, Query: r.URL.Query()})
	if res.Status == http.StatusInternalServerError {
		writeErr(w, http.StatusInternalServerError, "The sign-in could not be completed.")
		return
	}
	if res.Cookie.Len() > 0 {
		s.runLoginHook(r.Context(), res.Name)
		if res.Admin {
			s.runAdminSignInHook(r.Context())
		}
		setSessionCookie(w, res.Cookie)
		res.Cookie.Destroy()
	}
	http.Redirect(w, r, res.Location, http.StatusSeeOther)
}

// ----- login (pre-update passkeys) -----------------------------------------

// loginGoneSentence is the 410 the pre-update passkey sign-in answers.
const loginGoneSentence = "Passkey sign-in on this page has been replaced. Sign in from the sign-in page instead."

// POST /api/auth/login/begin and /api/auth/login/finish — gone: the console
// signs in only through the home door (geekdojo/geekdojo-brain#989). They do
// no ceremony work and set no cookie.
func (s *Service) handleLoginGone(w http.ResponseWriter, _ *http.Request) {
	writeErr(w, http.StatusGone, loginGoneSentence)
}

// ----- helpers ------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// errNilDep is a constructor's refusal of a missing collaborator.
func errNilDep(fn string) error { return errors.New("auth: " + fn + ": a collaborator is nil") }
