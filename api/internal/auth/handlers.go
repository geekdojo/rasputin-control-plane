package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/geekdojo/rasputin-control-plane/secret"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
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
	mux.HandleFunc("GET /api/auth/callback", s.handleCallback)
	mux.HandleFunc("GET "+ResetDonePath, s.handleResetDone)
	mux.HandleFunc("POST /api/identity/backchannel/{client}", s.handleBackchannel)
	mux.HandleFunc("POST /api/auth/register/begin", s.handleRegisterBegin)
	mux.HandleFunc("POST /api/auth/register/step-up", s.handleRegisterStepUp)
	mux.HandleFunc("POST /api/auth/register/finish", s.handleRegisterFinish)
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

// GET /api/auth/status — open. firstRun drives the restore page (no
// pre-update operator exists); ready says whether a sign-in can start now;
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

// GET /api/auth/reset-done — open. The home door's reset client returns
// here: ResetDone ends the person's sessions and mints none.
func (s *Service) handleResetDone(w http.ResponseWriter, r *http.Request) {
	rd := s.reset()
	if rd == nil {
		http.Redirect(w, r, launcherPath+"?signin="+ResetOutcomeFailed, http.StatusSeeOther)
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

// ----- registration -------------------------------------------------------
//
// One way in: first run (no pre-update operator exists). register/begin
// returns creation options; register/finish commits only if no operator
// exists by then, and opens no session: a console session comes only from a
// sign-in through the home door (geekdojo/geekdojo-brain#989). Adding a
// passkey to a signed-in account needed a pre-update session, which no longer
// signs anyone in, so it is refused; passkeys are managed at the sign-in
// service (#319). Identity 4.8 removes these routes.

// signedInPasskeyGone is the 401 every signed-in passkey ceremony gets.
const signedInPasskeyGone = "Passkeys are managed from your account at the sign-in service, not here."

// POST /api/auth/register/begin
// Body: { "name": "alice", "displayName": "Alice", "authenticator": "platform" }
//
// authenticator is optional and names the kind of authenticator the operator
// picked in the UI — see authenticatorChoice. Absent or empty means "whatever
// the browser offers", which is what the first-run wizard sends.
//
// First run: creates the first operator; returns creation options. Past
// first run: 401.
func (s *Service) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string `json:"name"`
		DisplayName   string `json:"displayName"`
		Authenticator string `json:"authenticator"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	choice, err := parseAuthenticatorChoice(req.Authenticator)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	firstRun, err := s.FirstRun(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !firstRun {
		writeErr(w, http.StatusUnauthorized, signedInPasskeyGone)
		return
	}
	s.beginFirstRunRegistration(w, r, req.Name, req.DisplayName, choice)
}

func (s *Service) beginFirstRunRegistration(w http.ResponseWriter, r *http.Request, name, displayName string, choice authenticatorChoice) {
	user, err := makeUser(name, displayName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	options, sessionData, err := s.beginCreation(user, choice)
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
	s.setCeremonyCookie(w, token)
	writeJSON(w, http.StatusOK, options)
}

// authenticatorChoice is the kind of authenticator the operator picked before
// adding a passkey. It exists because excludeCredentials does its job: on a
// machine whose built-in authenticator already holds a passkey for the
// account, creation is refused, and a browser left to choose for itself offers
// its own password manager rather than the phone or the security key the
// operator actually has in hand. The choice is made in the UI, travels on the
// register/begin body, and becomes the attachment and hint on the creation
// options.
type authenticatorChoice string

const (
	// authenticatorAny is the absent choice: no attachment and no hints, so
	// the browser offers everything it can. This is what the first-run
	// wizard sends — there is no existing passkey to collide with, and the
	// operator is at the machine they are setting up.
	authenticatorAny authenticatorChoice = ""
	// authenticatorPlatform is the authenticator built into this machine
	// (Touch ID, Windows Hello).
	authenticatorPlatform authenticatorChoice = "platform"
	// authenticatorHybrid is a phone or tablet, reached by QR code or a
	// previously linked device.
	authenticatorHybrid authenticatorChoice = "hybrid"
	// authenticatorSecurityKey is a roaming hardware key (USB, NFC).
	authenticatorSecurityKey authenticatorChoice = "security-key"
)

// parseAuthenticatorChoice validates the wire value. An unknown value is a
// 400 rather than a silent fall back to authenticatorAny: a UI sending a value
// this api does not model has a bug, and quietly widening the ceremony would
// put the operator back at the dead end the choice exists to avoid.
func parseAuthenticatorChoice(s string) (authenticatorChoice, error) {
	switch c := authenticatorChoice(s); c {
	case authenticatorAny, authenticatorPlatform, authenticatorHybrid, authenticatorSecurityKey:
		return c, nil
	default:
		return authenticatorAny, errors.New(`authenticator must be "platform", "hybrid", "security-key", or absent`)
	}
}

// hint maps the choice onto the WebAuthn Level 3 hint that expresses it.
// authenticatorAny has no hint, which is how beginCreation knows to leave the
// creation options untouched.
func (c authenticatorChoice) hint() protocol.PublicKeyCredentialHints {
	switch c {
	case authenticatorPlatform:
		return protocol.PublicKeyCredentialHintClientDevice
	case authenticatorHybrid:
		return protocol.PublicKeyCredentialHintHybrid
	case authenticatorSecurityKey:
		return protocol.PublicKeyCredentialHintSecurityKey
	default:
		return ""
	}
}

// beginCreation issues WebAuthn creation options for user, excluding the
// credentials it already has, narrowed to the authenticator kind the operator
// picked.
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
//
// The choice is expressed twice, deliberately. The hint is what a current
// browser reads; the matching authenticatorAttachment is what a browser that
// predates hints reads, and the spec tells relying parties to send both so the
// two kinds of user agent filter the same way (protocol.PublicKeyCredentialHints).
//
// WithAuthenticatorSelection REPLACES the whole AuthenticatorSelection struct
// the library seeded from Config — including UserVerification: required
// (decision #561). So the user-verification setting is re-supplied here, read
// back off the relying-party config rather than restated, and
// WithResidentKeyRequirement is applied last because it edits that same struct
// in place. TestUserVerificationRequired executes this.
func (s *Service) beginCreation(user *User, choice authenticatorChoice) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	creds := user.WebAuthnCredentials()
	excl := make([]protocol.CredentialDescriptor, 0, len(creds))
	for i := range creds {
		excl = append(excl, creds[i].Descriptor())
	}
	opts := []webauthn.RegistrationOption{webauthn.WithExclusions(excl)}
	if hint := choice.hint(); hint != "" {
		opts = append(opts,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				AuthenticatorAttachment: hint.AuthenticatorAttachment(),
				UserVerification:        s.web.Config.AuthenticatorSelection.UserVerification,
			}),
			webauthn.WithPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{hint}),
		)
	}
	opts = append(opts, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	return s.web.BeginRegistration(user, opts...)
}

// POST /api/auth/register/step-up — refused: it confirmed a signed-in
// account's existing passkey, and no pre-update session signs anyone in.
func (s *Service) handleRegisterStepUp(w http.ResponseWriter, _ *http.Request) {
	writeErr(w, http.StatusUnauthorized, signedInPasskeyGone)
}

// POST /api/auth/register/finish
// Body: the PublicKeyCredential attestation response from the browser.
func (s *Service) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(ceremonyCookieName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing pending cookie")
		return
	}
	p := s.takePending(cookie.Value)
	s.clearCeremonyCookie(w)
	if p == nil || p.kind != "register" || p.user == nil || p.session == nil {
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

	// User and credential commit in one transaction, and only if no operator
	// exists now, checked in the same statement as the insert.
	if err := s.store.CreateFirstUser(r.Context(), p.user, dbCred); err != nil {
		if errors.Is(err, ErrNotFirstRun) {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// No session is opened: a console session comes only from a sign-in
	// through the home door (geekdojo/geekdojo-brain#989).
	writeJSON(w, http.StatusOK, publicUser(p.user))
}

// ----- login (pre-update passkeys) -----------------------------------------

// loginGoneSentence is the 410 the pre-update passkey sign-in answers.
const loginGoneSentence = "Passkey sign-in on this page has been replaced. Sign in from the sign-in page instead."

// POST /api/auth/login/begin and /api/auth/login/finish — gone: the console
// signs in only through the home door (geekdojo/geekdojo-brain#989). They do
// no ceremony work and set no cookie, until Identity 4.8 removes them.
func (s *Service) handleLoginGone(w http.ResponseWriter, _ *http.Request) {
	writeErr(w, http.StatusGone, loginGoneSentence)
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

// errNilDep is a constructor's refusal of a missing collaborator.
func errNilDep(fn string) error { return errors.New("auth: " + fn + ": a collaborator is nil") }

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
