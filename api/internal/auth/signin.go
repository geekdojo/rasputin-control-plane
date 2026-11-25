package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/idtoken"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The console's sign-in (geekdojo/geekdojo-brain#989, Identity 4.7; register
// row C70): the console is an OIDC client, rasputin-console, of the home
// door. GET /api/auth/signin starts an authorization-code flow with PKCE
// S256, a state, a nonce and prompt=login at the door's issuer (GET
// /api/auth/signup the same with prompt=create, Identity 4.8); the door
// sends the browser back to GET /api/auth/callback, where the code is
// exchanged on loopback over the api's own leaf, the ID token verified, and
// an opaque console session minted (ConsoleSessions). No token the identity
// service issued is kept: the session names the account, its identity
// session and its console roles.

// The answers a sign-in sends the browser to: the launcher, which routes a
// signed-in person on, or the launcher with one sentence's key.
const (
	launcherPath      = "/login"
	signinFailed      = launcherPath + "?signin=failed"
	signinExpired     = launcherPath + "?signin=expired"
	signinUnavailable = launcherPath + "?signin=unavailable"
	signinWrongHost   = launcherPath + "?signin=wrong-host"
	// signinActionFailed is a fresh-sign-in action that ran and failed, or
	// could not start (ERR-MESSAGE: not the sign-in's own failure).
	signinActionFailed = launcherPath + "?signin=action-failed"
	// actionStartPath is where a prepared action's fresh sign-in starts.
	actionStartPath = "/api/auth/signin?action="
	callbackPath    = "/api/auth/callback"
)

// Exchanger is the code exchange: *idclient.Client.
type Exchanger interface {
	ExchangeCode(ctx context.Context, x idclient.CodeExchange) (secret.Value, error)
}

// TokenVerifier verifies the home door's ID and logout tokens for the
// console: *idtoken.Verifier.
type TokenVerifier interface {
	IDToken(ctx context.Context, raw secret.Value) (idtoken.Claims, error)
	LogoutToken(ctx context.Context, raw secret.Value) (string, error)
}

// SessionEnder ends an identity session by its id through the Admin API.
type SessionEnder interface {
	EndSession(ctx context.Context, sid string) error
}

// Readiness answers whether the identity service can take a sign-in: nil
// when it can (*identitystate.Monitor).
type Readiness interface {
	Ready(ctx context.Context) error
}

// Action is a fresh-sign-in action (Identity 9.3, 9.7, #319, 4.10, 4.12):
// it runs once the person it was started for has signed in again, and
// returns where the browser goes next. payload is what PrepareAction held
// for it, or nil; the action may read it during Run and must copy whatever
// it keeps, since the sign-in destroys it once Run returns.
type Action interface {
	Run(ctx context.Context, p Principal, payload ActionPayload) (redirect string, err error)
}

// ActionPayload is a value an action runs with that must not travel through
// the browser, such as a password (geekdojo/geekdojo-brain#992). The sign-in
// destroys it exactly once, whatever becomes of the record holding it.
type ActionPayload interface{ Destroy() }

// FirstRunner is the first-run predicate (*Store, register row C03).
type FirstRunner interface {
	FirstRun(ctx context.Context) (bool, error)
}

// Claimer names the account a first-run claim designates: the realm's
// earliest-created person (*accounts.FirstAccount,
// geekdojo/geekdojo-brain#990).
type Claimer interface {
	Earliest(ctx context.Context) (string, error)
}

// Observer is told of every verified console sign-in, so a designated
// account whose setup is complete gets its role (*accounts.Observer; row
// B101: the callback is the fact that submits, and resubmits, the grant).
// It decides and logs on its own and returns nothing.
type Observer interface {
	SignedIn(ctx context.Context, sub string)
}

// ErrNoAction is PrepareAction's refusal of a kind no action is registered
// under, a request with no signed-in person, or a browser carrying the
// pending cookie twice.
var ErrNoAction = errors.New("auth: the action cannot be prepared")

// SignInDeps are SignIn's collaborators. NewSignIn refuses a missing one;
// Actions may be empty.
type SignInDeps struct {
	// Door is the home door: its issuer is the one the console signs in at
	// and accepts tokens from, and its forwarded headers go on the exchange.
	Door doors.Door
	// ConsoleHost is the console's name, <cid>.local. A sign-in begun at
	// any other name is refused, because the redirect URI names this one.
	ConsoleHost string
	// ClientID is rasputin-console.
	ClientID  string
	Realm     string
	Exchanger Exchanger
	Verifier  TokenVerifier
	Ender     SessionEnder
	Ready     Readiness
	Sessions  *ConsoleSessions
	// FirstRun, Claimer and Observer are the first-run claim and the
	// designation's fact (geekdojo/geekdojo-brain#990).
	FirstRun FirstRunner
	Claimer  Claimer
	Observer Observer
	Actions  map[string]Action
	// Clock is the api's clock-sync fact: an authenticator app is added, and
	// its kc_action forwarded, only while it holds
	// (geekdojo/geekdojo-brain#1150).
	Clock ClockFact
	Now   func() time.Time
	Rand  io.Reader
	Log   *slog.Logger
}

// SignIn is the console's OIDC client for the home door.
type SignIn struct {
	d       SignInDeps
	pending *pendingSignins
	log     *slog.Logger
}

// NewSignIn checks d and returns a SignIn. It does no I/O.
func NewSignIn(d SignInDeps) (*SignIn, error) {
	switch {
	case d.Door.Issuer == "" || d.Door.Host == "":
		return nil, errors.New("auth: SignInDeps.Door is empty")
	case d.ConsoleHost == "":
		return nil, errors.New("auth: SignInDeps.ConsoleHost is empty")
	case d.ClientID == "" || d.Realm == "":
		return nil, errors.New("auth: SignInDeps.ClientID or Realm is empty")
	case d.Exchanger == nil:
		return nil, errors.New("auth: SignInDeps.Exchanger is nil")
	case d.Verifier == nil:
		return nil, errors.New("auth: SignInDeps.Verifier is nil")
	case d.Ender == nil:
		return nil, errors.New("auth: SignInDeps.Ender is nil")
	case d.Ready == nil:
		return nil, errors.New("auth: SignInDeps.Ready is nil")
	case d.Sessions == nil:
		return nil, errors.New("auth: SignInDeps.Sessions is nil")
	case d.FirstRun == nil || d.Claimer == nil || d.Observer == nil:
		return nil, errors.New("auth: SignInDeps.FirstRun, Claimer or Observer is nil")
	case d.Clock == nil:
		return nil, errors.New("auth: SignInDeps.Clock is nil")
	case d.Now == nil:
		return nil, errors.New("auth: SignInDeps.Now is nil")
	case d.Rand == nil:
		return nil, errors.New("auth: SignInDeps.Rand is nil")
	case d.Log == nil:
		return nil, errors.New("auth: SignInDeps.Log is nil")
	}
	return &SignIn{d: d, pending: newPendingSignins(d.Now), log: d.Log.With("component", "auth")}, nil
}

// redirectURI is the one redirect URI the console's client has.
func (s *SignIn) redirectURI() string { return "https://" + s.d.ConsoleHost + callbackPath }

// consoleHost reports whether r arrived at the console's own name (port 443
// is the console's only port, and a browser leaves it out).
func (s *SignIn) consoleHost(r *http.Request) bool {
	host := r.Host
	if h, port, err := net.SplitHostPort(host); err == nil {
		if port != "443" {
			return false
		}
		host = h
	}
	return strings.EqualFold(strings.TrimSuffix(host, "."), s.d.ConsoleHost)
}

// Begin serves GET /api/auth/signin: it stores the sign-in's record (or
// replaces the browser's live one) and sends the browser to the home door.
func (s *SignIn) Begin(w http.ResponseWriter, r *http.Request) {
	s.begin(w, r, nil, "", promptLogin)
}

// BeginCreate serves GET /api/auth/signup: Begin with prompt=create, which
// opens the home door's registration form (geekdojo/geekdojo-brain#990).
// The new account's return is an ordinary sign-in at the callback, so the
// api sees every account created.
func (s *SignIn) BeginCreate(w http.ResponseWriter, r *http.Request) {
	s.begin(w, r, nil, "", promptCreate)
}

// The prompts a sign-in starts with: a fresh sign-in, or account creation.
const (
	promptLogin  = "login"
	promptCreate = "create"
)

// PrepareAction holds payload for the action named kind, for the person r
// is signed in as, under the browser's pending cookie (replacing any record
// there), and returns where the browser goes to start the action's fresh
// sign-in: GET /api/auth/signin?action=<kind>. It takes payload whatever
// happens: on a refusal (ErrNoAction, or no random values) it destroys it.
func (s *SignIn) PrepareAction(w http.ResponseWriter, r *http.Request, kind string, payload ActionPayload) (string, error) {
	destroy := func() {
		if payload != nil {
			payload.Destroy()
		}
	}
	if _, known := s.d.Actions[kind]; !known {
		destroy()
		return "", ErrNoAction
	}
	next, err := s.prepare(w, r, kind, &pendingAction{kind: kind, payload: payload})
	if err != nil {
		destroy()
	}
	return next, err
}

// prepare stores action, for the person r is signed in as, as a prepared
// record under the browser's pending cookie (replacing any record there),
// sets the cookie and returns the fresh sign-in's start. It refuses with
// ErrNoAction without a signed-in person or with the pending cookie twice;
// on any refusal it stores nothing and the caller still owns the payload.
func (s *SignIn) prepare(w http.ResponseWriter, r *http.Request, kind string, action *pendingAction) (string, error) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Sub == "" {
		return "", ErrNoAction
	}
	key := ""
	switch c, err := oneCookie(r, pendingCookieName); {
	case errors.Is(err, errDuplicateCookie):
		return "", ErrNoAction
	case err == nil && s.pending.live(c.Value):
		key = c.Value
	}
	if key == "" {
		var err error
		if key, err = s.random(32); err != nil {
			return "", err
		}
	}
	action.sub = p.Sub
	s.pending.put(key, &pendingSignin{begin: s.d.Now(), prepared: true, action: action})
	setCookie(w, pendingCookieName, key, signinPendingLifetime)
	return actionStartPath + url.QueryEscape(kind), nil
}

// known reports whether kind names a registered action or a sign-in
// method.
func (s *SignIn) known(kind string) bool {
	_, ok := s.d.Actions[kind]
	return ok || methodKind(kind)
}

// StartAction begins the fresh sign-in a prepared action needs, for the
// person r is signed in as: the same round trip with prompt=login, whose
// return runs the action named kind instead of minting a session. It
// answers 404 for a kind no action is registered under and 401 without a
// signed-in person. It begins only from the browser's live prepared record
// of that kind for that person; anything else is destroyed and sends the
// browser to the launcher's action-failed sentence.
func (s *SignIn) StartAction(w http.ResponseWriter, r *http.Request, kind string) {
	if !s.known(kind) {
		writeErr(w, http.StatusNotFound, "There is no such action.")
		return
	}
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	if !s.consoleHost(r) {
		http.Redirect(w, r, signinWrongHost, http.StatusSeeOther)
		return
	}
	c, err := oneCookie(r, pendingCookieName)
	if errors.Is(err, errDuplicateCookie) {
		writeDuplicateCookie(w, pendingCookieName)
		return
	}
	var rec *pendingSignin
	if err == nil {
		rec = s.pending.take(c.Value)
	}
	if rec == nil || !rec.prepared || rec.action.kind != kind || rec.action.sub != p.Sub {
		if rec != nil {
			rec.destroy()
		}
		s.refused(r.Context(), "action_record", p.Sub)
		http.Redirect(w, r, signinActionFailed, http.StatusSeeOther)
		return
	}
	if rec.action.method != "" {
		s.log.LogAttrs(r.Context(), slog.LevelInfo, "A person started adding a sign-in method.",
			slog.String("event", "signin.method_started"), slog.String("method", string(rec.action.method)),
			slog.String("kind", kind), slog.String("sub", p.Sub))
	}
	s.begin(w, r, rec.action, c.Value, promptLogin)
}

// begin starts a sign-in. An action's (StartAction) comes with its
// prepared record's key and has already left the map; begin owns the
// action's payload, and destroys it on every answer but the redirect.
func (s *SignIn) begin(w http.ResponseWriter, r *http.Request, action *pendingAction, key, prompt string) {
	drop := func() {
		if action != nil && action.payload != nil {
			action.payload.Destroy()
		}
	}
	if action == nil {
		if !s.consoleHost(r) {
			http.Redirect(w, r, signinWrongHost, http.StatusSeeOther)
			return
		}
		switch c, err := oneCookie(r, pendingCookieName); {
		case errors.Is(err, errDuplicateCookie):
			writeDuplicateCookie(w, pendingCookieName)
			return
		case err == nil && s.pending.live(c.Value):
			key = c.Value
		}
	}
	if err := s.d.Ready.Ready(r.Context()); err != nil {
		drop()
		s.log.LogAttrs(r.Context(), slog.LevelWarn, "A console sign-in could not start: the sign-in service is not ready.",
			slog.String("event", "signin.unavailable"))
		http.Redirect(w, r, signinUnavailable, http.StatusSeeOther)
		return
	}
	rec, challenge, err := s.newRecord(action)
	if err == nil && key == "" {
		key, err = s.random(32)
	}
	if err != nil {
		drop()
		s.log.LogAttrs(r.Context(), slog.LevelError, "A console sign-in could not start: no random values.",
			slog.String("event", "signin.begin_failed"), slog.String("err", err.Error()))
		writeErr(w, http.StatusInternalServerError, "The sign-in could not start.")
		return
	}
	s.pending.put(key, rec)
	setCookie(w, pendingCookieName, key, signinPendingLifetime)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {s.d.ClientID},
		"redirect_uri":          {s.redirectURI()},
		"scope":                 {"openid"},
		"state":                 {rec.state},
		"nonce":                 {rec.nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"prompt":                {prompt},
	}
	if action != nil && action.kcAction != "" {
		q.Set("kc_action", action.kcAction)
	}
	http.Redirect(w, r, s.d.Door.Issuer+"/protocol/openid-connect/auth?"+q.Encode(), http.StatusSeeOther)
}

// newRecord makes a sign-in's state, nonce and PKCE verifier, and returns
// the verifier's S256 challenge.
func (s *SignIn) newRecord(action *pendingAction) (*pendingSignin, string, error) {
	state, err := s.random(32)
	if err != nil {
		return nil, "", err
	}
	nonce, err := s.random(32)
	if err != nil {
		return nil, "", err
	}
	v, err := s.random(32)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256([]byte(v))
	rec := &pendingSignin{state: state, nonce: nonce, verifier: secret.New([]byte(v)), begin: s.d.Now(), action: action}
	return rec, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// random is n bytes from the injected randomness, base64url without
// padding.
func (s *SignIn) random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.d.Rand, b); err != nil {
		return "", fmt.Errorf("auth: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CallbackInput is what the callback read off its request.
type CallbackInput struct {
	// PendingKey is the pending cookie's value, "" when there is none.
	PendingKey string
	Query      url.Values
}

// CallbackResult is what the callback answers.
type CallbackResult struct {
	// Status is 303, or 500 when the session could not be stored.
	Status   int
	Location string
	// Cookie is the new console session's cookie value, set only when a
	// session was minted; the caller owns it and destroys it.
	Cookie secret.Value
	// Name is the signed-in account's preferred_username, for the login
	// hook; set only with Cookie.
	Name string
	// Admin reports that the minted session holds the admin role, for the
	// admin sign-in hook; set only with Cookie.
	Admin bool
}

// refusal is one callback refusal: the class logged and where the browser
// goes.
type refusal struct {
	reason   string
	location string
}

// Complete serves GET /api/auth/callback. The record is taken first, so it
// is consumed whatever the outcome; every refusal sends the browser to the
// launcher with one sentence's key and mints nothing.
func (s *SignIn) Complete(ctx context.Context, in CallbackInput) CallbackResult {
	rec := s.pending.take(in.PendingKey)
	if rec == nil {
		return CallbackResult{Status: http.StatusSeeOther, Location: signinExpired}
	}
	defer rec.destroy()
	if rec.prepared {
		s.refused(ctx, "state", "")
		return CallbackResult{Status: http.StatusSeeOther, Location: signinFailed}
	}
	claims, ref := s.verify(ctx, rec, in.Query)
	if ref != nil {
		s.refused(ctx, ref.reason, claims.Subject)
		return CallbackResult{Status: http.StatusSeeOther, Location: ref.location}
	}
	p := Principal{Sub: claims.Subject, Name: claims.PreferredUsername, Roles: claims.Roles,
		Session: SessionRef{SID: claims.SessionID, CreatedAt: s.d.Now()}}
	if rec.action != nil {
		res := s.runAction(ctx, rec, claims, p, in.Query)
		s.d.Observer.SignedIn(ctx, p.Sub)
		return res
	}
	claim := s.claim(ctx)
	cookie, claimed, err := s.d.Sessions.CreateWithClaim(ctx, p, claim)
	if err != nil {
		s.log.LogAttrs(ctx, slog.LevelError, "A console sign-in could not store its session.",
			slog.String("event", "signin.store_failed"), slog.String("sub", p.Sub), slog.String("err", err.Error()))
		return CallbackResult{Status: http.StatusInternalServerError}
	}
	if claimed {
		s.log.LogAttrs(ctx, slog.LevelInfo, "First run is over: the account created first is designated the first administrator.",
			slog.String("event", "firstrun.claimed"), slog.String("sub", claim.Sub))
	}
	s.log.LogAttrs(ctx, slog.LevelInfo, "A person signed in to the console.",
		slog.String("event", "signin.succeeded"), slog.String("sub", p.Sub))
	s.d.Observer.SignedIn(ctx, p.Sub)
	return CallbackResult{Status: http.StatusSeeOther, Location: launcherPath, Cookie: cookie, Name: p.Name,
		Admin: p.HasRole(string(authz.Admin))}
}

// claim is the first-run claim a callback tries, or nil: while first run
// holds, the realm's earliest-created person, whoever is signing in (D13:
// the first account created, not the first to finish). A first-run read
// error is not first run, and an Earliest error claims nothing; either way
// the session is minted with the roles its token carries, and a later
// callback tries again.
func (s *SignIn) claim(ctx context.Context) *Claim {
	first, err := s.d.FirstRun.FirstRun(ctx)
	if err != nil {
		s.log.LogAttrs(ctx, slog.LevelWarn, "First run could not be read, so this sign-in claims nothing.",
			slog.String("event", "firstrun.unreadable"), slog.String("err", err.Error()))
		return nil
	}
	if !first {
		return nil
	}
	sub, err := s.d.Claimer.Earliest(ctx)
	if err != nil {
		// The Admin API's error names the account in its path, so only its
		// status and kind are logged, never person data.
		attrs := []slog.Attr{slog.String("event", "firstrun.claim_aborted"), slog.String("kind", kindOf(err))}
		var ie *idclient.Error
		if errors.As(err, &ie) {
			attrs = append(attrs, slog.Int("status", ie.Status))
		}
		s.log.LogAttrs(ctx, slog.LevelWarn, "The first account could not be read, so this sign-in claims nothing.", attrs...)
		return nil
	}
	return &Claim{Sub: sub}
}

// verify runs every check of the callback in order, and returns the
// verified claims or the refusal.
func (s *SignIn) verify(ctx context.Context, rec *pendingSignin, q url.Values) (idtoken.Claims, *refusal) {
	failed := func(reason string) *refusal { return &refusal{reason: reason, location: signinFailed} }
	if q.Has("error") {
		return idtoken.Claims{}, failed("door_error")
	}
	if len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(rec.state)) != 1 {
		return idtoken.Claims{}, failed("state")
	}
	x := idclient.CodeExchange{Realm: s.d.Realm, ClientID: s.d.ClientID, Verifier: rec.verifier,
		RedirectURI: s.redirectURI(), Forward: s.d.Door.SetForwarded}
	raw, reason, err := exchangeReturn(ctx, q, s.d.Door.Issuer, x, s.d.Exchanger.ExchangeCode)
	switch {
	case reason == "code":
		return idtoken.Claims{}, failed("state")
	case reason == "exchange" && err != nil:
		s.unavailable(ctx, kindOf(err))
		return idtoken.Claims{}, &refusal{location: signinUnavailable}
	case reason != "":
		return idtoken.Claims{}, failed(reason)
	}
	defer raw.Destroy()
	c, err := s.d.Verifier.IDToken(ctx, raw)
	if err != nil {
		if errors.Is(err, idtoken.ErrUnavailable) {
			s.unavailable(ctx, "keys")
			return idtoken.Claims{}, &refusal{location: signinUnavailable}
		}
		return idtoken.Claims{}, failed("token")
	}
	switch {
	case c.Issuer != s.d.Door.Issuer:
		return c, failed("iss")
	case c.AuthorizedParty != s.d.ClientID:
		return c, failed("azp")
	case subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(rec.nonce)) != 1:
		return c, failed("nonce")
	case c.AuthTime.IsZero() || c.AuthTime.Before(rec.begin.Truncate(time.Second)):
		return c, failed("auth_time")
	case c.SessionID == "":
		return c, failed("sid")
	case c.Subject == "":
		return c, failed("sub")
	}
	return c, nil
}

// exchangeReturn is the checks a door's return shares (SignIn.verify and
// ResetDone): exactly one iss, the door's own (RFC 9207); exactly one
// non-empty code; then the exchange through ex with x, the code added. It
// returns the token, or the refusal's reason: "iss", "code" or "exchange".
// An exchange the identity service did not answer is reason "exchange" with
// its error, for the caller's unavailable record; one it refused is
// "exchange" with none.
func exchangeReturn(ctx context.Context, q url.Values, issuer string, x idclient.CodeExchange,
	ex func(context.Context, idclient.CodeExchange) (secret.Value, error)) (secret.Value, string, error) {
	if len(q["iss"]) != 1 || q.Get("iss") != issuer {
		return secret.Value{}, "iss", nil
	}
	if len(q["code"]) != 1 || q.Get("code") == "" {
		return secret.Value{}, "code", nil
	}
	x.Code = secret.New([]byte(q.Get("code")))
	defer x.Code.Destroy()
	raw, err := ex(ctx, x)
	switch {
	case err == nil:
		return raw, "", nil
	case errors.Is(err, idclient.ErrUnreachable) || errors.Is(err, idclient.ErrDenied):
		return secret.Value{}, "exchange", err
	}
	return secret.Value{}, "exchange", nil
}

// runAction runs a fresh sign-in's action when the same person signed in
// again after it began, and mints no session. The record's payload goes to
// the action; Complete destroys it afterwards. Another person's return is
// the action-failed sentence; a sign-in method's return is methodReturn,
// which reads q.
func (s *SignIn) runAction(ctx context.Context, rec *pendingSignin, c idtoken.Claims, p Principal, q url.Values) CallbackResult {
	if c.Subject != rec.action.sub {
		s.refused(ctx, "action", c.Subject)
		return CallbackResult{Status: http.StatusSeeOther, Location: signinActionFailed}
	}
	if c.AuthTime.Before(rec.begin.Truncate(time.Second)) {
		s.refused(ctx, "action", c.Subject)
		return CallbackResult{Status: http.StatusSeeOther, Location: signinFailed}
	}
	if rec.action.method != "" {
		return s.methodReturn(ctx, rec, p, q)
	}
	act, ok := s.d.Actions[rec.action.kind]
	if !ok {
		s.refused(ctx, "action", c.Subject)
		return CallbackResult{Status: http.StatusSeeOther, Location: signinFailed}
	}
	next, err := act.Run(ctx, p, rec.action.payload)
	if err != nil {
		s.log.LogAttrs(ctx, slog.LevelError, "A fresh-sign-in action failed.",
			slog.String("event", "signin.action_failed"), slog.String("kind", rec.action.kind),
			slog.String("sub", p.Sub), slog.String("err", err.Error()))
		return CallbackResult{Status: http.StatusSeeOther, Location: signinActionFailed}
	}
	return CallbackResult{Status: http.StatusSeeOther, Location: next}
}

// refused writes the one WARN record of a refused callback: its class, and
// the subject once the token has verified. Never a code, state, nonce,
// token or query.
func (s *SignIn) refused(ctx context.Context, reason, sub string) {
	attrs := []slog.Attr{slog.String("event", "signin.refused"), slog.String("reason", reason)}
	if sub != "" {
		attrs = append(attrs, slog.String("sub", sub))
	}
	s.log.LogAttrs(ctx, slog.LevelWarn, "A console sign-in was refused.", attrs...)
}

// unavailable writes the ERROR record of an exchange or key fetch the
// identity service did not answer.
func (s *SignIn) unavailable(ctx context.Context, kind string) {
	s.log.LogAttrs(ctx, slog.LevelError, "A console sign-in could not reach the sign-in service.",
		slog.String("event", "signin.exchange_failed"), slog.String("kind", kind))
}

// kindOf is an identity client error's kind name.
func kindOf(err error) string {
	switch {
	case errors.Is(err, idclient.ErrUnreachable):
		return "unreachable"
	case errors.Is(err, idclient.ErrDenied):
		return "denied"
	}
	return "other"
}

// EndSession ends the identity session sid after a sign-out. A failure is
// logged and not returned: the console's own session is already gone, and
// the identity service's idle bound ends the other (prompt=login means it
// can never be resumed).
func (s *SignIn) EndSession(ctx context.Context, sid string) {
	if err := s.d.Ender.EndSession(ctx, sid); err != nil {
		s.log.LogAttrs(ctx, slog.LevelWarn, "A sign-out could not end the person's sign-in service session; it ends at its idle limit.",
			slog.String("event", "signout.sid_not_ended"), slog.String("err", err.Error()))
	}
}

// Ready reports whether a sign-in can start now.
func (s *SignIn) Ready(ctx context.Context) bool { return s.d.Ready.Ready(ctx) == nil }

// prune drops expired pending sign-ins.
func (s *SignIn) prune() { s.pending.prune() }
