package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/idtoken"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The password reset's return (geekdojo/geekdojo-brain#992, Identity 4.10):
// each door's reset client (rasputin-reset-home, rasputin-reset-app) runs the
// realm's reset flow from the login-actions/reset-credentials entry and sends
// the browser back to GET /api/auth/reset-done with a code. ResetDone
// exchanges it, verifies the access token the answer carries (the entry's
// code yields no ID token; capability row T200), and ends every session of
// the person whose password just changed: their identity sessions, online
// and offline, and their console sessions. It mints nothing.
//
// It checks no state and no nonce: the entry takes neither, the route
// grants nothing, and only the api's own leaf can exchange a code.

// ResetDonePath is the reset clients' redirect URI path at each door.
const ResetDonePath = "/api/auth/reset-done"

// The outcomes, as the launcher's ?signin= keys.
const (
	ResetOutcomeDone       = "reset-done"
	ResetOutcomeIncomplete = "reset-incomplete"
	ResetOutcomeFailed     = "reset-failed"
)

// resetSentences are the outcomes' sentences, for the app door's page
// (the console's launcher holds the same three).
var resetSentences = map[string]string{
	ResetOutcomeDone:       "Your password is changed. Sign in with it and your second step.",
	ResetOutcomeIncomplete: "Your password is changed, but Rasputin couldn't end your other sign-ins. Ask an administrator to sign you out everywhere.",
	ResetOutcomeFailed:     "Rasputin couldn't confirm the password reset. If you chose a new password, sign in with it. Otherwise start the reset again.",
}

// ResetStartURL is door's reset start: the reset-credentials entry for
// client, returning to redirectURI. Without redirect_uri Keycloak ends the
// reset on an information page and never calls back.
func ResetStartURL(door doors.Door, client, redirectURI string) string {
	q := url.Values{"client_id": {client}, "redirect_uri": {redirectURI}}
	return door.Issuer + "/login-actions/reset-credentials?" + q.Encode()
}

// ResetExchanger exchanges a reset code for its access token
// (*idclient.Client).
type ResetExchanger interface {
	ExchangeAccessToken(ctx context.Context, x idclient.CodeExchange) (secret.Value, error)
}

// AccessVerifier verifies the reset client's access token
// (*idtoken.Verifier for the reset client at the door's issuer).
type AccessVerifier interface {
	AccessToken(ctx context.Context, raw secret.Value) (idtoken.AccessClaims, error)
}

// IdentitySessions ends a person's identity sessions (sessions.Ender, #991).
type IdentitySessions interface {
	EndAll(ctx context.Context, sub string) error
	EndOffline(ctx context.Context, sub string) (int, error)
}

// ConsoleEnder ends a person's console sessions (*ConsoleSessions).
type ConsoleEnder interface {
	EndBySub(ctx context.Context, sub string) (int64, error)
}

// ResetDoneDeps are a ResetDone's collaborators. NewResetDone refuses a
// missing one.
type ResetDoneDeps struct {
	// Door is the door whose reset client returns here; DoorName names it
	// in log records ("home" or "app").
	Door     doors.Door
	DoorName string
	// ClientID is the door's reset client, and RedirectURI its redirect URI.
	ClientID, RedirectURI string
	Realm                 string
	Exchanger             ResetExchanger
	Verifier              AccessVerifier
	Identity              IdentitySessions
	Console               ConsoleEnder
	Log                   *slog.Logger
}

// ResetDone is one door's reset return.
type ResetDone struct {
	d   ResetDoneDeps
	log *slog.Logger
}

// NewResetDone checks d and returns a ResetDone. It does no I/O.
func NewResetDone(d ResetDoneDeps) (*ResetDone, error) {
	switch {
	case d.Door.Issuer == "" || d.DoorName == "":
		return nil, errors.New("auth: ResetDoneDeps.Door or DoorName is empty")
	case d.ClientID == "" || d.RedirectURI == "" || d.Realm == "":
		return nil, errors.New("auth: ResetDoneDeps.ClientID, RedirectURI or Realm is empty")
	case d.Exchanger == nil || d.Verifier == nil || d.Identity == nil || d.Console == nil || d.Log == nil:
		return nil, errNilDep("NewResetDone")
	}
	return &ResetDone{d: d, log: d.Log.With("component", "auth")}, nil
}

// ServeHTTP answers the console's reset return: a 303 to the launcher with
// the outcome's key, and no cookie.
func (rd *ResetDone) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Each answer is a constant: nothing the request carries reaches the
	// Location.
	switch outcome, _ := rd.Finish(r.Context(), r.URL.Query()); outcome {
	case ResetOutcomeDone:
		http.Redirect(w, r, resetDoneLocation, http.StatusSeeOther)
	case ResetOutcomeIncomplete:
		http.Redirect(w, r, resetIncompleteLocation, http.StatusSeeOther)
	default:
		http.Redirect(w, r, resetFailedLocation, http.StatusSeeOther)
	}
}

// The console's answers to a reset return: the launcher with the outcome.
const (
	resetDoneLocation       = launcherPath + "?signin=" + ResetOutcomeDone
	resetIncompleteLocation = launcherPath + "?signin=" + ResetOutcomeIncomplete
	resetFailedLocation     = launcherPath + "?signin=" + ResetOutcomeFailed
)

// Finish decides one reset return from its query: the outcome's key and its
// sentence. The app door renders the sentence on its own page.
func (rd *ResetDone) Finish(ctx context.Context, q url.Values) (outcome, sentence string) {
	outcome = rd.finish(ctx, q)
	return outcome, resetSentences[outcome]
}

func (rd *ResetDone) finish(ctx context.Context, q url.Values) string {
	if q.Has("error") {
		return rd.refused(ctx, "door_error")
	}
	x := idclient.CodeExchange{Realm: rd.d.Realm, ClientID: rd.d.ClientID, NoVerifier: true,
		RedirectURI: rd.d.RedirectURI, Forward: rd.d.Door.SetForwarded}
	raw, reason, err := exchangeReturn(ctx, q, rd.d.Door.Issuer, x, rd.d.Exchanger.ExchangeAccessToken)
	switch {
	case reason == "exchange" && err != nil:
		return rd.unavailable(ctx, kindOf(err))
	case reason != "":
		return rd.refused(ctx, reason)
	}
	c, err := rd.d.Verifier.AccessToken(ctx, raw)
	raw.Destroy()
	switch {
	case errors.Is(err, idtoken.ErrUnavailable):
		return rd.unavailable(ctx, "keys")
	case err != nil:
		return rd.refused(ctx, "token")
	case c.Issuer != rd.d.Door.Issuer:
		return rd.refused(ctx, "iss")
	case c.AuthorizedParty != rd.d.ClientID:
		return rd.refused(ctx, "azp")
	case c.Subject == "":
		return rd.refused(ctx, "sub")
	}
	return rd.end(ctx, c.Subject)
}

// end ends sub's sessions with #991's primitives, in its sign_out order:
// online identity sessions and the not-before, offline sessions, console
// sessions. A step that fails is recorded and the rest still run, so as
// many sessions as possible end.
func (rd *ResetDone) end(ctx context.Context, sub string) string {
	failed := false
	fail := func(step string, err error) {
		failed = true
		rd.log.LogAttrs(ctx, slog.LevelError, "A password was reset, but some of the person's sessions could not be ended.",
			slog.String("event", "reset.sessions_not_ended"), slog.String("sub", sub), slog.String("door", rd.d.DoorName),
			slog.String("step", step), slog.String("err", err.Error()))
	}
	if err := rd.d.Identity.EndAll(ctx, sub); err != nil {
		fail("online_sessions", err)
	}
	if _, err := rd.d.Identity.EndOffline(ctx, sub); err != nil {
		fail("offline_sessions", err)
	}
	if _, err := rd.d.Console.EndBySub(ctx, sub); err != nil {
		fail("console_sessions", err)
	}
	if failed {
		return ResetOutcomeIncomplete
	}
	rd.log.LogAttrs(ctx, slog.LevelInfo, "A password was reset and the person's sessions ended.",
		slog.String("event", "reset.done"), slog.String("sub", sub), slog.String("door", rd.d.DoorName))
	return ResetOutcomeDone
}

// refused writes the WARN record of a refused return: its class and door,
// never a code, token or query.
func (rd *ResetDone) refused(ctx context.Context, reason string) string {
	rd.log.LogAttrs(ctx, slog.LevelWarn, "A password reset's return was refused.",
		slog.String("event", "reset.refused"), slog.String("reason", reason), slog.String("door", rd.d.DoorName))
	return ResetOutcomeFailed
}

// unavailable writes the ERROR record of an exchange or key fetch the
// identity service did not answer.
func (rd *ResetDone) unavailable(ctx context.Context, kind string) string {
	rd.log.LogAttrs(ctx, slog.LevelError, "A password reset's return could not reach the sign-in service.",
		slog.String("event", "reset.exchange_failed"), slog.String("kind", kind), slog.String("door", rd.d.DoorName))
	return ResetOutcomeFailed
}
