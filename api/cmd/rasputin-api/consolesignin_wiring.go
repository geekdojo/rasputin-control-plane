package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/idtoken"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// The console's sign-in through the home door (geekdojo/geekdojo-brain#989,
// Identity 4.7): built here only when the identity service is keycloak, the
// doors are on and the api's Admin API session exists. Otherwise nothing is
// built: /api/auth/signin answers unavailable, status says ready:false, and
// no session can be minted, so every gated route answers 401.

const (
	// consoleCallbackPath is the console client's one redirect URI's path.
	consoleCallbackPath = "/api/auth/callback"
	// consoleBackchannelURL is where the identity service posts a logout
	// token: the api's own https listener on loopback, which keycloak.service
	// reaches and trusts (the api leaf names 127.0.0.1).
	consoleBackchannelURL = "https://127.0.0.1/api/identity/backchannel/" + flows.ConsoleClient
)

// consoleHost is the console's own name, <cluster-id>.local, or "" on a
// box with no cluster id. The sign-in's redirect URI, converge's console
// origin and the doors' link back to the console all derive from it.
func consoleHost() string { return clusterHostname() }

// The reset clients (geekdojo/geekdojo-brain#992): each door's own.
const (
	resetHomeClient = "rasputin-reset-home"
	resetAppClient  = "rasputin-reset-app"
)

// consoleInputs are the console's and the reset clients' URLs converge
// writes.
type consoleInputs struct {
	redirectURIs map[string][]string
	backchannel  map[string]string
	// resetHome and resetApp are each door's reset start, which the sign-in
	// pages link "Forgot your password?" to.
	resetHome, resetApp string
}

// resetReturns are each reset client's one redirect URI: the home door's
// return to the console's name, the app door's to its own.
func resetReturns(table doors.Table, host string) (home, app string) {
	return "https://" + host + auth.ResetDonePath, "https://" + table.App.Host + auth.ResetDonePath
}

// consoleConvergeInputs is the console client's redirect URI and back-channel
// URL, and the reset clients' redirect URIs and starts, while the doors are
// on, and none otherwise: a client with neither can never complete a
// sign-in or a reset, which is the closed state.
func consoleConvergeInputs(doorsOn bool, host string, table doors.Table) consoleInputs {
	if !doorsOn || host == "" {
		return consoleInputs{redirectURIs: map[string][]string{}, backchannel: map[string]string{}}
	}
	home, app := resetReturns(table, host)
	return consoleInputs{
		redirectURIs: map[string][]string{
			flows.ConsoleClient: {"https://" + host + consoleCallbackPath},
			resetHomeClient:     {home},
			resetAppClient:      {app},
		},
		backchannel: map[string]string{flows.ConsoleClient: consoleBackchannelURL},
		resetHome:   auth.ResetStartURL(table.Home, resetHomeClient, home),
		resetApp:    auth.ResetStartURL(table.App, resetAppClient, app),
	}
}

// codeClient is the identity client the sign-in exchanges codes and fetches
// keys through: *idclient.Client, and Disabled, which refuses both.
type codeClient interface {
	auth.Exchanger
	auth.ResetExchanger
	Forwarding(forward func(http.Header)) *http.Client
}

// adminSession is the api's Admin API session (*idclient.Session).
type adminSession interface {
	Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error)
}

// sidEnder ends an identity session through the Admin API.
type sidEnder struct{ session adminSession }

func (e sidEnder) EndSession(ctx context.Context, sid string) error {
	if sid == "" {
		return errors.New("no session id to end")
	}
	_, err := e.session.Admin(ctx, http.MethodDelete, "/admin/realms/"+identityRealm+"/sessions/"+url.PathEscape(sid), nil, nil)
	return err
}

// consoleSignInDeps is what the wiring takes from main.
type consoleSignInDeps struct {
	mode     string
	doorsOn  bool
	table    doors.Table
	host     string
	client   codeClient
	session  adminSession
	ready    auth.Readiness
	sessions *auth.ConsoleSessions
	// identity ends a person's identity sessions after a reset (#991's
	// sessions.Ender); actions are the fresh-sign-in actions by kind (#992's
	// accounts.reset_password).
	identity auth.IdentitySessions
	actions  map[string]auth.Action
	// firstRun is the first-run predicate (authStore); claimer and observer
	// are the accounts wiring's first account and designation observer
	// (#990).
	firstRun auth.FirstRunner
	claimer  auth.Claimer
	observer auth.Observer
	now      func() time.Time
	log      *slog.Logger
}

// consoleSignIn is what consoleSignInWiring built: the sign-in, and the
// role-change sink for the sign-in history drain. Both are nil when nothing
// is built.
type consoleSignIn struct {
	signIn *auth.SignIn
	sink   *auth.RoleChangeSink
	// resetHome is the console's reset return and resetApp the app door's
	// (geekdojo/geekdojo-brain#992).
	resetHome, resetApp *auth.ResetDone
}

// adminSinks are the drain sinks the console adds to sinks.
func (w consoleSignIn) adminSinks(sinks convergeSinks) convergeSinks {
	if w.sink != nil {
		sinks.admin = append(append([]events.AdminSink(nil), sinks.admin...), w.sink)
	}
	return sinks
}

// install sets the sign-in and the console's reset return on the auth
// service when they were built.
func (w consoleSignIn) install(svc interface {
	SetSignIn(*auth.SignIn)
	SetResetDone(*auth.ResetDone)
}) {
	if w.signIn != nil {
		svc.SetSignIn(w.signIn)
		svc.SetResetDone(w.resetHome)
	}
}

// appResetDone is the app door's reset return, or nil when none was built
// (the doors then refuse to build, which keeps them closed).
func (w consoleSignIn) appResetDone() door.ResetDone {
	if w.resetApp == nil {
		return nil
	}
	return w.resetApp
}

// consoleSignInWiring builds the sign-in under keycloak with the doors on.
// It does no I/O. An error is a programming error, which main treats as
// fatal.
func consoleSignInWiring(ctx context.Context, d consoleSignInDeps) (consoleSignIn, error) {
	if d.mode != identityModeKeycloak || !d.doorsOn {
		return consoleSignIn{}, nil
	}
	if d.client == nil || d.session == nil || d.ready == nil || d.sessions == nil || d.identity == nil || d.now == nil || d.log == nil || d.host == "" ||
		d.firstRun == nil || d.claimer == nil || d.observer == nil {
		return consoleSignIn{}, errors.New("console sign-in: a collaborator is nil under keycloak with the doors on")
	}
	home := d.table.Home
	verifier, err := idtoken.New(ctx, home.Issuer, flows.ConsoleClient, d.client.Forwarding(home.SetForwarded), d.now)
	if err != nil {
		return consoleSignIn{}, fmt.Errorf("console sign-in: %w", err)
	}
	si, err := auth.NewSignIn(auth.SignInDeps{
		Door: home, ConsoleHost: d.host, ClientID: flows.ConsoleClient, Realm: identityRealm,
		Exchanger: d.client, Verifier: verifier, Ender: sidEnder{session: d.session}, Ready: d.ready,
		Sessions: d.sessions, FirstRun: d.firstRun, Claimer: d.claimer, Observer: d.observer,
		Actions: d.actions, Now: d.now, Rand: rand.Reader, Log: d.log,
	})
	if err != nil {
		return consoleSignIn{}, fmt.Errorf("console sign-in: %w", err)
	}
	homeReturn, appReturn := resetReturns(d.table, d.host)
	resetHome, err := d.resetDone(ctx, d.table.Home, "home", resetHomeClient, homeReturn)
	if err != nil {
		return consoleSignIn{}, err
	}
	resetApp, err := d.resetDone(ctx, d.table.App, "app", resetAppClient, appReturn)
	if err != nil {
		return consoleSignIn{}, err
	}
	sink, err := auth.NewRoleChangeSink(d.sessions, d.log)
	if err != nil {
		return consoleSignIn{}, fmt.Errorf("console sign-in: %w", err)
	}
	d.log.InfoContext(ctx, "console sign-in wired", "component", "auth", "issuer", home.Issuer, "console", d.host)
	return consoleSignIn{signIn: si, sink: sink, resetHome: resetHome, resetApp: resetApp}, nil
}

// resetDone is one door's reset return, with its own verifier: the door's
// issuer and its reset client, its keys fetched over the door's forwarding.
func (d consoleSignInDeps) resetDone(ctx context.Context, door doors.Door, name, client, redirect string) (*auth.ResetDone, error) {
	v, err := idtoken.New(ctx, door.Issuer, client, d.client.Forwarding(door.SetForwarded), d.now)
	if err != nil {
		return nil, fmt.Errorf("reset return (%s): %w", name, err)
	}
	rd, err := auth.NewResetDone(auth.ResetDoneDeps{Door: door, DoorName: name, ClientID: client, RedirectURI: redirect,
		Realm: identityRealm, Exchanger: d.client, Verifier: v, Identity: d.identity, Console: d.sessions, Log: d.log})
	if err != nil {
		return nil, fmt.Errorf("reset return (%s): %w", name, err)
	}
	return rd, nil
}
