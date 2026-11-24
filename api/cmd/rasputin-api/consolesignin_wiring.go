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

// consoleInputs are the console client's URLs converge writes.
type consoleInputs struct {
	redirectURIs map[string][]string
	backchannel  map[string]string
}

// consoleConvergeInputs is the console client's redirect URI and back-channel
// URL while the doors are on, and none otherwise: a client with neither can
// never complete a sign-in, which is the closed state.
func consoleConvergeInputs(doorsOn bool, host string) consoleInputs {
	if !doorsOn || host == "" {
		return consoleInputs{redirectURIs: map[string][]string{}, backchannel: map[string]string{}}
	}
	return consoleInputs{
		redirectURIs: map[string][]string{flows.ConsoleClient: {"https://" + host + consoleCallbackPath}},
		backchannel:  map[string]string{flows.ConsoleClient: consoleBackchannelURL},
	}
}

// codeClient is the identity client the sign-in exchanges codes and fetches
// keys through: *idclient.Client, and Disabled, which refuses both.
type codeClient interface {
	auth.Exchanger
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
	now      func() time.Time
	log      *slog.Logger
}

// consoleSignIn is what consoleSignInWiring built: the sign-in, and the
// role-change sink for the sign-in history drain. Both are nil when nothing
// is built.
type consoleSignIn struct {
	signIn *auth.SignIn
	sink   *auth.RoleChangeSink
}

// adminSinks are the drain sinks the console adds to sinks.
func (w consoleSignIn) adminSinks(sinks convergeSinks) convergeSinks {
	if w.sink != nil {
		sinks.admin = append(append([]events.AdminSink(nil), sinks.admin...), w.sink)
	}
	return sinks
}

// install sets the sign-in on the auth service when one was built.
func (w consoleSignIn) install(svc interface{ SetSignIn(*auth.SignIn) }) {
	if w.signIn != nil {
		svc.SetSignIn(w.signIn)
	}
}

// consoleSignInWiring builds the sign-in under keycloak with the doors on.
// It does no I/O. An error is a programming error, which main treats as
// fatal.
func consoleSignInWiring(ctx context.Context, d consoleSignInDeps) (consoleSignIn, error) {
	if d.mode != identityModeKeycloak || !d.doorsOn {
		return consoleSignIn{}, nil
	}
	if d.client == nil || d.session == nil || d.ready == nil || d.sessions == nil || d.now == nil || d.log == nil || d.host == "" {
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
		Sessions: d.sessions, Actions: nil, Now: d.now, Rand: rand.Reader, Log: d.log,
	})
	if err != nil {
		return consoleSignIn{}, fmt.Errorf("console sign-in: %w", err)
	}
	sink, err := auth.NewRoleChangeSink(d.sessions, d.log)
	if err != nil {
		return consoleSignIn{}, fmt.Errorf("console sign-in: %w", err)
	}
	d.log.InfoContext(ctx, "console sign-in wired", "component", "auth", "issuer", home.Issuer, "console", d.host)
	return consoleSignIn{signIn: si, sink: sink}, nil
}
