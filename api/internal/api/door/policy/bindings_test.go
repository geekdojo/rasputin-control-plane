package policy

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type pausedSet map[string]bool

func (p pausedSet) ClientPaused(c string) bool { return p[c] }

type someApps map[string]bool

func (a someApps) AppClient(_ context.Context, id string) (AppClient, bool, error) {
	return AppClient{}, a[id], nil
}

// TC-987-33: a paused client's authorization request answers 503 with its
// sentence and reason; its other routes, and other clients, are unaffected;
// with no Bindings no client is paused.
func TestCheck_PausedClient(t *testing.T) {
	th, _ := newThrottle(t)
	deps := Deps{Table: table(t), Readiness: okReady{}, Throttle: th, AppClients: someApps{"strict": true, "plain": true},
		Actions: NoActionsIssued{}, Network: RegistrationClosed{}, Waiting: RegistrationClosed{}, Now: time.Now,
		Bindings: pausedSet{"strict": true}}
	svc, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	auth := func(client string) Request {
		return Request{Door: App, Route: RouteAuth, Method: http.MethodGet, ClientIDs: []string{client},
			Params: map[string][]string{"response_type": {"code"}}}
	}
	d := svc.Check(context.Background(), auth("strict"))
	if d.Allow || d.Status != http.StatusServiceUnavailable || d.Reason != ReasonClientPaused ||
		d.Sentence != "Signing in to this app is paused because its sign-in settings changed. An administrator can see why in Rasputin's alerts." {
		t.Errorf("paused client: %+v", d)
	}
	if d := svc.Check(context.Background(), auth("plain")); !d.Allow {
		t.Errorf("an unpaused client was refused: %+v", d)
	}
	tok := Request{Door: App, Route: RouteToken, Method: http.MethodPost, ClientIDs: []string{"strict"},
		Params: map[string][]string{"grant_type": {"authorization_code"}}}
	if d := svc.Check(context.Background(), tok); d.Reason == ReasonClientPaused {
		t.Errorf("the token route was paused: %+v", d)
	}
	deps.Bindings = nil
	open, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	if d := open.Check(context.Background(), auth("strict")); !d.Allow {
		t.Errorf("with no Bindings a client was refused: %+v", d)
	}
}
