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
// with nil Bindings an app client outside the door table is paused and the
// door table's own clients are not.
func TestCheck_PausedClient(t *testing.T) {
	th, _ := newThrottle(t)
	deps := Deps{Table: table(t), Readiness: okReady{}, Throttle: th, AppClients: someApps{"strict": true, "plain": true},
		Actions: NoActionsIssued{}, Network: closedNetwork{}, Waiting: closedNetwork{}, Removed: noneRemoved{}, Emails: noEmails{}, Now: time.Now,
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
	for _, c := range []string{"strict", "plain"} {
		if d := open.Check(context.Background(), auth(c)); d.Allow || d.Reason != ReasonClientPaused {
			t.Errorf("with nil Bindings app client %q was not paused: %+v", c, d)
		}
	}
	for _, door := range []struct {
		kind    Kind
		clients []string
	}{{Home, deps.Table.Home.Clients}, {App, deps.Table.App.Clients}} {
		for _, c := range door.clients {
			r := Request{Door: door.kind, Route: RouteAuth, Method: http.MethodGet, ClientIDs: []string{c},
				Params: map[string][]string{"response_type": {"code"}}}
			if d := open.Check(context.Background(), r); d.Reason == ReasonClientPaused {
				t.Errorf("with nil Bindings door-table client %q was paused: %+v", c, d)
			}
		}
	}
}
