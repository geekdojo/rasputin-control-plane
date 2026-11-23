package policy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type okReady struct{}

func (okReady) Ready(context.Context) error { return nil }

// TC-985-34: New refuses every missing collaborator.
func TestNew_RefusesMissing(t *testing.T) {
	th, _ := newThrottle(t)
	good := Deps{Table: table(t), Readiness: okReady{}, Throttle: th, AppClients: NoAppClients{}, Actions: NoActionsIssued{},
		Network: RegistrationClosed{}, Waiting: RegistrationClosed{}, Now: time.Now}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Deps){
		"Table": func(d *Deps) { d.Table.App.Clients = nil }, "Readiness": func(d *Deps) { d.Readiness = nil },
		"Throttle": func(d *Deps) { d.Throttle = nil }, "AppClients": func(d *Deps) { d.AppClients = nil },
		"Actions": func(d *Deps) { d.Actions = nil }, "Network": func(d *Deps) { d.Network = nil },
		"Waiting": func(d *Deps) { d.Waiting = nil }, "Now": func(d *Deps) { d.Now = nil },
	} {
		d := good
		mut(&d)
		if _, err := New(d); err == nil {
			t.Errorf("New with no %s succeeded", name)
		}
	}
}

// The fail-closed collaborators wired until their producers land refuse.
func TestFailClosedCollaborators(t *testing.T) {
	ctx := context.Background()
	if _, ok, err := (NoAppClients{}).AppClient(ctx, "immich"); ok || err != nil {
		t.Error("NoAppClients holds a client")
	}
	if ok, err := (NoActionsIssued{}).Issued(ctx, ActionRequest{Client: ConsoleClient, Action: "UPDATE_PASSWORD"}); ok || err != nil {
		t.Error("NoActionsIssued issued an action")
	}
	if _, err := (RegistrationClosed{}).Facts(ctx); !errors.Is(err, ErrRegistrationClosed) {
		t.Error("RegistrationClosed gave network facts")
	}
	if _, err := (RegistrationClosed{}).Full(ctx); !errors.Is(err, ErrRegistrationClosed) {
		t.Error("RegistrationClosed gave a waiting count")
	}
	if (NetworkFacts{HomeSubnets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}).AdmitsRegistration(netip.Addr{}) {
		t.Error("an address that did not parse admits registration")
	}
	if !(NetworkFacts{HomeSubnets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}).AdmitsRegistration(netip.MustParseAddr("::ffff:192.0.2.4")) {
		t.Error("an IPv4-mapped home address does not admit registration")
	}
	if Kind(9).String() != "unknown" || Home.String() != "home" || App.String() != "app" {
		t.Error("door names")
	}
}
