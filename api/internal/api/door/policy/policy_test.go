package policy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// closedNetwork refuses every registration: its facts and its count can't
// be read.
type closedNetwork struct{}

var errClosed = errors.New("closed")

func (closedNetwork) Facts(context.Context) (NetworkFacts, error) { return NetworkFacts{}, errClosed }
func (closedNetwork) Full(context.Context) (bool, error)          { return false, errClosed }

// noEmails holds no email.
type noEmails struct{}

func (noEmails) EmailInUse(context.Context, string) (bool, error) { return false, nil }

type okReady struct{}

func (okReady) Ready(context.Context) error { return nil }

// TC-985-34: New refuses every missing collaborator.
func TestNew_RefusesMissing(t *testing.T) {
	th, _ := newThrottle(t)
	good := Deps{Table: table(t), Readiness: okReady{}, Throttle: th, AppClients: NoAppClients{}, Actions: NoActionsIssued{},
		Network: closedNetwork{}, Waiting: closedNetwork{}, Removed: noneRemoved{}, Emails: noEmails{}, Now: time.Now}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Deps){
		"Table": func(d *Deps) { d.Table.App.Clients = nil }, "Readiness": func(d *Deps) { d.Readiness = nil },
		"Throttle": func(d *Deps) { d.Throttle = nil }, "AppClients": func(d *Deps) { d.AppClients = nil },
		"Actions": func(d *Deps) { d.Actions = nil }, "Network": func(d *Deps) { d.Network = nil },
		"Waiting": func(d *Deps) { d.Waiting = nil }, "Now": func(d *Deps) { d.Now = nil },
		"Removed": func(d *Deps) { d.Removed = nil }, "Emails": func(d *Deps) { d.Emails = nil },
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
