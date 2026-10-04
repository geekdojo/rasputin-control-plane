package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

const (
	routePublic   = "https://cp.test"
	routeListener = "https://c.local:8443"
)

// TC-514-09: the router's rule, in its stated order, for both directions.
func TestTransferRouterRule(t *testing.T) {
	readErr := errors.New("disk on fire")
	keysErr := errors.New("keys table locked")
	cases := []struct {
		name     string
		reader   *fakeRouteNodes
		listener string
		// want is a route; wantErr is the substrings an error must carry.
		want    *TransferRoute
		egress  string
		wantErr []string
		wrapped error
	}{
		{
			name:     "(a) capable, agent key, listener",
			reader:   (&fakeRouteNodes{}).capable("A", agentKeys()),
			listener: routeListener,
			want:     &TransferRoute{Destination: routeListener + "/api/backup/ingest/", KeyBound: true},
			egress:   routeListener + "/api/backup/egress/",
		},
		{
			name:     "(b) not capable; a key-read error has no effect",
			reader:   &fakeRouteNodes{keysErr: keysErr},
			listener: routeListener,
			want:     &TransferRoute{Destination: routePublic + "/api/backup/ingest/", Why: "agent predates key-bound transfer"},
			egress:   routePublic + "/api/backup/egress/",
		},
		{
			name:     "(c) capable, no listener",
			reader:   (&fakeRouteNodes{}).capable("A", agentKeys()),
			listener: "",
			want:     &TransferRoute{Destination: routePublic + "/api/backup/ingest/", Why: "this api has no node listener"},
			egress:   routePublic + "/api/backup/egress/",
		},
		{
			name:     "(d) capable, listener, only a collector key",
			reader:   (&fakeRouteNodes{}).capable("A", proto.NodeKeys{proto.NodeKeyCollector: "spki-collector"}),
			listener: routeListener,
			wantErr:  []string{"node A", "no registered agent key"},
		},
		{
			name: "(e) capable, listener, key read fails",
			reader: func() *fakeRouteNodes {
				f := (&fakeRouteNodes{}).capable("A", agentKeys())
				f.keysErr = keysErr
				return f
			}(),
			listener: routeListener,
			wantErr:  []string{"node A"},
			wrapped:  keysErr,
		},
		{
			name:     "(f) absent",
			reader:   &fakeRouteNodes{absent: map[string]bool{"A": true}},
			listener: routeListener,
			wantErr:  []string{"node A", "not in inventory"},
		},
		{
			name:     "(g) node read fails",
			reader:   &fakeRouteNodes{getErr: readErr},
			listener: routeListener,
			wantErr:  []string{"node A"},
			wrapped:  readErr,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := NewTransferRouter(c.reader, routePublic, c.listener)
			if err != nil {
				t.Fatal(err)
			}
			for dir, ask := range map[string]func(context.Context, string) (TransferRoute, error){"ingest": r.Ingest, "egress": r.Egress} {
				got, err := ask(context.Background(), "A")
				if c.want == nil {
					if err == nil {
						t.Fatalf("%s: route %+v, want an error", dir, got)
					}
					if got.Destination != "" {
						t.Errorf("%s: an error came with a destination %q", dir, got.Destination)
					}
					for _, sub := range c.wantErr {
						if !strings.Contains(err.Error(), sub) {
							t.Errorf("%s: error %q lacks %q", dir, err, sub)
						}
					}
					if c.wrapped != nil && !errors.Is(err, c.wrapped) {
						t.Errorf("%s: error %q does not wrap %v", dir, err, c.wrapped)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", dir, err)
				}
				want := *c.want
				if dir == "egress" {
					want.Destination = c.egress
				}
				if got.Destination != want.Destination || got.KeyBound != want.KeyBound || !strings.Contains(got.Why, want.Why) || (want.Why == "") != (got.Why == "") {
					t.Errorf("%s: route %+v, want %+v", dir, got, want)
				}
			}
		})
	}
}

// TC-514-10: the constructor refuses what it cannot route with.
func TestNewTransferRouterRefuses(t *testing.T) {
	if r, err := NewTransferRouter(nil, routePublic, routeListener); err == nil || r != nil {
		t.Errorf("nil reader: router %v, err %v", r, err)
	}
	if r, err := NewTransferRouter(&fakeRouteNodes{}, "::not a url", routeListener); err == nil || r != nil {
		t.Errorf("bad public base: router %v, err %v", r, err)
	}
	if r, err := NewTransferRouter(&fakeRouteNodes{}, routePublic, "::not a url"); err == nil || r != nil {
		t.Errorf("bad node-listener base: router %v, err %v", r, err)
	}
}

// TC-514-26: over the real inventory store, a node whose registration drops
// the capability (an A/B fallback to an older agent) routes by bearer again.
// The capability write is the one registration makes (inventory/service.go:
// existing.Capabilities = ev.Capabilities, then Store.Update).
func TestTransferRouterFollowsAFallbackToAnOlderAgent(t *testing.T) {
	ctx := context.Background()
	inv := newInventory(t)
	n := &proto.Node{ID: "A", Role: proto.RoleCompute, Hostname: "a.test", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
		Capabilities: []string{proto.CapabilityKeyBoundTransfer}}
	if err := inv.Insert(ctx, n); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.SetNodeKeys(ctx, "A", proto.NodeKeys{proto.NodeKeyAgent: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	r, err := NewTransferRouter(inv, routePublic, routeListener)
	if err != nil {
		t.Fatal(err)
	}
	before, err := r.Ingest(ctx, "A")
	if err != nil || !before.KeyBound || before.Destination != routeListener+"/api/backup/ingest/" {
		t.Fatalf("before the fallback: %+v, %v", before, err)
	}

	n.Capabilities = nil
	if err := inv.Update(ctx, n); err != nil {
		t.Fatal(err)
	}
	after, err := r.Ingest(ctx, "A")
	if err != nil {
		t.Fatal(err)
	}
	if after.KeyBound || after.Destination != routePublic+"/api/backup/ingest/" || after.Why != "agent predates key-bound transfer" {
		t.Fatalf("after the fallback: %+v", after)
	}
}
