package storage

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const routeListener = "https://c.local:8443"

// TC-514-09, TC-516-03: the router's rule, in its stated order, for both
// directions. Every node that cannot take the node listener is an error that
// names it; only a capable node with an agent key gets a destination.
func TestTransferRouterRule(t *testing.T) {
	readErr := errors.New("disk on fire")
	keysErr := errors.New("keys table locked")
	wantIngest, err := backupxfer.IngestDestination(routeListener)
	if err != nil {
		t.Fatal(err)
	}
	wantEgress, err := backupxfer.EgressDestination(routeListener)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		reader   *fakeRouteNodes
		listener string
		ok       bool     // a destination, not an error
		wantErr  []string // substrings the error carries
		wrapped  error    // an error the error wraps
	}{
		{
			name:     "capable, agent key, listener",
			reader:   (&fakeRouteNodes{}).capable("A", agentKeys()),
			listener: routeListener,
			ok:       true,
		},
		{
			name: "not capable; its keys are never read",
			reader: func() *fakeRouteNodes {
				f := (&fakeRouteNodes{}).predates("A", "2026.09.5")
				f.keysErr = keysErr
				return f
			}(),
			listener: routeListener,
			wantErr:  []string{"node A", "2026.09.5", "predates key-bound transfer", "update the node"},
			wrapped:  ErrAgentPredatesKeyBoundTransfer,
		},
		{
			name:     "capable, no listener",
			reader:   (&fakeRouteNodes{}).capable("A", agentKeys()),
			listener: "",
			wantErr:  []string{"node A", "RASPUTIN_HTTPS_ADDR"},
			wrapped:  ErrNoNodeListener,
		},
		{
			name:     "not capable, no listener: the listener is named first",
			reader:   (&fakeRouteNodes{}).predates("A", "2026.09.5"),
			listener: "",
			wantErr:  []string{"node A", "RASPUTIN_HTTPS_ADDR"},
			wrapped:  ErrNoNodeListener,
		},
		{
			name:     "capable, listener, only a collector key",
			reader:   (&fakeRouteNodes{}).capable("A", proto.NodeKeys{proto.NodeKeyCollector: "spki-collector"}),
			listener: routeListener,
			wantErr:  []string{"node A", "no registered agent key"},
		},
		{
			name: "capable, listener, key read fails",
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
			name:     "absent",
			reader:   &fakeRouteNodes{absent: map[string]bool{"A": true}},
			listener: routeListener,
			wantErr:  []string{"node A", "not in inventory"},
		},
		{
			name:     "node read fails",
			reader:   &fakeRouteNodes{getErr: readErr},
			listener: routeListener,
			wantErr:  []string{"node A"},
			wrapped:  readErr,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := NewTransferRouter(c.reader, c.listener)
			if err != nil {
				t.Fatal(err)
			}
			for dir, d := range map[string]struct {
				ask  func(context.Context, string) (string, error)
				want string
			}{"ingest": {r.Ingest, wantIngest}, "egress": {r.Egress, wantEgress}} {
				got, err := d.ask(context.Background(), "A")
				if c.ok {
					if err != nil || got != d.want {
						t.Errorf("%s: %q, %v; want %q", dir, got, err, d.want)
					}
					continue
				}
				if err == nil {
					t.Fatalf("%s: destination %q, want an error", dir, got)
				}
				if got != "" {
					t.Errorf("%s: an error came with a destination %q", dir, got)
				}
				for _, sub := range c.wantErr {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("%s: error %q lacks %q", dir, err, sub)
					}
				}
				if c.wrapped != nil && !errors.Is(err, c.wrapped) {
					t.Errorf("%s: error %q does not wrap %v", dir, err, c.wrapped)
				}
			}
		})
	}
}

// TC-514-10, TC-516-04: the constructor refuses a nil reader and an
// unparseable node-listener base, and builds over an empty base a router
// whose every route call errors.
func TestNewTransferRouterRefuses(t *testing.T) {
	if r, err := NewTransferRouter(nil, routeListener); err == nil || r != nil {
		t.Errorf("nil reader: router %v, err %v", r, err)
	}
	if r, err := NewTransferRouter(&fakeRouteNodes{}, "::not a url"); err == nil || r != nil {
		t.Errorf("bad node-listener base: router %v, err %v", r, err)
	}
	r, err := NewTransferRouter((&fakeRouteNodes{}).capable("A", agentKeys()), "")
	if err != nil || r == nil {
		t.Fatalf("empty base: router %v, err %v; want a router", r, err)
	}
	for dir, ask := range map[string]func(context.Context, string) (string, error){"ingest": r.Ingest, "egress": r.Egress} {
		if got, err := ask(context.Background(), "A"); err == nil || got != "" {
			t.Errorf("empty base, %s: %q, %v; want an error", dir, got, err)
		}
	}
}

// TC-514-26, TC-516-07: over the real inventory store, a node whose
// registration drops the capability (an A/B fallback to an older agent) is
// refused by name on its next route call, and handed no destination. The
// capability write is the one registration makes (inventory/service.go:
// existing.Capabilities = ev.Capabilities, then Store.Update).
func TestTransferRouterFollowsAFallbackToAnOlderAgent(t *testing.T) {
	ctx := context.Background()
	inv := newInventory(t)
	n := &proto.Node{ID: "A", Role: proto.RoleCompute, Hostname: "a.test", AgentVersion: "2026.09.6", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
		Capabilities: []string{proto.CapabilityKeyBoundTransfer}}
	if err := inv.Insert(ctx, n); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.SetNodeKeys(ctx, "A", proto.NodeKeys{proto.NodeKeyAgent: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	r, err := NewTransferRouter(inv, routeListener)
	if err != nil {
		t.Fatal(err)
	}
	before, err := r.Ingest(ctx, "A")
	if err != nil || before != routeListener+backupxfer.IngestPathPrefix {
		t.Fatalf("before the fallback: %q, %v", before, err)
	}

	n.Capabilities = nil
	n.AgentVersion = "2026.09.5"
	if err := inv.Update(ctx, n); err != nil {
		t.Fatal(err)
	}
	after, err := r.Ingest(ctx, "A")
	if !errors.Is(err, ErrAgentPredatesKeyBoundTransfer) || after != "" {
		t.Fatalf("after the fallback: %q, %v; want no destination and the predates error", after, err)
	}
	if !strings.Contains(err.Error(), "2026.09.5") {
		t.Errorf("error %q does not name the agent version", err)
	}
}

// TC-516-16: a step-1 result written by the previous release, which recorded
// "keyBound", still decodes, and every other field round-trips.
func TestRestoreAppTargetDecodesAPreviousReleasesResult(t *testing.T) {
	const prev = `{"restoreId":"rs-0123456789abcdef","appId":"app-vw","appName":"vaultwarden","tileId":"vaultwarden","nodeId":"n1",` +
		`"partUuid":"part-1","sourceLabel":"backup-a","generationId":"20260903T120000Z-JOB12345-full","generationCreatedAt":"2026-09-03T12:00:00Z",` +
		`"clusterId":"c1","keyId":"key-1","scope":"full","complete":true,"manifestVersion":2,"matchedBy":"app-id",` +
		`"source":"https://c.local:8443/api/backup/egress/","keyBound":true,` +
		`"restore":[{"volume":"vaultwarden-data","class":"critical","member":"volumes/vaultwarden/vaultwarden-data.rasputin-archive",` +
		`"sizeBytes":4096,"sha256":"aa","sealedSha256":"bb","sealedSizeBytes":5000,"fileCount":3,"capturedFrom":"n1","consistency":"clean-shutdown"}],"skipped":[]}`
	var got restoreAppTarget
	if err := json.Unmarshal([]byte(prev), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	back, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var want, again map[string]any
	if err := json.Unmarshal([]byte(prev), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(back, &again); err != nil {
		t.Fatal(err)
	}
	delete(want, "keyBound")
	if !reflect.DeepEqual(want, again) {
		t.Fatalf("round trip lost a field:\n got  %v\n want %v", again, want)
	}
}
