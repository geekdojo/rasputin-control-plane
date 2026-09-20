package alerts

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func nodeKeyService(t *testing.T) (*Service, *Store) {
	t.Helper()
	ctx := context.Background()
	store, err := OpenStore(ctx, filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return &Service{store: store}, store
}

func change(node, was, now string) inventory.NodeKeyChange {
	return inventory.NodeKeyChange{
		NodeID:   node,
		Previous: proto.NodeKeys{proto.NodeKeyAgent: was},
		Current:  proto.NodeKeys{proto.NodeKeyAgent: now},
		Replaced: []proto.NodeKeyPurpose{proto.NodeKeyAgent},
	}
}

// A replaced key raises a crit alert filed under the security source, naming
// the node and both key hashes.
func TestRaiseNodeKeyChanged(t *testing.T) {
	ctx := context.Background()
	svc, _ := nodeKeyService(t)
	if err := svc.RaiseNodeKeyChanged(ctx, change("c1", "sha256/old", "sha256/new")); err != nil {
		t.Fatal(err)
	}
	got, err := svc.ruleAlerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d alerts, want 1: %+v", len(got), got)
	}
	a := got[0]
	if a.Severity != proto.AlertCrit {
		t.Errorf("severity = %q, want crit", a.Severity)
	}
	if a.Source != proto.AlertSourceSecurity {
		t.Errorf("source = %q, want security", a.Source)
	}
	if a.RelatedKind != "node" || a.RelatedID != "c1" {
		t.Errorf("related = %s/%s, want node/c1", a.RelatedKind, a.RelatedID)
	}
	if !strings.Contains(a.Title, "c1") {
		t.Errorf("title does not name the node: %q", a.Title)
	}
	if !strings.Contains(a.Detail, "reflash") || !strings.Contains(a.Detail, "revoke") {
		t.Errorf("detail says neither reading: %q", a.Detail)
	}
}

// A first registration is not a change, so there is nothing to raise.
func TestRaiseNodeKeyChanged_NothingReplaced(t *testing.T) {
	ctx := context.Background()
	svc, store := nodeKeyService(t)
	err := svc.RaiseNodeKeyChanged(ctx, inventory.NodeKeyChange{
		NodeID:  "c1",
		Current: proto.NodeKeys{proto.NodeKeyAgent: "sha256/new"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("a first registration persisted %d alert(s)", len(rows))
	}
}

// A second, different change is its own alert: the first ack said "yes, I
// reflashed it then", which does not cover a later change.
func TestRaiseNodeKeyChanged_ASecondChangeIsASecondAlert(t *testing.T) {
	ctx := context.Background()
	svc, store := nodeKeyService(t)
	if err := svc.RaiseNodeKeyChanged(ctx, change("c1", "sha256/a", "sha256/b")); err != nil {
		t.Fatal(err)
	}
	if err := svc.RaiseNodeKeyChanged(ctx, change("c1", "sha256/b", "sha256/c")); err != nil {
		t.Fatal(err)
	}
	// The same change again does not multiply.
	if err := svc.RaiseNodeKeyChanged(ctx, change("c1", "sha256/b", "sha256/c")); err != nil {
		t.Fatal(err)
	}
	rows, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(rows), rows)
	}
}

// The rules engine must never resolve an alert the api raised itself. Before
// the id filter, the first rule sync after a key change erased it.
func TestRuleSyncLeavesApiOwnedAlertsAlone(t *testing.T) {
	ctx := context.Background()
	svc, store := nodeKeyService(t)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }
	if err := svc.RaiseNodeKeyChanged(ctx, change("c1", "sha256/old", "sha256/new")); err != nil {
		t.Fatal(err)
	}
	// vmalert reports nothing firing, which resolves every rule alert.
	if err := svc.SyncRuleAlerts(ctx, nil); err != nil {
		t.Fatal(err)
	}
	rows, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Status != "firing" {
		t.Fatalf("the rule sync resolved an api-owned alert: %+v", rows)
	}

	// And a real rule alert still resolves normally.
	if err := svc.SyncRuleAlerts(ctx, []FiringRule{{Labels: map[string]string{"alertname": "HighCPU"}}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SyncRuleAlerts(ctx, nil); err != nil {
		t.Fatal(err)
	}
	rows, err = store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firing := 0
	for _, r := range rows {
		if r.Status == "firing" {
			firing++
		}
	}
	if firing != 1 {
		t.Errorf("firing rows = %d, want only the node-key alert: %+v", firing, rows)
	}
}

// With no store — the aggregator-only wiring a dev run uses — raising is a
// no-op rather than an error: the change is audited in the log either way.
func TestRaiseNodeKeyChanged_NoStore(t *testing.T) {
	svc := &Service{}
	if err := svc.RaiseNodeKeyChanged(context.Background(), change("c1", "sha256/a", "sha256/b")); err != nil {
		t.Errorf("no store: %v", err)
	}
}
