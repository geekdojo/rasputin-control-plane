package inventory

// A node cannot change roles once enrolled: changing role means remove,
// reflash, re-add. A re-registration presenting a different role than the
// stored row is rejected and leaves the row untouched; the same role still
// updates the row; a removed node may come back with a new role.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// rawNodeRow returns every column of the node's row, rendered verbatim, so a
// comparison catches a change to any field including timestamps.
func rawNodeRow(t *testing.T, s *Store, id string) string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `SELECT * FROM nodes WHERE id = ?`, id)
	if err != nil {
		t.Fatalf("select %s: %v", id, err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	if !rows.Next() {
		t.Fatalf("no row for %s", id)
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		t.Fatalf("scan: %v", err)
	}
	var b strings.Builder
	for i, c := range cols {
		fmt.Fprintf(&b, "%s=%#v\n", c, vals[i])
	}
	return b.String()
}

func newRoleTestService(t *testing.T) (*Service, *Store, *nats.Subscription) {
	t.Helper()
	nc := startNATS(t)
	store := newStore(t)
	svc := NewService(store, nc)
	svc.ctx = context.Background()
	changes, err := nc.SubscribeSync("rasputin.inventory.>")
	if err != nil {
		t.Fatalf("subscribe changes: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return svc, store, changes
}

func register(t *testing.T, svc *Service, ev proto.NodeRegisteredEvt) {
	t.Helper()
	svc.handleRegistered(&nats.Msg{Subject: proto.NodeRegisteredSubject(ev.NodeID), Data: mustJSON(t, ev)})
}

func TestHandleRegistered_RoleChangeRejected(t *testing.T) {
	ctx := context.Background()
	svc, store, changes := newRoleTestService(t)

	confirmed := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	n := makeNode("alpha", proto.RoleCompute, time.Minute)
	n.LANIP = "192.168.1.20"
	n.Architecture = "amd64"
	n.ImageVersionConfirmedAt = &confirmed
	if err := store.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	before := rawNodeRow(t, store, "alpha")

	for _, role := range []proto.NodeRole{proto.RoleFirewall, proto.RoleControlPlane, proto.RoleStorage} {
		register(t, svc, proto.NodeRegisteredEvt{
			NodeID:       "alpha",
			Role:         role,
			Hostname:     "alpha-renamed.test",
			AgentVersion: "v9.9.9",
			ImageVersion: "2026.09.2",
			Architecture: "arm64",
			LANIP:        "10.0.0.20",
		})
		if after := rawNodeRow(t, store, "alpha"); after != before {
			t.Errorf("a re-registration presenting role %q changed the %q row:\nbefore:\n%s\nafter:\n%s",
				role, proto.RoleCompute, before, after)
		}
	}
	if err := svc.nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if m, err := changes.NextMsg(200 * time.Millisecond); err == nil {
		t.Errorf("a rejected re-registration emitted an inventory change: %s", m.Subject)
	}
}

func TestHandleRegistered_SameRoleStillUpdates(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newRoleTestService(t)

	n := makeNode("alpha", proto.RoleCompute, time.Minute)
	n.LANIP = "192.168.1.20"
	if err := store.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	register(t, svc, proto.NodeRegisteredEvt{
		NodeID:       "alpha",
		Role:         proto.RoleCompute,
		Hostname:     "alpha-renamed.test",
		AgentVersion: "v9.9.9",
		ImageVersion: "2026.09.2",
		LANIP:        "10.0.0.20",
	})
	got, err := store.Get(ctx, "alpha")
	if err != nil || got == nil {
		t.Fatalf("Get: %v %+v", err, got)
	}
	if got.Hostname != "alpha-renamed.test" || got.AgentVersion != "v9.9.9" ||
		got.ImageVersion != "2026.09.2" || got.LANIP != "10.0.0.20" || got.Role != proto.RoleCompute {
		t.Errorf("same-role re-registration did not update the row: %+v", got)
	}
	if got.ImageVersionConfirmedAt == nil {
		t.Errorf("same-role re-registration did not confirm the image version")
	}
}

func TestHandleRegistered_RemovedNodeMayReturnWithNewRole(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newRoleTestService(t)

	register(t, svc, proto.NodeRegisteredEvt{NodeID: "alpha", Role: proto.RoleCompute, Hostname: "alpha.test"})
	if got, _ := store.Get(ctx, "alpha"); got == nil || got.Role != proto.RoleCompute {
		t.Fatalf("first registration: %+v", got)
	}
	// The same removal DELETE /api/nodes/{id} performs.
	if err := svc.Remove(ctx, "alpha"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	register(t, svc, proto.NodeRegisteredEvt{NodeID: "alpha", Role: proto.RoleFirewall, Hostname: "alpha-fw.test"})
	got, err := store.Get(ctx, "alpha")
	if err != nil || got == nil {
		t.Fatalf("Get after re-add: %v %+v", err, got)
	}
	if got.Role != proto.RoleFirewall || got.Hostname != "alpha-fw.test" {
		t.Errorf("re-add after removal = role %q host %q, want %q %q",
			got.Role, got.Hostname, proto.RoleFirewall, "alpha-fw.test")
	}
}
