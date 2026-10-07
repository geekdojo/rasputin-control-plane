package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// F-741-16 (TC-741-15's clock): the store main opens reads presence at the
// clock main hands it, not the wall clock. The node's last heartbeat is a day
// before the wall clock and current at the injected one, so a store that read
// the wall clock would call it offline.
func TestOpenInventory_InjectsTheClock(t *testing.T) {
	ctx := context.Background()
	at := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	s, err := openInventory(ctx, filepath.Join(t.TempDir(), "inv.db"), func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	n := &proto.Node{ID: "n1", Role: proto.RoleCompute, Hostname: "n1", FirstSeen: at, LastSeen: at}
	if err := s.Insert(ctx, n); err != nil {
		t.Fatal(err)
	}
	nodes, err := s.List(ctx)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("List: %d nodes, err %v", len(nodes), err)
	}
	s.Presence(ctx, nodes)
	if nodes[0].Status != proto.StatusOnline {
		t.Errorf("status %q at the injected clock, want online", nodes[0].Status)
	}

	if _, err := openInventory(ctx, filepath.Join(t.TempDir(), "inv.db"), nil); err == nil {
		t.Error("a nil clock was accepted")
	}
}
