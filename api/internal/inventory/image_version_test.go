package inventory

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// SetImageVersion is the one writer of nodes.image_version that is NOT the
// agent's self-report: the updater reconciling inventory from a terminal update
// outcome (ADR-0005 Decision 4). See the updater's reconcileInventoryVersion.

func TestStore_SetImageVersion(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	n := makeNode("n-ver", proto.RoleCompute, 0)
	n.ImageVersion = "2026.07.0-dev.104" // the version it was MEANT to reach
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if err := s.SetImageVersion(ctx, "n-ver", "2026.07.0-dev.101"); err != nil {
		t.Fatalf("SetImageVersion: %v", err)
	}
	got, err := s.Get(ctx, "n-ver")
	if err != nil || got == nil {
		t.Fatalf("Get: %v, %+v", err, got)
	}
	if got.ImageVersion != "2026.07.0-dev.101" {
		t.Errorf("image_version = %q, want the reconciled value", got.ImageVersion)
	}
}

// The reason this is a targeted column write and not a read-modify-Update: a
// full Update overwrites every mutable field, so anything a concurrent
// registration learned between the read and the write would be clobbered. The
// updater knows exactly one fact about the node and must write exactly that.
func TestStore_SetImageVersion_LeavesEveryOtherColumnAlone(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	n := makeNode("n-only", proto.RoleCompute, 0)
	n.Architecture = "arm64"
	n.LANIP = "192.168.1.40"
	n.Storage = &proto.StorageInfo{PersistentTotalBytes: 1 << 30, Growpart: "grown"}
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	before, _ := s.Get(ctx, "n-only")

	if err := s.SetImageVersion(ctx, "n-only", "2026.08.0"); err != nil {
		t.Fatalf("SetImageVersion: %v", err)
	}
	after, err := s.Get(ctx, "n-only")
	if err != nil || after == nil {
		t.Fatalf("Get: %v, %+v", err, after)
	}
	if after.ImageVersion != "2026.08.0" {
		t.Errorf("image_version = %q, want it changed", after.ImageVersion)
	}
	if after.Architecture != before.Architecture ||
		after.LANIP != before.LANIP ||
		after.Hostname != before.Hostname ||
		after.AgentVersion != before.AgentVersion ||
		after.Role != before.Role ||
		!after.LastSeen.Equal(before.LastSeen) ||
		!after.FirstSeen.Equal(before.FirstSeen) {
		t.Errorf("a column other than image_version moved:\n before %+v\n after  %+v", before, after)
	}
	if after.Storage == nil || *after.Storage != *before.Storage {
		t.Errorf("storage moved: got %+v want %+v", after.Storage, before.Storage)
	}
	if len(after.Capabilities) != len(before.Capabilities) {
		t.Errorf("capabilities moved: got %v want %v", after.Capabilities, before.Capabilities)
	}
}

// An update outcome for a node that is no longer in inventory is a reason to
// log, never a reason to fail the saga — so the caller needs to be able to tell
// "no such node" apart from a real write error.
func TestStore_SetImageVersion_UnknownNodeIsErrNoRows(t *testing.T) {
	err := newStore(t).SetImageVersion(context.Background(), "n-gone", "2026.08.0")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("SetImageVersion on a missing node = %v, want sql.ErrNoRows", err)
	}
}
