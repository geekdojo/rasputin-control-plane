package alerts

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(context.Background(), filepath.Join(dir, "alerts.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStore_UpsertNewRow_ReportsIsNew(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	saved, isNew, err := s.Upsert(ctx, &PersistedAlert{
		Fingerprint: "fp1", Status: "firing",
		Severity: proto.AlertCrit, Title: "NodeDown",
		StartsAt: time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if !isNew {
		t.Error("first Upsert should report isNew=true")
	}
	if saved.ID != "rule:fp1" {
		t.Errorf("default ID = %q, want rule:fp1", saved.ID)
	}
}

func TestStore_UpsertExistingRow_StableIDAndIsNewFalse(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	a := &PersistedAlert{
		Fingerprint: "fp2", Status: "firing",
		Severity: proto.AlertWarn, Title: "HighCPU",
		StartsAt: time.Now().UTC().Truncate(time.Second),
	}
	first, _, _ := s.Upsert(ctx, a)
	a.Status = "resolved"
	second, isNew, err := s.Upsert(ctx, a)
	if err != nil {
		t.Fatalf("Upsert 2: %v", err)
	}
	if isNew {
		t.Error("second Upsert should not be new")
	}
	if first.ID != second.ID {
		t.Errorf("ID changed across upserts: %q → %q", first.ID, second.ID)
	}
	if second.Status != "resolved" {
		t.Errorf("status not updated: %q", second.Status)
	}
}

func TestStore_AckSetsTimestamp(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	saved, _, _ := s.Upsert(ctx, &PersistedAlert{
		Fingerprint: "fp3", Status: "firing",
		Severity: proto.AlertWarn, Title: "X",
		StartsAt: time.Now().UTC().Truncate(time.Second),
	})
	if saved.AckedAt != nil {
		t.Fatal("AckedAt should start nil")
	}
	acked, err := s.Ack(ctx, saved.ID)
	if err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if acked.AckedAt == nil {
		t.Fatal("AckedAt should be set after Ack")
	}
}

func TestStore_DismissHidesFromList(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	saved, _, _ := s.Upsert(ctx, &PersistedAlert{
		Fingerprint: "fp4", Status: "firing",
		Severity: proto.AlertWarn, Title: "X",
		StartsAt: time.Now().UTC().Truncate(time.Second),
	})
	list, _ := s.List(ctx)
	if len(list) != 1 {
		t.Fatalf("pre-dismiss list count = %d", len(list))
	}
	if _, err := s.Dismiss(ctx, saved.ID); err != nil {
		t.Fatalf("Dismiss: %v", err)
	}
	list, _ = s.List(ctx)
	if len(list) != 0 {
		t.Errorf("post-dismiss list should be empty, got %d", len(list))
	}
}

func TestStore_FingerprintRequired(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, _, err := s.Upsert(ctx, &PersistedAlert{Title: "x"}); err == nil {
		t.Fatal("Upsert with no fingerprint should error")
	}
}

func TestStore_TitleRequired(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, _, err := s.Upsert(ctx, &PersistedAlert{Fingerprint: "fp"}); err == nil {
		t.Fatal("Upsert with no title should error")
	}
}
