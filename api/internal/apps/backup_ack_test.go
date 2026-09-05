package apps

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The §4.4 install-time acknowledgement (#299) survives the store: written
// at Create, read back by id, by name and in the list; absent when none was
// given — and absent is a nil pointer, never a zero record with an empty name.
func TestBackupAck_RoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := OpenStore(ctx, filepath.Join(t.TempDir(), "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	acked := &App{
		ID: "01J", Name: "vaultwarden", ComposeYAML: "services: {}", TargetNode: "n1",
		LastStatus: proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now,
		BackupAck: &BackupAck{At: now, By: "bryce"},
	}
	plain := &App{
		ID: "01K", Name: "jellyfin", ComposeYAML: "services: {}", TargetNode: "n1",
		LastStatus: proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now,
	}
	for _, a := range []*App{acked, plain} {
		if err := st.Create(ctx, a); err != nil {
			t.Fatalf("create %s: %v", a.Name, err)
		}
	}
	got, err := st.Get(ctx, "01J")
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.BackupAck == nil || got.BackupAck.By != "bryce" || !got.BackupAck.At.Equal(now) {
		t.Errorf("ack = %+v, want {bryce %s}", got.BackupAck, now)
	}
	byName, err := st.GetByName(ctx, "jellyfin")
	if err != nil || byName == nil {
		t.Fatalf("get by name: %v %v", byName, err)
	}
	if byName.BackupAck != nil {
		t.Errorf("an install that needed no acknowledgement must read back nil, got %+v", byName.BackupAck)
	}
	all, err := st.List(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("list: %d %v", len(all), err)
	}
	for _, a := range all {
		if (a.ID == "01J") != (a.BackupAck != nil) {
			t.Errorf("list row %s: ack = %+v", a.Name, a.BackupAck)
		}
	}
}
