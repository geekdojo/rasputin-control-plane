package sealrotate

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-800-11 (geekdojo/geekdojo-brain#800, F-800-02): every refusal an OS
// update's copy gets from the gate names the OS update and never a backup,
// and a rotation tried while the update's copy holds the gate is not told a
// backup holds the store.
func TestGate_UpdateRefusalsNameTheOSUpdate(t *testing.T) {
	ctx := context.Background()
	t.Run("a: the seal files are not Clean", func(t *testing.T) {
		st := &fakeState{}
		st.set(Staged)
		log, rec := logkittest.New()
		g, err := NewGate(st, func(context.Context, string) (bool, error) { return true, nil }, log)
		if err != nil {
			t.Fatal(err)
		}
		err = g.AcquireForUpdate(ctx, "upd-1")
		if !errors.Is(err, errUpdateRotationIncomplete) {
			t.Fatalf("AcquireForUpdate = %v, want errUpdateRotationIncomplete", err)
		}
		assertUpdateSentence(t, err.Error())
		if n := len(rec.Matching(slog.LevelWarn, "os update refused: a seal-key rotation has not finished")); n != 1 {
			t.Errorf("%d os-update refusal WARN(s), want 1", n)
		}
		if g.holder != "" {
			t.Errorf("a refused update holds the gate as %q", g.holder)
		}
	})
	t.Run("b: the seal files cannot be read", func(t *testing.T) {
		st := &fakeState{err: errors.New("permission denied")}
		g := newGate(t, st, nil)
		err := g.AcquireForUpdate(ctx, "upd-1")
		if !errors.Is(err, errUpdateSealUnreadable) {
			t.Fatalf("AcquireForUpdate = %v, want errUpdateSealUnreadable", err)
		}
		assertUpdateSentence(t, err.Error())
		if strings.Contains(err.Error(), "permission denied") {
			t.Error("the defect reached the sentence")
		}
	})
	t.Run("c: a rotation while the update's copy holds the gate", func(t *testing.T) {
		st := &fakeState{}
		st.set(Clean)
		g := newGate(t, st, nil)
		if err := g.AcquireForUpdate(ctx, "upd-1"); err != nil {
			t.Fatal(err)
		}
		err := g.TryAcquire("rot-1")
		if !errors.Is(err, errUpdateHolds) {
			t.Fatalf("TryAcquire = %v, want errUpdateHolds", err)
		}
		if strings.Contains(strings.ToLower(err.Error()), "backup") || !strings.Contains(err.Error(), "OS update") {
			t.Errorf("rotation refusal %q does not name the OS update", err)
		}
		// Released, the gate forgets the update: the rotation takes it, and a
		// backup then waiting is told nothing about an update.
		g.Release("upd-1")
		if err := g.TryAcquire("rot-1"); err != nil {
			t.Fatalf("TryAcquire after the update released = %v", err)
		}
		g.Release("rot-1")
		if err := g.Acquire(ctx, "bk-1"); err != nil {
			t.Fatal(err)
		}
		if err := g.TryAcquire("rot-2"); !errors.Is(err, errBackupHolds) {
			t.Fatalf("TryAcquire under a backup = %v, want errBackupHolds", err)
		}
	})
	t.Run("backup sentences are unchanged", func(t *testing.T) {
		st := &fakeState{}
		st.set(Staged)
		g := newGate(t, st, nil)
		if err := g.Acquire(ctx, "bk-1"); !errors.Is(err, errBackupRotationIncomplete) {
			t.Fatalf("Acquire = %v, want errBackupRotationIncomplete", err)
		}
	})
}

// AcquireForUpdate shares Acquire's wait: it waits while a rotation holds
// the gate, returns once it is released, and returns ctx's error when the
// step's time runs out first.
func TestGate_AcquireForUpdateWaits(t *testing.T) {
	st := &fakeState{}
	st.set(Clean)
	g := newGate(t, st, nil)
	if err := g.TryAcquire("rot-1"); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.AcquireForUpdate(short, "upd-1"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcquireForUpdate under a rotation, ctx ended = %v, want DeadlineExceeded", err)
	}
	done := make(chan error, 1)
	go func() { done <- g.AcquireForUpdate(context.Background(), "upd-1") }()
	g.Release("rot-1")
	if err := <-done; err != nil {
		t.Fatalf("AcquireForUpdate after the release = %v", err)
	}
	if g.RotationHolder() != "" {
		t.Error("the update reads as a rotation holder")
	}
}

// assertUpdateSentence checks an update refusal: the shared opening, a
// sentence, and no word of a backup.
func assertUpdateSentence(t *testing.T, s string) {
	t.Helper()
	if !strings.HasPrefix(s, UpdateCopyRefused) || !strings.HasSuffix(s, ".") {
		t.Errorf("sentence %q does not open with the update refusal or end with a full stop", s)
	}
	if strings.Contains(strings.ToLower(s), "backup") {
		t.Errorf("sentence %q names a backup", s)
	}
}
