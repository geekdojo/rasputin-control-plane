package ids

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// drainFor collects lines arriving on the tailer for the given duration.
// Used by the rotation/append tests to give the polling tailer enough
// wake-ups to notice the file change.
func drainFor(t *testing.T, tail *Tailer, d time.Duration) []string {
	t.Helper()
	var got []string
	deadline := time.After(d)
	for {
		select {
		case line, ok := <-tail.Lines():
			if !ok {
				return got
			}
			got = append(got, line)
		case <-deadline:
			return got
		}
	}
}

func TestTailer_AppendedLinesArrive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_fast.txt")
	// Pre-create empty file; tailer starts mid-life.
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	prev := PollInterval
	PollInterval = 10 * time.Millisecond
	t.Cleanup(func() { PollInterval = prev })

	tail := NewTailer(path)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tail.Run(ctx)
	time.Sleep(20 * time.Millisecond) // let the initial openSeekEnd land

	// Append two lines.
	if err := os.WriteFile(path, []byte("alpha\nbeta\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := drainFor(t, tail, 300*time.Millisecond)
	want := []string{"alpha\n", "beta\n"}
	if !equalStringSlices(got, want) {
		t.Errorf("got %#v want %#v", got, want)
	}
}

func TestTailer_PreExistingContentNotReplayed(t *testing.T) {
	// Critical contract: when the tailer starts and the file already has
	// content, we do NOT publish that backlog to the controlplane —
	// otherwise every agent restart would resend the entire alert log.
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_fast.txt")
	if err := os.WriteFile(path, []byte("old1\nold2\nold3\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	prev := PollInterval
	PollInterval = 10 * time.Millisecond
	t.Cleanup(func() { PollInterval = prev })

	tail := NewTailer(path)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tail.Run(ctx)

	// Wait briefly, then check we got nothing.
	got := drainFor(t, tail, 100*time.Millisecond)
	if len(got) != 0 {
		t.Errorf("expected no backlog replay; got %#v", got)
	}

	// Now append a new line; it SHOULD arrive.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("new\n")
	_ = f.Close()

	got = drainFor(t, tail, 300*time.Millisecond)
	if len(got) != 1 || got[0] != "new\n" {
		t.Errorf("expected only the new line; got %#v", got)
	}
}

func TestTailer_FileMissingThenAppears(t *testing.T) {
	// Snort hasn't started yet → file doesn't exist. Tailer should poll
	// patiently and pick up the file once it appears.
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_fast.txt")
	// Do NOT pre-create.

	prev := PollInterval
	PollInterval = 10 * time.Millisecond
	t.Cleanup(func() { PollInterval = prev })

	tail := NewTailer(path)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tail.Run(ctx)

	time.Sleep(50 * time.Millisecond) // some polls land while file absent

	// Create the file with two lines. Since the file was missing on the
	// initial open, openSeekEnd didn't run — the first poll opens at
	// offset=0 and we DO read both lines (this is the right behavior:
	// snort started fresh, and these are its first alerts).
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := drainFor(t, tail, 300*time.Millisecond)
	want := []string{"first\n", "second\n"}
	if !equalStringSlices(got, want) {
		t.Errorf("got %#v want %#v", got, want)
	}
}

func TestTailer_RotatedFileReopened(t *testing.T) {
	// snort renames alert_fast.txt to alert_fast.txt.1 and creates a
	// fresh alert_fast.txt. The tailer should detect the size shrink
	// and start reading the new file from offset 0.
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_fast.txt")
	if err := os.WriteFile(path, []byte("pre-rotation-A\npre-rotation-B\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	prev := PollInterval
	PollInterval = 10 * time.Millisecond
	t.Cleanup(func() { PollInterval = prev })

	tail := NewTailer(path)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tail.Run(ctx)

	time.Sleep(40 * time.Millisecond) // initial seek-to-end lands; offset > 0

	// Append normally — should appear.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("mid-stream\n")
	_ = f.Close()

	got := drainFor(t, tail, 200*time.Millisecond)
	if len(got) != 1 || got[0] != "mid-stream\n" {
		t.Errorf("pre-rotation: got %#v want [mid-stream\\n]", got)
	}

	// Simulate rotation: shrink the file to ~zero, write new content.
	// (Real snort rename-then-create has the same observable shape from
	// the tailer's view: stat reports a smaller file.)
	if err := os.WriteFile(path, []byte("post-rotation-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got = drainFor(t, tail, 300*time.Millisecond)
	if len(got) != 1 || !strings.HasPrefix(got[0], "post-rotation") {
		t.Errorf("post-rotation: got %#v want [post-rotation-1\\n]", got)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
