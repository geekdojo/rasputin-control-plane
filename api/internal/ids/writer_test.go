package ids

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func sampleEvt() *proto.IDSAlertEvt {
	return &proto.IDSAlertEvt{
		NodeID: "fw-1",
		Ts:     time.Date(2026, 6, 8, 14, 23, 45, 0, time.UTC),
		GID:    1, SID: 2009582, Rev: 5,
		Message:        "ET POLICY HTTP traffic on port 443 (POST)",
		Classification: "Potentially Bad Traffic",
		Priority:       2,
		Protocol:       "TCP",
		SrcAddr:        "192.168.1.50", SrcPort: 54321,
		DstAddr: "8.8.8.8", DstPort: 443,
		Raw: "06/08-14:23:45.123456 [**] [1:2009582:5] ET POLICY HTTP traffic on port 443 (POST) [**] ...",
	}
}

func TestWriter_AppendsOneJSONLinePerEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ids-alerts.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	for i := 0; i < 3; i++ {
		if err := w.Write(sampleEvt()); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	sc := bufio.NewScanner(f)
	lines := 0
	for sc.Scan() {
		lines++
		var ev proto.IDSAlertEvt
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Errorf("line %d: not valid JSON: %v", lines, err)
		}
		if ev.SID != 2009582 {
			t.Errorf("line %d: SID round-trip mismatch", lines)
		}
	}
	if lines != 3 {
		t.Errorf("got %d lines, want 3", lines)
	}
}

func TestWriter_RotatesAtSizeLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ids-alerts.jsonl")
	// Tiny limits so a few writes trigger rotation.
	w, err := NewWriterWithLimits(path, 600, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	// Each evt JSON is roughly 350-400 bytes; 5 writes will trigger
	// rotation at least once.
	for i := 0; i < 5; i++ {
		if err := w.Write(sampleEvt()); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// We expect at least one backup (.1) to exist after rotation.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var liveCount, backupCount int
	for _, e := range entries {
		if e.Name() == "ids-alerts.jsonl" {
			liveCount++
		} else if strings.HasPrefix(e.Name(), "ids-alerts.jsonl.") {
			backupCount++
		}
	}
	if liveCount != 1 {
		t.Errorf("expected exactly 1 live file, got %d", liveCount)
	}
	if backupCount < 1 {
		t.Errorf("expected at least 1 rotated backup, got %d", backupCount)
	}
}

func TestWriter_RotateCapsBackups(t *testing.T) {
	// Walk through many rotations; assert the number of backups never
	// exceeds maxBackups.
	dir := t.TempDir()
	path := filepath.Join(dir, "x.log")
	w, err := NewWriterWithLimits(path, 400, 2) // very small + only 2 backups
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	for i := 0; i < 20; i++ {
		if err := w.Write(sampleEvt()); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var backups []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "x.log.") {
			backups = append(backups, e.Name())
		}
	}
	if len(backups) > 2 {
		t.Errorf("expected <=2 backups, got %d: %v", len(backups), backups)
	}
}

func TestWriter_ReopenAppendsContinues(t *testing.T) {
	// Close + reopen: contents from the first run survive (the on-disk
	// file is the truth) and new writes append to the same file.
	path := filepath.Join(t.TempDir(), "x.log")

	w1, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w1.Write(sampleEvt()); err != nil {
		t.Fatal(err)
	}
	if err := w1.Close(); err != nil {
		t.Fatal(err)
	}

	w2, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Write(sampleEvt()); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Count(string(data), "\n")
	if lines != 2 {
		t.Errorf("expected 2 lines after reopen-and-append; got %d", lines)
	}
}

func TestWriter_NilEventErrors(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "x.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if err := w.Write(nil); err == nil {
		t.Error("expected error on nil event")
	}
}
