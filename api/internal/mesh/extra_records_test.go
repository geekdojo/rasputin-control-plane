package mesh

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRenderExtraRecords_SortedStableFormat(t *testing.T) {
	// Insertion order is intentionally not sorted; output must be name-sorted
	// and byte-stable so Headscale's checksum only changes on real content changes.
	in := map[string]string{
		"jellyfin.home1.internal": "100.64.0.3",
		"actual.home1.internal":   "100.64.0.2",
		"":                        "100.64.0.9", // empty name → dropped
		"skip.home1.internal":     "",           // empty IP → dropped
	}
	out, err := renderExtraRecords(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	var recs []extraRecord
	if err := json.Unmarshal(out, &recs); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (empties dropped): %+v", len(recs), recs)
	}
	// Sorted by name: "actual" before "jellyfin".
	if recs[0].Name != "actual.home1.internal" || recs[1].Name != "jellyfin.home1.internal" {
		t.Errorf("not name-sorted: %q, %q", recs[0].Name, recs[1].Name)
	}
	for _, r := range recs {
		if r.Type != "A" {
			t.Errorf("record %s type = %q, want A", r.Name, r.Type)
		}
	}
	if recs[0].Value != "100.64.0.2" {
		t.Errorf("actual value = %q, want 100.64.0.2", recs[0].Value)
	}

	// Stability: same input → identical bytes.
	out2, _ := renderExtraRecords(in)
	if string(out) != string(out2) {
		t.Errorf("render not stable across calls")
	}
}

func TestRenderExtraRecords_EmptyIsArrayNotNull(t *testing.T) {
	out, err := renderExtraRecords(map[string]string{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if string(out) != "[]" {
		t.Errorf("empty render = %q, want [] (never null)", out)
	}
}

func TestExtraRecordsFile_SeedThenReconcile(t *testing.T) {
	s, err := NewDockerSupervisor(DockerSupervisorConfig{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDockerSupervisor: %v", err)
	}
	if err := s.prepareHostDirs(); err != nil {
		t.Fatalf("prepareHostDirs: %v", err)
	}

	// Seed: creates an empty [] file when none exists.
	if err := s.ensureExtraRecordsFile(); err != nil {
		t.Fatalf("ensureExtraRecordsFile: %v", err)
	}
	if got := readFile(t, s.extraRecordsHostPath()); got != "[]\n" {
		t.Errorf("seeded file = %q, want %q", got, "[]\n")
	}

	// Reconcile writes the projection in place (same path/inode).
	if err := s.ReconcileAppRecords(map[string]string{"jellyfin.home1.internal": "100.64.0.3"}); err != nil {
		t.Fatalf("ReconcileAppRecords: %v", err)
	}
	var recs []extraRecord
	if err := json.Unmarshal([]byte(readFile(t, s.extraRecordsHostPath())), &recs); err != nil {
		t.Fatalf("reconciled file not valid JSON: %v", err)
	}
	if len(recs) != 1 || recs[0].Name != "jellyfin.home1.internal" || recs[0].Value != "100.64.0.3" {
		t.Fatalf("reconciled records = %+v", recs)
	}

	// A second reconcile with an existing file must NOT re-seed it to [] —
	// ensureExtraRecordsFile leaves a present file alone.
	if err := s.ensureExtraRecordsFile(); err != nil {
		t.Fatalf("ensureExtraRecordsFile (existing): %v", err)
	}
	if got := readFile(t, s.extraRecordsHostPath()); got == "[]\n" {
		t.Errorf("ensureExtraRecordsFile clobbered an existing projection")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
