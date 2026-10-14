package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// TC-853-19: journalStoreDir returns <dataDir>/journal only when that is a
// directory.
func TestJournalStoreDir(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		dataDir := t.TempDir()
		want := filepath.Join(dataDir, "journal")
		if err := os.Mkdir(want, 0o755); err != nil {
			t.Fatal(err)
		}
		if got := journalStoreDir(dataDir); got != want {
			t.Errorf("journalStoreDir = %q, want %q", got, want)
		}
	})
	t.Run("missing", func(t *testing.T) {
		if got := journalStoreDir(t.TempDir()); got != "" {
			t.Errorf("journalStoreDir = %q, want \"\"", got)
		}
	})
	t.Run("regular file", func(t *testing.T) {
		dataDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dataDir, "journal"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if got := journalStoreDir(dataDir); got != "" {
			t.Errorf("journalStoreDir = %q, want \"\"", got)
		}
	})
}

// TC-853-19: the composition root's obs wiring, with obs off and an injected
// logger. A missing journal store logs exactly one Info record naming the dir
// and the reason, builds the supervisor with no JournalDir, and returns
// normally. A present store logs nothing and hands the supervisor its path.
func TestMustWireObs_JournalDir(t *testing.T) {
	t.Setenv("RASPUTIN_OBS_STATE_DIR", "")
	off := func(context.Context) (bool, error) { return false, nil }

	for _, tc := range []struct {
		name    string
		present bool
	}{
		{"store missing", false},
		{"store present", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			storeDir := filepath.Join(dataDir, "journal")
			if tc.present {
				if err := os.Mkdir(storeDir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			h := &recordsHandler{}
			sup, _, _ := mustWireObs(context.Background(), slog.New(h), dataDir, "cp-1", nil,
				filepath.Join(dataDir, "obs", "ids-alerts"), off)
			if sup == nil {
				t.Fatal("mustWireObs returned no supervisor")
			}

			recs := h.matching(slog.LevelInfo, "obs journal source off")
			if !tc.present {
				if len(recs) != 1 || recs[0].Message != "obs journal source off" {
					t.Fatalf("%d records %v, want exactly one Info \"obs journal source off\"", len(recs), recs)
				}
				attrs := map[string]string{}
				recs[0].Attrs(func(a slog.Attr) bool {
					attrs[a.Key] = a.Value.String()
					return true
				})
				if attrs["dir"] != storeDir || attrs["reason"] != "not a directory" || len(attrs) != 2 {
					t.Errorf("attrs %v, want dir=%s reason=\"not a directory\"", attrs, storeDir)
				}
				if got := sup.JournalDir(); got != "" {
					t.Errorf("supervisor JournalDir = %q, want \"\"", got)
				}
				return
			}
			if len(h.recs) != 0 {
				t.Errorf("records %v, want none", h.recs)
			}
			if got := sup.JournalDir(); got != storeDir {
				t.Errorf("supervisor JournalDir = %q, want %q", got, storeDir)
			}
		})
	}
}
