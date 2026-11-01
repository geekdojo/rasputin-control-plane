package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
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
			// The store's audit directory is present, so the store audit
			// source is on and this test reads the journal source's records
			// alone (TestMustWireObs_StoreAuditLog covers that source).
			if err := os.Mkdir(filepath.Join(dataDir, "openbao-audit"), 0o700); err != nil {
				t.Fatal(err)
			}
			h := &recordsHandler{}
			sup, _, _ := mustWireObs(context.Background(), slog.New(h), dataDir, "cp-1", nil,
				filepath.Join(dataDir, "obs", "ids-alerts"), storeModeOpenBao, off, vmOnly)
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

// TC-802-06: storeAuditLog returns <dataDir>/openbao-audit/audit.log only for
// the openbao store with its audit directory present.
func TestStoreAuditLog(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  string
		setup func(t *testing.T, dataDir string)
		want  bool
	}{
		{"openbao, directory", storeModeOpenBao, mkAuditDir, true},
		{"mock, directory", storeModeMock, mkAuditDir, false},
		{"off, directory", storeModeOff, mkAuditDir, false},
		{"unset, directory", "", mkAuditDir, false},
		{"openbao, missing", storeModeOpenBao, func(*testing.T, string) {}, false},
		{"openbao, regular file", storeModeOpenBao, func(t *testing.T, dataDir string) {
			if err := os.WriteFile(filepath.Join(dataDir, "openbao-audit"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			tc.setup(t, dataDir)
			want := ""
			if tc.want {
				want = filepath.Join(dataDir, "openbao-audit", "audit.log")
			}
			if got := storeAuditLog(tc.mode, dataDir); got != want {
				t.Errorf("storeAuditLog(%q) = %q, want %q", tc.mode, got, want)
			}
		})
	}
}

func mkAuditDir(t *testing.T, dataDir string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(dataDir, "openbao-audit"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// TC-802-06: with no audit file to ship, mustWireObs logs exactly one Info
// "obs store audit source off" naming the dir and the reason, and builds the
// supervisor with no StoreAuditLog. With one, it logs no such record and hands
// the supervisor the path.
func TestMustWireObs_StoreAuditLog(t *testing.T) {
	t.Setenv("RASPUTIN_OBS_STATE_DIR", "")
	off := func(context.Context) (bool, error) { return false, nil }

	for _, tc := range []struct {
		name       string
		mode       string
		dirPresent bool
		wantReason string // "" means the source is on
	}{
		{"openbao, directory", storeModeOpenBao, true, ""},
		{"openbao, missing", storeModeOpenBao, false, "not a directory"},
		{"mock", storeModeMock, true, "store_mode=mock"},
		{"off", storeModeOff, true, "store_mode=off"},
		{"unset", "", true, "store_mode="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			auditDir := filepath.Join(dataDir, "openbao-audit")
			if tc.dirPresent {
				mkAuditDir(t, dataDir)
			}
			h := &recordsHandler{}
			sup, _, _ := mustWireObs(context.Background(), slog.New(h), dataDir, "cp-1", nil,
				filepath.Join(dataDir, "obs", "ids-alerts"), tc.mode, off, vmOnly)
			if sup == nil {
				t.Fatal("mustWireObs returned no supervisor")
			}
			recs := h.matching(slog.LevelInfo, "obs store audit source off")
			if tc.wantReason == "" {
				if len(recs) != 0 {
					t.Errorf("records %v, want no \"obs store audit source off\"", recs)
				}
				if want := filepath.Join(auditDir, "audit.log"); sup.StoreAuditLog() != want {
					t.Errorf("supervisor StoreAuditLog = %q, want %q", sup.StoreAuditLog(), want)
				}
				return
			}
			if len(recs) != 1 {
				t.Fatalf("%d records %v, want exactly one Info \"obs store audit source off\"", len(recs), recs)
			}
			attrs := map[string]string{}
			recs[0].Attrs(func(a slog.Attr) bool {
				attrs[a.Key] = a.Value.String()
				return true
			})
			if attrs["dir"] != auditDir || attrs["reason"] != tc.wantReason || len(attrs) != 2 {
				t.Errorf("attrs %v, want dir=%s reason=%q", attrs, auditDir, tc.wantReason)
			}
			if got := sup.StoreAuditLog(); got != "" {
				t.Errorf("supervisor StoreAuditLog = %q, want \"\"", got)
			}
		})
	}
}

// vmOnly is mustWireObs's fanout for tests about the supervisor: the VM sink
// as is.
func vmOnly(vm *obs.VMSink) metrics.Sink { return vm }
