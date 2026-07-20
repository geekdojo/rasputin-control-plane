package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLog(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "growpart.log")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGrowpartOutcome(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"absent", "", ""}, // path overridden to a missing file below
		{"grown then already-full", "2026-07-20T17:19:54Z grown: /dev/nvme0n1p5 512MiB -> 119736MiB (table=gpt, part 5); rebooting\n2026-07-20T17:20:34Z already-full: /dev/nvme0n1p5 fills /dev/nvme0n1 (119735MiB; 0MiB tail) — nothing to do\n", "already-full"},
		{"single grown", "2026-07-20T17:19:54Z grown: x; rebooting\n", "grown"},
		{"failed via trap", "2026-07-20T00:00:00Z failed: exit=1 — grow aborted, see journalctl\n", "failed"},
		{"deferred trial", "ts deferred-trial: in an uncommitted A/B trial (booted=rootfs.1, committed=rootfs.0)\n", "deferred-trial"},
		{"skipped", "ts skipped: unrecognized partition table 'loop' on /dev/sda; not growing\n", "skipped"},
		{"garbage line newest, falls back", "ts grown: ok; rebooting\nhalf-a-rotated-line-without-structure\n", "grown"},
		{"no keyword at all", "just some noise\nand more noise\n", ""},
		{"future keyword passes through", "ts trimmed-tail: something new\n", "trimmed-tail"},
		{"uppercase rejected", "ts FAILED: shouting\n", ""},
		{"trailing blank lines", "ts already-full: fine\n\n\n", "already-full"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p string
			if tc.name == "absent" {
				p = filepath.Join(t.TempDir(), "nope.log")
			} else {
				p = writeLog(t, tc.content)
			}
			if got := growpartOutcome(p); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGrowpartOutcomeScansOnlyTail(t *testing.T) {
	// A file larger than the scan cap: the newest outcome (at the end) must
	// still win, and the scan must not choke on the oversized head.
	head := strings.Repeat("ts already-full: old line\n", 2000) // ~50 KiB
	p := writeLog(t, head+"ts grown: the newest\n")
	if got := growpartOutcome(p); got != "grown" {
		t.Fatalf("got %q, want grown", got)
	}
}

func TestStorage(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "growpart.log")
	if err := os.WriteFile(log, []byte("ts grown: x; rebooting\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	st := Storage(dir, log)
	if st == nil {
		t.Fatal("expected storage info for an existing dir")
	}
	if st.PersistentTotalBytes == 0 {
		t.Error("expected a nonzero statfs total")
	}
	if st.Growpart != "grown" {
		t.Errorf("growpart = %q, want grown", st.Growpart)
	}

	// Neither statfs nor breadcrumb: report unknown, not zeros.
	if st := Storage(filepath.Join(dir, "missing"), filepath.Join(dir, "missing.log")); st != nil {
		t.Fatalf("expected nil for nothing-learned, got %+v", st)
	}

	// Breadcrumb alone (statfs path missing) still reports the outcome.
	st = Storage(filepath.Join(dir, "missing"), log)
	if st == nil || st.Growpart != "grown" || st.PersistentTotalBytes != 0 {
		t.Fatalf("expected outcome-only info, got %+v", st)
	}
}
