package identitystate

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-979-10 (systemctl show): both units' values parse; a missing property,
// empty output, one unit and a line that is not KEY=VALUE are errors.
func TestParseUnits(t *testing.T) {
	good := "ActiveState=activating\nSubState=start-post\nInvocationID=" + id(1) + "\n\n" +
		"InvocationID=" + id(2) + "\nActiveState=active\nSubState=running\n"
	u, err := ParseUnits([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	want := Units{KC: Unit{ActiveState: "activating", SubState: "start-post", InvocationID: id(1)}, DB: Unit{ActiveState: "active", SubState: "running", InvocationID: id(2)}}
	if u != want {
		t.Fatalf("units = %+v, want %+v", u, want)
	}
	// An unknown unit: systemd prints inactive/dead and an empty InvocationID.
	unknown := "ActiveState=inactive\nSubState=dead\nInvocationID=\n\nActiveState=active\nSubState=running\nInvocationID=" + id(2) + "\n"
	if u, err := ParseUnits([]byte(unknown)); err != nil || u.KC != (Unit{ActiveState: "inactive", SubState: "dead"}) {
		t.Fatalf("unknown unit: %+v, %v", u, err)
	}
	for name, out := range map[string]string{
		"missing property": "ActiveState=active\nSubState=running\n\nActiveState=active\nSubState=running\nInvocationID=\n",
		"empty":            "",
		"one unit":         "ActiveState=active\nSubState=running\nInvocationID=\n",
		"not key=value":    "ActiveState=active\nrubbish\nInvocationID=\n\nActiveState=active\nSubState=running\nInvocationID=\n",
		"empty state":      "ActiveState=\nSubState=\nInvocationID=\n\nActiveState=active\nSubState=running\nInvocationID=\n",
	} {
		if _, err := ParseUnits([]byte(out)); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
}

// SystemctlUnits makes one systemctl show call naming both units, Keycloak's
// first, and wraps its failure.
func TestSystemctlUnits(t *testing.T) {
	var calls [][]string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return []byte("ActiveState=active\nSubState=running\nInvocationID=\n\nActiveState=active\nSubState=running\nInvocationID=\n"), nil
	}
	if _, err := SystemctlUnits(run, "kc.service", "db.service")(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || strings.Join(calls[0], " ") != "systemctl show --property=ActiveState,SubState,InvocationID kc.service db.service" {
		t.Fatalf("calls = %q", calls)
	}
	fail := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("no bus") }
	if _, err := SystemctlUnits(fail, "kc.service", "db.service")(t.Context()); err == nil || !strings.Contains(err.Error(), "no bus") {
		t.Fatalf("err = %v", err)
	}
}

// TC-979-10 (exit records and last): every outcome word parses, with
// exit_code and exit_status filled or empty; each malformed record is an
// error that is logged once, left in place, and never becomes a state or a
// job; a missing, malformed or dangling `last` is no `last`. The package
// carries no journal parser.
func TestExitRecords(t *testing.T) {
	dir := t.TempDir()
	words := []string{"success", "protocol", "timeout", "exit-code", "signal", "core-dump", "watchdog", "start-limit-hit", "resources", "oom-kill"}
	for i, w := range words {
		code, status := "exited", "1"
		if i%2 == 1 {
			code, status = "", ""
		}
		writeRecord(t, dir, id(i+1), w, code, status, fixedNow)
	}
	read := ExitRecords(os.DirFS("/"), dir)
	d, err := read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Records) != len(words) || len(d.Bad) != 0 || d.Last != nil {
		t.Fatalf("records %d, bad %d, last %v; want %d, 0, nil", len(d.Records), len(d.Bad), d.Last, len(words))
	}
	for i, r := range d.Records {
		if r.ID != id(i+1) || r.Outcome != words[i] || !r.Written.Equal(fixedNow) {
			t.Errorf("record %d = %+v", i, r)
		}
	}

	for _, last := range []string{"not-an-id\n", strings.ToUpper(id(0xabcdef)), id(99) + "\n"} {
		if err := os.WriteFile(filepath.Join(dir, lastName), []byte(last), 0o600); err != nil {
			t.Fatal(err)
		}
		if d, err := read(t.Context()); err != nil || d.Last != nil {
			t.Errorf("last %q: Last = %v (%v), want none", last, d.Last, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, lastName), []byte(id(3)), 0o600); err != nil {
		t.Fatal(err)
	}
	if d, err := read(t.Context()); err != nil || d.Last == nil || d.Last.ID != id(3) {
		t.Fatalf("last without a newline: %v (%v)", d.Last, err)
	}

	bad := map[string]string{
		"missing key":  "outcome=exit-code\ninvocation_id=" + id(50) + "\nexit_code=exited\n",
		"unknown key":  "outcome=exit-code\ninvocation_id=" + id(51) + "\nexit_code=exited\nexit_status=3\nunit=keycloak\n",
		"unknown word": "outcome=crashed\ninvocation_id=" + id(52) + "\nexit_code=exited\nexit_status=3\n",
		"id mismatch":  "outcome=exit-code\ninvocation_id=" + id(1) + "\nexit_code=exited\nexit_status=3\n",
		"over 4 KiB":   "outcome=exit-code\ninvocation_id=" + id(54) + "\nexit_code=exited\nexit_status=3\n" + strings.Repeat("x", 4096),
		"empty":        "",
	}
	names := map[string]string{"missing key": id(50), "unknown key": id(51), "unknown word": id(52), "id mismatch": id(53), "over 4 KiB": id(54), "empty": id(55)}
	for name, body := range bad {
		if err := os.WriteFile(filepath.Join(dir, names[name]), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d, err = read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Bad) != len(bad) || len(d.Records) != len(words) {
		t.Fatalf("bad %d, records %d; want %d, %d", len(d.Bad), len(d.Records), len(bad), len(words))
	}

	// Through the Monitor: one WARN per bad record, each left in place, no
	// job, and no state from it.
	x := newFixture(t)
	x.dir = dir
	x.m.d.Exits = read
	x.m.d.RemoveExit = RemoveExitRecord(os.Remove, dir)
	_ = os.Remove(filepath.Join(dir, lastName))
	for range 2 {
		if got := x.state(t); got != Ready {
			t.Fatalf("state = %s, want ready", got)
		}
	}
	warns := x.rec.Matching(slog.LevelWarn, "identity exit record unreadable")
	if len(warns) != len(bad) {
		t.Fatalf("%d WARNs over two readings, want one per bad record (%d)", len(warns), len(bad))
	}
	for _, w := range warns {
		if p, _ := logkittest.Attr(w, "path"); p == "" {
			t.Error("WARN has no path")
		}
		if e, _ := logkittest.Attr(w, "err"); e == "" {
			t.Error("WARN has no err")
		}
	}
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("bad record %s was not left in place: %v", n, err)
		}
	}
	for _, j := range x.ledger.byKind(ExitKind) {
		for _, n := range names {
			if j.ID == exitJobID(n) {
				t.Errorf("a bad record became job %s", j.ID)
			}
		}
	}

	// A directory that does not exist holds no record.
	if d, err := ExitRecords(os.DirFS("/"), filepath.Join(dir, "absent"))(t.Context()); err != nil || len(d.Records) != 0 {
		t.Fatalf("absent directory: %+v, %v", d, err)
	}
	// One that cannot be listed is an error.
	if _, err := ExitRecords(errFS{errors.New("permission denied")}, "/run/x")(t.Context()); err == nil {
		t.Fatal("an unlistable directory read")
	}

	// No journal: the package names no journal tool or parser.
	srcs, _ := filepath.Glob("*.go")
	for _, f := range srcs {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "journalctl") || strings.Contains(string(b), "sdjournal") {
			t.Errorf("%s reads the journal", f)
		}
	}
}

// RemoveExitRecord removes by invocation ID inside the directory, and refuses
// `last` and anything that is not a plain name.
func TestRemoveExitRecord(t *testing.T) {
	var got []string
	rm := RemoveExitRecord(func(name string) error { got = append(got, name); return nil }, "/run/x")
	if err := rm(t.Context(), id(1)); err != nil || len(got) != 1 || got[0] != "/run/x/"+id(1) {
		t.Fatalf("removed %q (%v)", got, err)
	}
	for _, bad := range []string{lastName, "", "../etc", "a/b", id(1) + ".tmp"} {
		if err := rm(t.Context(), bad); err == nil {
			t.Errorf("removed %q", bad)
		}
	}
}

// The start hold's record and the version marker.
func TestStartHoldAndMarker(t *testing.T) {
	dir := t.TempDir()
	hold := filepath.Join(dir, "outcome")
	read := StartHoldRecord(os.DirFS("/"), hold)
	if h, err := read(t.Context()); err != nil || h.Refused {
		t.Fatalf("absent: %+v %v", h, err)
	}
	body := "outcome=refused\nboot_id=0f3c5b2a-1d4e-4f6a-9b8c-7d6e5f4a3b2c\nreason=Sign-in failed to start three times in a row.\n"
	if err := os.WriteFile(hold, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if h, err := read(t.Context()); err != nil || !h.Refused || h.Reason != "Sign-in failed to start three times in a row." {
		t.Fatalf("refused: %+v %v", h, err)
	}
	if err := os.WriteFile(hold, []byte("outcome=maybe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := read(t.Context()); err == nil {
		t.Fatal("a malformed hold parsed")
	}
	if err := os.Chmod(hold, 0o000); err == nil && os.Geteuid() != 0 {
		if _, err := read(t.Context()); err == nil {
			t.Fatal("an unreadable hold read")
		}
	}

	marker := filepath.Join(dir, "keycloak-version")
	mread := MarkerFile(os.DirFS("/"), marker)
	if _, err := mread(t.Context()); err == nil {
		t.Fatal("an absent marker read")
	}
	for body, want := range map[string]string{"26.8.2\n": "26.8.2", "\n": "", strings.Repeat("9", 5000): ""} {
		if err := os.WriteFile(marker, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		v, err := mread(t.Context())
		if want == "" && err == nil || want != "" && (err != nil || v != want) {
			t.Errorf("marker %q: %q, %v; want %q", body[:min(len(body), 8)], v, err, want)
		}
	}
}

// TC-979-21 (the mapping): PairState is failed when the database failed or
// Keycloak is not active, activating while the database activates under an
// active Keycloak, and active when both are.
func TestPairState(t *testing.T) {
	for _, c := range []struct {
		kc, db string
		want   string
	}{
		{"active", "failed", PairFailed},
		{"inactive", "active", PairFailed},
		{"failed", "active", PairFailed},
		{"activating", "activating", PairFailed},
		{"active", "activating", PairActivating},
		{"active", "active", PairActive},
	} {
		if got := PairState(Units{KC: Unit{ActiveState: c.kc}, DB: Unit{ActiveState: c.db}}); got != c.want {
			t.Errorf("kc %s, db %s: %s, want %s", c.kc, c.db, got, c.want)
		}
	}
	read := PairStateOf(func(context.Context) (Units, error) { return Units{}, errors.New("no bus") })
	if _, err := read(t.Context()); err == nil {
		t.Fatal("an unreadable pair read")
	}
	read = PairStateOf(func(context.Context) (Units, error) {
		return Units{KC: Unit{ActiveState: "active"}, DB: Unit{ActiveState: "active"}}, nil
	})
	if s, err := read(t.Context()); err != nil || s != PairActive {
		t.Fatalf("%s, %v", s, err)
	}
}

// errFS fails every Open.
type errFS struct{ err error }

func (e errFS) Open(string) (fs.File, error) { return nil, e.err }
