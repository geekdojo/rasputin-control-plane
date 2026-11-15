package osoutcome

import "testing"

// exitSource declares the identity service's exit record the way
// identitystate does (geekdojo/geekdojo-brain#979).
var exitSource = Source{
	Kind:   "identity.service_exit",
	Fields: []string{FieldInvocationID, FieldExitCode, FieldExitStatus},
	Outcomes: map[string]Verdict{
		"success": OK, "exit-code": Alert, "signal": Alert, "oom-kill": Alert,
	},
}

func exitRec(id, code, status string) []byte {
	return []byte("outcome=exit-code\ninvocation_id=" + id + "\nexit_code=" + code + "\nexit_status=" + status + "\n")
}

// The exit record's three fields parse, empty exit_code and exit_status
// included, and each malformed value is refused.
func TestParse_ExitFields(t *testing.T) {
	for _, c := range []struct{ code, status string }{{"exited", "3"}, {"killed", "KILL"}, {"dumped", "SEGV"}, {"", ""}} {
		rec, err := Parse(exitSource, exitRec(testRun, c.code, c.status))
		if err != nil {
			t.Fatalf("exit_code=%q exit_status=%q: %v", c.code, c.status, err)
		}
		if rec.InvocationID != testRun || rec.ExitCode != c.code || rec.ExitStatus != c.status {
			t.Errorf("record = %+v", rec)
		}
	}
	for name, b := range map[string][]byte{
		"upper-case id":   exitRec("0123456789ABCDEF0123456789ABCDEF", "exited", "3"),
		"short id":        exitRec("0123", "exited", "3"),
		"unknown code":    exitRec(testRun, "vanished", "3"),
		"bad status":      exitRec(testRun, "exited", "three"),
		"too long status": exitRec(testRun, "exited", "1234"),
	} {
		if _, err := Parse(exitSource, b); err == nil {
			t.Errorf("%s: parsed, want a refusal", name)
		}
	}
}

// TC-979-15 (ReadKind's half): ReadKind reads the one declared record of the
// kind it names into the ledger, and refuses a kind that is not declared
// without reading anything.
func TestReadKind(t *testing.T) {
	h := newHarness(t)
	h.write(t, 1, initRec("failed", testBoot, "The store did not initialise."))
	h.write(t, 0, sealRec("created", testBoot, testKeyID, "Made."))
	r := h.reader(t)
	if err := r.ReadKind(t.Context(), "os.store_init"); err != nil {
		t.Fatal(err)
	}
	if got := h.jobs(t, "os.store_init"); len(got) != 1 {
		t.Fatalf("os.store_init jobs = %d, want 1", len(got))
	}
	if got := h.jobs(t, "os.seal_key"); len(got) != 0 {
		t.Fatalf("os.seal_key jobs = %d, want 0: ReadKind read another kind", len(got))
	}
	if err := r.ReadKind(t.Context(), "os.not_declared"); err == nil {
		t.Fatal("ReadKind of an undeclared kind succeeded")
	}
}
