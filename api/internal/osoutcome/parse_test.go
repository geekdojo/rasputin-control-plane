package osoutcome

import (
	"path/filepath"
	"strings"
	"testing"
)

const (
	testBoot  = "0f3c5b2a-1d4e-4f6a-9b8c-7d6e5f4a3b2c"
	testBoot2 = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	testRun   = "0123456789abcdef0123456789abcdef"
	testRun2  = "fedcba9876543210fedcba9876543210"
	testKeyID = "rasputin-3e1c9a52-7b4d-4c8e-a0f1-2d3b4c5e6f70"
)

// testSources mirrors the three production declarations under dir.
func testSources(dir string) []Source {
	return []Source{
		{
			Kind: "os.seal_key", Path: filepath.Join(dir, "seal"),
			Fields: []string{FieldBootID, FieldKeyID, FieldReason}, KeyField: FieldBootID,
			Outcomes: map[string]Verdict{"created": OK, "untouched": OK, "failed": Alert, "refused": Alert},
			Title:    "seal key",
		},
		{
			Kind: "os.store_init", Path: filepath.Join(dir, "init"),
			Fields: []string{FieldBootID, FieldReason}, KeyField: FieldBootID,
			Outcomes: map[string]Verdict{"initialised": OK, "failed": Alert},
			Title:    "store init", AfterStoreRestart: true,
		},
		{
			Kind: "os.store_provision", Path: filepath.Join(dir, "provision"),
			Fields: []string{FieldBootID, FieldRunID, FieldReason}, KeyField: FieldRunID,
			Outcomes: map[string]Verdict{"applied": OK, "unchanged": OK, "failed": Alert},
			Title:    "store provision", AfterStoreRestart: true, StartUnit: "rasputin-store-provision.service",
		},
	}
}

func sealRec(outcome, boot, keyID, reason string) string {
	return "outcome=" + outcome + "\nboot_id=" + boot + "\nkey_id=" + keyID + "\nreason=" + reason + "\n"
}

func initRec(outcome, boot, reason string) string {
	return "outcome=" + outcome + "\nboot_id=" + boot + "\nreason=" + reason + "\n"
}

func provRec(outcome, boot, run, reason string) string {
	return "outcome=" + outcome + "\nboot_id=" + boot + "\nrun_id=" + run + "\nreason=" + reason + "\n"
}

// recordFor is a well-formed record for src with the given outcome.
func recordFor(src Source, outcome string) string {
	switch src.Kind {
	case "os.seal_key":
		return sealRec(outcome, testBoot, testKeyID, "The seal key is in place.")
	case "os.store_init":
		return initRec(outcome, testBoot, "The store initialised.")
	default:
		return provRec(outcome, testBoot, testRun, "The store is provisioned.")
	}
}

// TC-833-01: every outcome of every vocabulary parses into the fixture's
// values.
func TestParse_EachOutcome(t *testing.T) {
	for _, src := range testSources(t.TempDir()) {
		for outcome := range src.Outcomes {
			rec, err := Parse(src, []byte(recordFor(src, outcome)))
			if err != nil {
				t.Fatalf("%s %s: %v", src.Kind, outcome, err)
			}
			if rec.Outcome != outcome || rec.BootID != testBoot || rec.Reason == "" {
				t.Errorf("%s %s: record %+v", src.Kind, outcome, rec)
			}
			switch src.Kind {
			case "os.seal_key":
				if rec.KeyID != testKeyID || rec.RunID != "" {
					t.Errorf("seal key record %+v", rec)
				}
			case "os.store_init":
				if rec.KeyID != "" || rec.RunID != "" {
					t.Errorf("store init record %+v", rec)
				}
			default:
				if rec.RunID != testRun || rec.KeyID != "" {
					t.Errorf("store provision record %+v", rec)
				}
			}
		}
	}
}

// TC-833-02: removing any one declared line, outcome included, is an error.
func TestParse_MissingField(t *testing.T) {
	for _, src := range testSources(t.TempDir()) {
		var ok string
		for w, v := range src.Outcomes {
			if v == OK {
				ok = w
			}
		}
		lines := strings.SplitAfter(recordFor(src, ok), "\n")
		lines = lines[:len(lines)-1] // the empty tail after the last newline
		for i := range lines {
			cut := strings.Join(append(append([]string{}, lines[:i]...), lines[i+1:]...), "")
			if rec, err := Parse(src, []byte(cut)); err == nil {
				t.Errorf("%s without line %d: parsed %+v", src.Kind, i, rec)
			}
		}
	}
}

// TC-833-03: an outcome outside the source's vocabulary is an error.
func TestParse_UnknownOutcome(t *testing.T) {
	seal := testSources(t.TempDir())[0]
	for _, o := range []string{"bogus", "applied"} {
		if _, err := Parse(seal, []byte(sealRec(o, testBoot, "-", "A sentence."))); err == nil {
			t.Errorf("outcome %q parsed", o)
		}
	}
}

// TC-833-04: a line with no '=', a blank line, and no trailing newline.
func TestParse_MalformedLine(t *testing.T) {
	seal := testSources(t.TempDir())[0]
	good := sealRec("untouched", testBoot, "-", "A sentence.")
	for name, b := range map[string]string{
		"no =":       good + "garbage\n",
		"blank line": "outcome=untouched\n\nboot_id=" + testBoot + "\nkey_id=-\nreason=A sentence.\n",
		"no newline": strings.TrimSuffix(good, "\n"),
		"empty":      "",
	} {
		if _, err := Parse(seal, []byte(b)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// TC-833-05: a duplicated key and an unknown key are errors.
func TestParse_ExactLineSet(t *testing.T) {
	seal := testSources(t.TempDir())[0]
	good := sealRec("untouched", testBoot, "-", "A sentence.")
	for name, b := range map[string]string{
		"duplicate outcome": good + "outcome=untouched\n",
		"unknown key":       good + "changed=1\n",
		"undeclared field":  good + "run_id=" + testRun + "\n",
	} {
		if _, err := Parse(seal, []byte(b)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// TC-833-06: boot_id and run_id are typed.
func TestParse_TypedIDs(t *testing.T) {
	srcs := testSources(t.TempDir())
	initSrc, prov := srcs[1], srcs[2]
	for _, b := range []string{"-", strings.ToUpper(testBoot), "not-a-uuid", testBoot + "0"} {
		if _, err := Parse(initSrc, []byte(initRec("initialised", b, "Done."))); err == nil {
			t.Errorf("boot_id %q parsed", b)
		}
	}
	for _, r := range []string{"-", testRun[:31], strings.ToUpper(testRun), testRun + "0"} {
		if _, err := Parse(prov, []byte(provRec("applied", testBoot, r, "Done."))); err == nil {
			t.Errorf("run_id %q parsed", r)
		}
	}
	if _, err := Parse(initSrc, []byte(initRec("initialised", testBoot, "Done."))); err != nil {
		t.Errorf("lowercase uuid boot_id: %v", err)
	}
	if _, err := Parse(prov, []byte(provRec("applied", testBoot, testRun, "Done."))); err != nil {
		t.Errorf("32-hex run_id: %v", err)
	}
}

// TC-833-07: key_id is - or rasputin-<uuid>.
func TestParse_KeyID(t *testing.T) {
	seal := testSources(t.TempDir())[0]
	for _, k := range []string{"-", testKeyID} {
		rec, err := Parse(seal, []byte(sealRec("created", testBoot, k, "Made.")))
		if err != nil || rec.KeyID != k {
			t.Errorf("key_id %q: %+v, %v", k, rec, err)
		}
	}
	for _, k := range []string{"rasputin-../x", "abc", ""} {
		if _, err := Parse(seal, []byte(sealRec("created", testBoot, k, "Made."))); err == nil {
			t.Errorf("key_id %q parsed", k)
		}
	}
}

// TC-833-08: reason is 1 to 1024 bytes with no C0 control but tab.
func TestParse_Reason(t *testing.T) {
	initSrc := testSources(t.TempDir())[1]
	for name, r := range map[string]string{
		"empty":     "",
		"1025":      strings.Repeat("a", 1025),
		"CR":        "a\rb",
		"ESC":       "a\x1bb",
		"NUL":       "a\x00b",
		"unit sep":  "a\x1fb",
		"just ctrl": "\x01",
	} {
		if _, err := Parse(initSrc, []byte(initRec("failed", testBoot, r))); err == nil {
			t.Errorf("reason %s parsed", name)
		}
	}
	for name, r := range map[string]string{"tab": "a\tb", "1024": strings.Repeat("a", 1024), "space": " "} {
		rec, err := Parse(initSrc, []byte(initRec("failed", testBoot, r)))
		if err != nil || rec.Reason != r {
			t.Errorf("reason %s: %v", name, err)
		}
	}
}

// TC-833-09: over 4096 bytes, or invalid UTF-8, is an error; 4096 parses.
func TestParse_SizeAndEncoding(t *testing.T) {
	initSrc := testSources(t.TempDir())[1]
	base := initRec("failed", testBoot, "")
	pad := func(n int) string { return initRec("failed", testBoot, strings.Repeat("a", n-len(base))) }
	// A record can only reach 4 KiB through an over-long reason, so the cap
	// is told apart from the reason check by its error.
	if _, err := Parse(initSrc, []byte(pad(4097))); err == nil || !strings.Contains(err.Error(), "4096") {
		t.Errorf("4097 bytes: %v, want the size cap", err)
	}
	if _, err := Parse(initSrc, []byte(initRec("failed", testBoot, "bad \xff byte"))); err == nil ||
		!strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("invalid UTF-8: %v", err)
	}
	if _, err := Parse(initSrc, []byte(pad(4096))); err == nil || strings.Contains(err.Error(), "4096") {
		t.Errorf("4096 bytes: %v, want past the size cap (and refused for its reason length)", err)
	}
}
