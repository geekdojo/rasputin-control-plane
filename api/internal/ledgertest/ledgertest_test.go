package ledgertest

import (
	"fmt"
	"log"
	"strings"
	"testing"
)

// The assertion in this package is the one every workflow's ledger test leans
// on, so the ways it can go wrong are the ways all of them go wrong at once.
// Two matter more than the rest:
//
//   - it passes when it should fail — a secret is in a ledger and nobody
//     hears about it;
//   - it PRINTS the secret when it fails. This repo's CI logs are public, and
//     a failure here means the material is real.
//
// Both are checked below against a recorder that stands in for *testing.T.

// recorder captures what the assertion would have reported.
type recorder struct {
	testing.TB
	errors []string
	fatal  string
	failed bool
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.failed = true
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}
func (r *recorder) Fatal(args ...any) {
	r.failed = true
	r.fatal = fmt.Sprintln(args...)
	panic(sentinelFatal)
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = true
	r.fatal = fmt.Sprintf(format, args...)
	panic(sentinelFatal)
}
func (r *recorder) Cleanup(func()) {}

func (r *recorder) all() string { return strings.Join(r.errors, "\n") + "\n" + r.fatal }

const sentinelFatal = "ledgertest: recorded fatal"

// run calls fn with a recorder, absorbing the panic a Fatal raises.
func run(fn func(tb *recorder)) *recorder {
	r := &recorder{}
	func() {
		defer func() {
			if p := recover(); p != nil && p != sentinelFatal {
				panic(p)
			}
		}()
		fn(r)
	}()
	return r
}

const theSecret = "SENTINEL-DO-NOT-PRINT-ME"

func secrets() []Secret { return Secrets("the PPPoE password", theSecret) }

func TestAssertAbsent_FindsASecretInEverySurface(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(*Surfaces)
		where string
	}{
		{"the spec", func(s *Surfaces) { s.Spec = "x" + theSecret }, "the job spec"},
		{"a step", func(s *Surfaces) { s.Steps = "x" + theSecret }, "a step result or error"},
		{"an event", func(s *Surfaces) { s.Events = "x" + theSecret }, "a job event"},
		{"the log", func(s *Surfaces) { s.Log = "x" + theSecret }, "the process log"},
		{"an extra surface", func(s *Surfaces) {
			s.Extra = map[string]string{"the rendered row": theSecret}
		}, "the rendered row"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := run(func(tb *recorder) {
				s := &Surfaces{}
				s.AssertPresent(tb, "the agent's command", theSecret, secrets())
				tc.build(s)
				s.AssertAbsent(tb, secrets())
			})
			if !r.failed {
				t.Fatalf("a secret in %s was not reported", tc.name)
			}
			if !strings.Contains(r.all(), tc.where) {
				t.Errorf("the failure does not name %q: %s", tc.where, r.all())
			}
			if !strings.Contains(r.all(), "the PPPoE password") {
				t.Errorf("the failure does not name the secret: %s", r.all())
			}
			// The one thing it must never do.
			if strings.Contains(r.all(), theSecret) {
				t.Errorf("the failure PRINTED the secret. CI logs for this repo are " +
					"public, so a real leak would be published a second time by the " +
					"test that found it.")
			}
		})
	}
}

func TestAssertAbsent_PassesOnACleanLedger(t *testing.T) {
	r := run(func(tb *recorder) {
		s := &Surfaces{
			Spec:   `{"archiveKeyId":"key-1"}`,
			Steps:  `{"hash":"abc"}`,
			Events: `{"kind":"job.created"}`,
			Log:    "claim: staged key key-1",
			Extra:  map[string]string{"the row": `{"keyId":"key-1"}`},
		}
		s.AssertPresent(tb, "the agent's command", theSecret, secrets())
		s.AssertAbsent(tb, secrets())
	})
	if r.failed {
		t.Fatalf("a clean ledger was reported as carrying a secret: %s", r.all())
	}
}

// The vacuity guard. A scan of an empty ledger passes, and that looks exactly
// like a clean one — so the assertion refuses to run at all until the caller
// has said where the secret really did arrive.
func TestAssertAbsent_RefusesToScanWithoutTheVacuityCheck(t *testing.T) {
	r := run(func(tb *recorder) {
		(&Surfaces{}).AssertAbsent(tb, secrets())
	})
	if !r.failed {
		t.Fatal("an empty ledger passed with no vacuity check; that is the failure " +
			"this package worries about most")
	}
	if !strings.Contains(r.fatal, "AssertPresent") {
		t.Errorf("the refusal does not say what is missing: %s", r.fatal)
	}
}

func TestAssertAbsent_RefusesAnEmptySecretList(t *testing.T) {
	r := run(func(tb *recorder) {
		s := &Surfaces{}
		s.AssertPresent(tb, "the agent's command", theSecret, secrets())
		s.AssertAbsent(tb, nil)
	})
	if !r.failed || !strings.Contains(r.fatal, "no secrets") {
		t.Fatalf("scanning for nothing was allowed: %s", r.all())
	}
}

func TestAssertPresent_FailsWhenTheSecretNeverArrived(t *testing.T) {
	r := run(func(tb *recorder) {
		s := &Surfaces{}
		s.AssertPresent(tb, "the agent's command", "something else entirely", secrets())
	})
	if !r.failed {
		t.Fatal("a workflow that stopped delivering the secret read as a clean ledger")
	}
	if !strings.Contains(r.fatal, "the PPPoE password") {
		t.Errorf("the failure does not name the secret: %s", r.fatal)
	}
	if strings.Contains(r.fatal, theSecret) {
		t.Error("the failure printed the secret")
	}
}

func TestSecrets(t *testing.T) {
	got := Secrets("a", "1", "b", "2")
	if len(got) != 2 || got[0] != (Secret{"a", "1"}) || got[1] != (Secret{"b", "2"}) {
		t.Fatalf("Secrets = %+v", got)
	}
	if len(Secrets()) != 0 {
		t.Fatal("Secrets() should be empty")
	}

	defer func() {
		if recover() == nil {
			t.Error("an odd number of arguments silently dropped one, which would " +
				"leave a secret unsearched for")
		}
	}()
	Secrets("a")
}

func TestCaptureLog(t *testing.T) {
	prev := log.Writer()
	l := CaptureLog(t)
	log.Printf("hello %s", "world")
	if got := l.String(); !strings.Contains(got, "hello world") {
		t.Fatalf("CaptureLog did not capture the standard logger: %q", got)
	}
	// Cleanup runs at the end of this test; the writer is swapped now.
	if log.Writer() == prev {
		t.Fatal("CaptureLog did not redirect the standard logger")
	}
}

func TestAssertAbsentIn(t *testing.T) {
	r := run(func(tb *recorder) {
		AssertAbsentIn(tb, "the response body", `{"secret":"`+theSecret+`"}`, secrets())
	})
	if !r.failed {
		t.Fatal("a secret in a one-off surface was not reported")
	}
	if strings.Contains(r.all(), theSecret) {
		t.Error("the failure printed the secret")
	}

	clean := run(func(tb *recorder) {
		AssertAbsentIn(tb, "the response body", `{"secretSet":true}`, secrets())
	})
	if clean.failed {
		t.Fatalf("a clean surface was reported: %s", clean.all())
	}
}
