// Package ledgertest holds the shared "no secret in the job ledger"
// assertion: gate 6 of the authentication methodology
// (geekdojo/geekdojo-brain#493).
//
// # The rule
//
// A workflow's ledger is everything about a job that outlives the job: its
// spec, every step's result and error, every job event, and the process log.
// All four are readable by anyone who can read a job, they are copied into
// backups, and none of them is a place a credential can be withdrawn from once
// it has landed. A passphrase-wrapped key counts as a secret: wrapping makes it
// attackable offline, not unreadable.
//
// So a workflow may pass a secret to the agent over the bus, and it may persist
// one where it belongs — and the four surfaces above must not carry it.
//
// # Why one package instead of a helper per caller
//
// This assertion was written four times, in three shapes, before it lived
// anywhere: two byte-identical copies of one helper, a second harness method
// that scanned three of the four surfaces but not the log, and a fourth that
// hand-rolled the log capture inline. Three implementations of one rule are one
// edit away from disagreeing about what the rule is, and the one nobody looks
// at is the one that stops checking the log.
//
// # Vacuity
//
// A scan of an empty ledger passes. That is the failure this package worries
// about most, because it looks exactly like success, so [Surfaces.AssertAbsent]
// refuses to run until the caller has stated where the secret DID have to
// arrive. Use [AssertPresent] for that, on the agent's command or the row that
// is meant to hold it, before asserting absence.
//
// # Failure messages
//
// Nothing here ever prints the haystack. A failing run of this assertion means
// a real secret is in a real ledger, and echoing the surface into CI output —
// which is public for this repo — would publish it a second time. The message
// names the surface, the sentinel's NAME, and nothing else.
package ledgertest

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
)

// Secret is one piece of material a workflow handles. Name is safe to print;
// Value never is.
type Secret struct {
	Name  string
	Value string
}

// Secrets builds the list from name/value pairs.
func Secrets(pairs ...string) []Secret {
	if len(pairs)%2 != 0 {
		panic("ledgertest.Secrets: odd number of arguments; want name, value pairs")
	}
	out := make([]Secret, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, Secret{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

// Every assertion below takes testing.TB rather than *testing.T. That is what
// lets this package's OWN tests drive it with a recorder and check what it
// reports — including that it never reports the secret itself.
//
// Log captures the standard logger for the rest of a test.
//
// The standard logger only: a workflow that logs through its own logger needs
// that writer passed to [Surfaces.Log] as well, and a caller that forgets is
// scanning three surfaces while believing it scanned four.
type Log struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// CaptureLog redirects log.Default()'s output into a buffer and restores the
// previous writer when the test ends.
func CaptureLog(t testing.TB) *Log {
	t.Helper()
	l := &Log{}
	prev := log.Writer()
	log.SetOutput(l)
	t.Cleanup(func() { log.SetOutput(prev) })
	return l
}

func (l *Log) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *Log) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Surfaces is one job's ledger, assembled by the caller from its own store.
//
// The fields are deliberately plain strings rather than the job types: every
// caller already has a harness that knows how to read its own store, and the
// alternative is this package importing the jobs store and every caller
// constructing one it does not otherwise need.
type Surfaces struct {
	// Spec is the persisted job spec, plus the job's own error.
	Spec string
	// Steps is every step's result and error, concatenated.
	Steps string
	// Events is every job event's data, concatenated. job.created included:
	// it carries the spec.
	Events string
	// Log is the process log captured for the duration of the job.
	Log string

	// Extra names further surfaces this workflow owns that a reader could
	// reach — an API response body, a rendered row. Keyed by a name that goes
	// into the failure message.
	Extra map[string]string

	// arrived records that the caller proved the secret reached where it was
	// supposed to. AssertAbsent refuses to run without it.
	arrived bool
}

// AssertPresent proves the test is not vacuous: it fails unless every secret
// appears in got, which is the surface the secret was actually supposed to
// reach — the agent's bus command, or the row that is meant to hold it.
//
// Call it before [Surfaces.AssertAbsent], on the same Surfaces value, so a
// workflow that quietly stopped passing the secret at all cannot read as a
// clean ledger.
func (s *Surfaces) AssertPresent(t testing.TB, where, got string, secrets []Secret) {
	t.Helper()
	for _, sec := range secrets {
		if !strings.Contains(got, sec.Value) {
			t.Fatalf("%s does not carry %s — the workflow stopped delivering it, so the "+
				"ledger assertion below would pass for the wrong reason", where, sec.Name)
		}
	}
	s.arrived = true
}

// AssertAbsent fails when any secret appears in any ledger surface.
//
// It reports every surface that carries a secret rather than stopping at the
// first, because "the spec is clean" and "the ledger is clean" are different
// answers and a caller fixing one wants to see the others.
func (s *Surfaces) AssertAbsent(t testing.TB, secrets []Secret) {
	t.Helper()
	if !s.arrived {
		t.Fatal("ledgertest: AssertAbsent called without AssertPresent. An empty ledger " +
			"passes this scan, and that looks exactly like a clean one — prove the secret " +
			"reached the agent or the row it belongs in first.")
	}
	if len(secrets) == 0 {
		t.Fatal("ledgertest: no secrets to look for")
	}

	AssertAbsentIn(t, "the job spec", s.Spec, secrets)
	AssertAbsentIn(t, "a step result or error", s.Steps, secrets)
	AssertAbsentIn(t, "a job event", s.Events, secrets)
	AssertAbsentIn(t, "the process log", s.Log, secrets)
	for name, got := range s.Extra {
		AssertAbsentIn(t, name, got, secrets)
	}
}

// AssertAbsentIn checks ONE surface for the same rule.
//
// Use it where the surface is not a job ledger — an API response body, a
// rendered row, a rendered config — and the vacuity question is answered by
// the test around it. For a workflow's ledger use [Surfaces], which asks that
// question itself.
func AssertAbsentIn(t testing.TB, where, got string, secrets []Secret) {
	t.Helper()
	for _, sec := range secrets {
		if strings.Contains(got, sec.Value) {
			// The value is NOT printed. This repo's CI logs are public, and a
			// failure here means the material is real.
			t.Errorf("%s carries %s", where, sec.Name)
		}
	}
}
