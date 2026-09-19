package firewall

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
)

// Helpers for the "no secret in the job ledger" assertions
// (geekdojo/geekdojo-brain#493, gate 6).

type ledgerLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *ledgerLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *ledgerLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog redirects the standard logger for the rest of the test, so the
// process log can be searched for a secret.
func captureLog(t *testing.T) *ledgerLogBuffer {
	t.Helper()
	b := &ledgerLogBuffer{}
	prev := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(prev) })
	return b
}

// assertNoSentinel fails the test when any sentinel appears in got.
func assertNoSentinel(t *testing.T, where, got string, sentinels []string) {
	t.Helper()
	for _, s := range sentinels {
		if strings.Contains(got, s) {
			t.Errorf("%s carries a secret (%q): %s", where, s, got)
		}
	}
}
