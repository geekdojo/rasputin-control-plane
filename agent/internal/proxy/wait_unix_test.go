//go:build unix

package proxy

import (
	"testing"
	"time"
)

// waitFor polls cond until it holds, failing the test if it still does not
// after within. what names the fact being waited on, so a timeout says what
// never happened.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("never happened within %s: %s", within, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
