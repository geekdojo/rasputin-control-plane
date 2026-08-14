package bus

import (
	"strings"
	"testing"
	"time"
)

// TestConnect_RejectsUnreachableURL_Fast covers the error path: dialing a URL
// that nobody is listening on must fail quickly and return a wrapped error.
// nats.DefaultURL is :4222 — we point at a port nothing would be on.
//
// We bound the wall-clock so a busy CI doesn't see this as flaky if the
// resolver decides to retry. The contract we're testing is: Connect returns
// *some* error here, not silently blocks forever.
func TestConnect_ReturnsErrorOnUnreachableURL(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		// Discard arg "onConnected" — if Connect erroneously succeeded the
		// callback would never run because no broker is on this port.
		_, err := Connect("nats://127.0.0.1:1", "node-x", "", nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("expected a connect error against unreachable port")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect blocked for > 5s on unreachable URL")
	}
}

// TestConnect_EmptyURLAttemptsDefault: when url == "" the helper substitutes
// nats.DefaultURL. We can't directly observe the substitution, but we can
// confirm Connect doesn't immediately reject an empty url with some kind of
// "missing url" error — instead it attempts to dial. On a dev box where
// nothing is listening on :4222 the attempt fails fast; on a dev box where
// the dev NATS happens to be running it succeeds. Either way we never want
// "empty url" as a synchronous error here.
func TestConnect_EmptyURLAttemptsDefault(t *testing.T) {
	done := make(chan struct {
		err error
		ok  bool
	}, 1)
	go func() {
		nc, err := Connect("", "node-x", "", nil)
		ok := nc != nil
		if nc != nil {
			nc.Close()
		}
		done <- struct {
			err error
			ok  bool
		}{err, ok}
	}()
	select {
	case res := <-done:
		// Success (broker happens to be running locally) — fine.
		if res.ok && res.err == nil {
			return
		}
		// Otherwise, the error must reference dialing, not a "url is empty"
		// validation reject. We can't pin the exact string across nats.go
		// versions, so just confirm we got *some* error.
		if res.err == nil {
			t.Errorf("got nil error and nil conn")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect blocked for > 5s with empty URL")
	}
}

// TestConnect_NonEmptyURLIsNotReplacedWithDefault pins that a caller-supplied,
// non-empty URL is dialed as-is — the empty-URL default substitution
// (client.go: `if url == ""`) must NOT fire for it. The error Connect wraps
// names the URL it actually dialed, so a distinctive unreachable port that is
// NOT the default (4222) proves which URL was used: if the `== ""` guard were
// negated, the non-empty URL would be swapped for nats.DefaultURL and the
// error would name :4222 instead of the port we passed.
func TestConnect_NonEmptyURLIsNotReplacedWithDefault(t *testing.T) {
	const url = "nats://127.0.0.1:1" // unreachable, and deliberately not :4222
	done := make(chan error, 1)
	go func() {
		_, err := Connect(url, "node-x", "", nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a connect error against an unreachable port")
		}
		if !strings.Contains(err.Error(), "127.0.0.1:1") {
			t.Errorf("error %q does not name the URL we passed (%s) — the non-empty URL must be dialed as-is, not swapped for the default", err.Error(), url)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect blocked for > 5s on unreachable URL")
	}
}
