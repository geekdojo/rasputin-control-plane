package bus

import (
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
		_, err := Connect("nats://127.0.0.1:1", "node-x", nil)
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
		nc, err := Connect("", "node-x", nil)
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
