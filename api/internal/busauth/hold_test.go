package busauth

import (
	"errors"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
)

// While the hold answers true, the real callout refuses every connection —
// the loopback agent's included, which otherwise needs no token — with the
// hold's reason; once it answers false the same client is admitted. This is
// what keeps a node from registering between the api's own connection
// rejoining a replaced server and job intake reopening
// (bustls.Service.Switching).
func TestResponder_HoldRefusesEveryConnectionUntilReleased(t *testing.T) {
	eb := startEnforcedBus(t, "127.0.0.1")
	eb.resp.SetHold(func() (bool, string) { return true, "the bus is switching to TLS-only; retry" })

	nc, err := connect(eb.url, "cp-1", "")
	if err == nil {
		nc.Close()
		t.Fatal("a loopback connection was admitted while the responder was held")
	}
	if !errors.Is(err, nats.ErrAuthorization) && !strings.Contains(strings.ToLower(err.Error()), "authorization") {
		t.Fatalf("held connection refused with %v, want an authorization error", err)
	}

	eb.resp.SetHold(nil)
	nc, err = connect(eb.url, "cp-1", "")
	if err != nil {
		t.Fatalf("loopback connection after the hold was cleared: %v", err)
	}
	nc.Close()
}
