package busauth

// Loopback earns no trust on the bus (geekdojo-brain#140, decided 2026-09-17).
// Until then the callout admitted any tokenless connection from 127.0.0.1 and
// let it claim whatever node id it presented, so any local user on a
// controlplane could take any node's command subjects. This drives the real
// embedded nats-server, with auth enforced and the real callout responder, to
// pin the replacement on the wire:
//
//   - a tokenless client on loopback claiming another node's id is refused,
//     and so is one claiming the controlplane's own id;
//   - the controlplane's agent, holding the token the api minted into its
//     file, connects and works;
//   - that file deleted and the api "restarted" (EnsureAgentToken again)
//     re-mints: the old session is closed, the old token refused, and a client
//     that reads the file again on reconnect is back on the bus.
//
// It also discharges geekdojo-brain#107's loopback item: loopback without a
// token is refused.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

func TestBus_LoopbackWithoutATokenIsRefused(t *testing.T) {
	eb := startEnforcedBus(t, "127.0.0.1")
	ctx := context.Background()
	api := eb.srv.Conn()

	// The node whose identity a local process would want: connected, with its
	// own bound token.
	victimTok, _, err := eb.tokens.MintBound(ctx, "compute", "compute-1", "compute")
	if err != nil {
		t.Fatal(err)
	}
	victim, err := connect(eb.url, "compute-1", victimTok)
	if err != nil {
		t.Fatalf("compute-1 with its token: %v", err)
	}
	defer victim.Close()
	assertNodeRoundTrip(t, api, victim, "compute-1")

	// The controlplane's own token exists too: holding the file is the only
	// way to use it.
	path := filepath.Join(t.TempDir(), "bus", proto.BusAgentTokenFileName)
	if _, err := eb.tokens.EnsureAgentToken(ctx, path, "cp-1"); err != nil {
		t.Fatalf("EnsureAgentToken: %v", err)
	}

	for _, claim := range []string{"compute-1", "cp-1", "never-enrolled"} {
		nc, err := connect(eb.url, claim, "")
		if err == nil {
			nc.Close()
			t.Fatalf("a tokenless loopback client claiming %q was admitted", claim)
		}
		if !errors.Is(err, nats.ErrAuthorization) {
			t.Fatalf("a tokenless loopback client claiming %q failed with %v, want an authorization violation", claim, err)
		}
	}
	// Nor does another node's token, or the controlplane's, make a loopback
	// client someone else.
	for claim, tok := range map[string]string{"cp-1": victimTok, "compute-1": readTokenFile(t, path)} {
		if nc, err := connect(eb.url, claim, tok); err == nil {
			nc.Close()
			t.Fatalf("a loopback client claiming %q with another node's token was admitted", claim)
		}
	}

	// The controlplane's agent, with the token from its file, is admitted and
	// scoped to its own node.
	cp, err := connect(eb.url, "cp-1", readTokenFile(t, path))
	if err != nil {
		t.Fatalf("the controlplane agent with its minted token: %v", err)
	}
	defer cp.Close()
	assertNodeRoundTrip(t, api, cp, "cp-1")
}

func TestBus_DeletedAgentTokenReMintsAndTheAgentRejoins(t *testing.T) {
	eb := startEnforcedBus(t, "127.0.0.1")
	ctx := context.Background()
	api := eb.srv.Conn()
	path := filepath.Join(t.TempDir(), "bus", proto.BusAgentTokenFileName)
	if _, err := eb.tokens.EnsureAgentToken(ctx, path, "cp-1"); err != nil {
		t.Fatal(err)
	}
	old := readTokenFile(t, path)

	// A client wired as the agent is: the token is read from the file on
	// every connect attempt, never captured once.
	var readErrs atomic.Int32
	lost := make(chan struct{}, 1)
	back := make(chan struct{}, 1)
	notify := func(ch chan struct{}) { // never block nats.go's callback goroutine
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	agent, err := nats.Connect(eb.url,
		nats.UserInfoHandler(func() (string, string) {
			b, err := os.ReadFile(path)
			if err != nil {
				readErrs.Add(1)
				return "cp-1", ""
			}
			return "cp-1", strings.TrimSpace(string(b))
		}),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(20*time.Millisecond),
		nats.IgnoreAuthErrorAbort(),
		nats.DisconnectErrHandler(func(*nats.Conn, error) { notify(lost) }),
		nats.ReconnectHandler(func(*nats.Conn) { notify(back) }),
	)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	defer agent.Close()
	assertNodeRoundTrip(t, api, agent, "cp-1")

	// The file is lost, and the api restarts: it mints a new token, writes
	// it, and revokes the old one — which closes the agent's session.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	reason, err := eb.tokens.EnsureAgentToken(ctx, path, "cp-1")
	if err != nil || reason == "" {
		t.Fatalf("EnsureAgentToken after the file was deleted = (%q, %v), want a re-mint", reason, err)
	}
	select {
	case <-lost:
	case <-time.After(busWaitLimit):
		t.Fatalf("revoking the replaced token did not close the agent's session within %s", busWaitLimit)
	}
	select {
	case <-back:
	case <-time.After(busWaitLimit):
		t.Fatalf("the agent did not reconnect with the re-minted token within %s (status %v)", busWaitLimit, agent.Status())
	}
	assertNodeRoundTrip(t, api, agent, "cp-1")

	if nc, err := connect(eb.url, "cp-1", old); err == nil {
		nc.Close()
		t.Fatal("the replaced token still authenticates")
	}
	if n := readErrs.Load(); n != 0 {
		t.Errorf("the token file was unreadable on %d connect attempt(s); the api writes it before revoking the old token", n)
	}
}
