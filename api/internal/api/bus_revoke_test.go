package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Functional test for revoke = force-disconnect (certificates.md §4.2(1);
// geekdojo-brain#247): a real embedded bus with auth enforced, the real
// auth-callout responder, the real HTTP handlers, and agent clients configured
// the way the agent configures its own (agent/internal/bus/client.go).
//
// Transport: every client dials 127.0.0.1, the controlplane's own agent and
// the nodes alike. Loopback earns no trust (geekdojo-brain#140), so the address
// makes no difference to authentication: each presents a token bound to its
// node id, the controlplane's agent the one the api mints for it at start.
//
// Every wait is event-driven (connection callbacks, server state read
// synchronously) and bounded by revokeWaitLimit.

const revokeWaitLimit = 10 * time.Second

// startAuthBus brings up an auth-enforced bus on loopback whose callout
// validates against tokens — the store the api handlers revoke through — wired
// as main.go does, and returns the server and the URL every agent dials.
func startAuthBus(t *testing.T, tokens *busauth.Store) (srv *bus.Server, url string) {
	t.Helper()
	dir := t.TempDir()
	issuer, err := busauth.EnsureIssuer(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nats"), 0o755); err != nil {
		t.Fatalf("mkdir nats: %v", err)
	}
	srv, err = bus.Start(context.Background(), bus.Config{
		Host: "127.0.0.1", Port: -1,
		StoreDir:        filepath.Join(dir, "nats"),
		AuthEnforce:     true,
		IssuerPublicKey: issuer.PublicKey(),
		APIUser:         "rasputin-api",
		APIPass:         "test-secret",
	})
	if err != nil {
		t.Fatalf("bus.Start: %v", err)
	}
	t.Cleanup(srv.Stop)
	tokens.TrackSessions(srv)
	resp := busauth.NewResponder(srv.Conn(), issuer, tokens)
	if err := resp.Start(); err != nil {
		t.Fatalf("responder.Start: %v", err)
	}
	t.Cleanup(resp.Stop)
	return srv, srv.ClientURL()
}

// testAgent is a connected agent-equivalent client and the events it saw.
type testAgent struct {
	name         string
	nc           *nats.Conn
	cid          uint64
	disconnected chan struct{}
	reconnected  chan struct{}
	authRefused  chan struct{}
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default: // already signalled; never block a client callback
	}
}

// dialAgent connects nodeID with the agent's own reconnect policy: reconnect
// forever, and keep reconnecting through auth errors (IgnoreAuthErrorAbort) —
// which is what makes "the reconnect is refused" observable as a repeating
// authorization error rather than a closed connection.
func dialAgent(t *testing.T, addr, nodeID, token string) *testAgent {
	t.Helper()
	a := &testAgent{
		name:         nodeID,
		disconnected: make(chan struct{}, 1),
		reconnected:  make(chan struct{}, 1),
		authRefused:  make(chan struct{}, 1),
	}
	opts := []nats.Option{
		nats.Name("rasputin-agent/" + nodeID),
		nats.UserInfo(nodeID, token),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(50 * time.Millisecond),
		nats.IgnoreAuthErrorAbort(),
		nats.DisconnectErrHandler(func(*nats.Conn, error) { signal(a.disconnected) }),
		nats.ReconnectHandler(func(*nats.Conn) { signal(a.reconnected) }),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			if errors.Is(err, nats.ErrAuthorization) {
				signal(a.authRefused)
			}
		}),
	}
	nc, err := nats.Connect(addr, opts...)
	if err != nil {
		t.Fatalf("agent %s connect: %v", nodeID, err)
	}
	t.Cleanup(nc.Close)
	cid, err := nc.GetClientID()
	if err != nil {
		t.Fatalf("agent %s client id: %v", nodeID, err)
	}
	a.nc, a.cid = nc, cid
	return a
}

func waitEvent(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(revokeWaitLimit):
		t.Fatalf("%s did not happen within %s", what, revokeWaitLimit)
	}
}

// assertEvicted: the server no longer holds the connection (read synchronously
// — the revoke closed it before returning), the client saw the disconnect, its
// reconnect was refused by the callout, and it never got back on.
func assertEvicted(t *testing.T, srv *bus.Server, a *testAgent) {
	t.Helper()
	if srv.ClientOpen(srv.ServerID(), a.cid) {
		t.Fatalf("%s: server still holds connection %d after the revoke returned", a.name, a.cid)
	}
	waitEvent(t, a.disconnected, a.name+"'s client observing the disconnect")
	waitEvent(t, a.authRefused, a.name+"'s reconnect being refused with an authorization violation")
	if len(a.reconnected) != 0 || a.nc.IsConnected() {
		t.Fatalf("%s reconnected with a revoked credential (status %v)", a.name, a.nc.Status())
	}
}

// assertLive: the server still holds the same connection, the client never
// saw a disconnect, and a round trip to the server completes on it.
func assertLive(t *testing.T, srv *bus.Server, a *testAgent) {
	t.Helper()
	if !srv.ClientOpen(srv.ServerID(), a.cid) {
		t.Fatalf("%s: connection %d was closed, but its credential was not revoked", a.name, a.cid)
	}
	if err := a.nc.FlushTimeout(revokeWaitLimit); err != nil {
		t.Fatalf("%s: round trip on the live connection failed: %v", a.name, err)
	}
	if len(a.disconnected) != 0 {
		t.Fatalf("%s: client saw a disconnect, but its credential was not revoked", a.name)
	}
	if cid, err := a.nc.GetClientID(); err != nil || cid != a.cid {
		t.Fatalf("%s: connection id is %d (err %v), want the original %d — it reconnected", a.name, cid, err, a.cid)
	}
}

func mintBoundViaAPI(t *testing.T, f *apiFixture, cookie *http.Cookie, nodeID string) (token, id string) {
	t.Helper()
	w := f.do(t, http.MethodPost, "/api/bus/tokens", `{"role":"compute","label":"test","nodeId":"`+nodeID+`"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint for %s = %d %s", nodeID, w.Code, w.Body.String())
	}
	var body struct{ ID, Token string }
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode mint: %v", err)
	}
	return body.Token, body.ID
}

func TestBusRevoke_ForceDisconnectsLiveSessions(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	busSrv, busURL := startAuthBus(t, f.srv.busTokens)

	tokA, idA := mintBoundViaAPI(t, f, cookie, "node-a")
	tokB, _ := mintBoundViaAPI(t, f, cookie, "node-b")
	tokRm, _ := mintBoundViaAPI(t, f, cookie, "node-rm")
	_, idOff := mintBoundViaAPI(t, f, cookie, "node-off")
	seedNodeWithCascade(t, f, "node-rm")

	// The controlplane's co-located agent, with the token the api mints for it
	// at start.
	cpTokenFile := filepath.Join(t.TempDir(), "bus", proto.BusAgentTokenFileName)
	if _, err := f.srv.busTokens.EnsureAgentToken(context.Background(), cpTokenFile, "cp-1"); err != nil {
		t.Fatalf("EnsureAgentToken: %v", err)
	}
	cpToken, err := os.ReadFile(cpTokenFile)
	if err != nil {
		t.Fatal(err)
	}
	cp := dialAgent(t, busURL, "cp-1", strings.TrimSpace(string(cpToken)))
	a := dialAgent(t, busURL, "node-a", tokA)
	b := dialAgent(t, busURL, "node-b", tokB)
	rm := dialAgent(t, busURL, "node-rm", tokRm)

	// Premise: every connection is on the token path — without a token it is
	// refused, loopback or not. If this ever stopped holding, an agent above
	// could be admitted without a token and never recorded for revocation.
	for _, id := range []string{"node-x", "cp-1", "node-b"} {
		if nc, err := nats.Connect(busURL, nats.UserInfo(id, ""), nats.MaxReconnects(0)); err == nil {
			nc.Close()
			t.Fatalf("tokenless connection as %s over loopback was accepted", id)
		} else if !errors.Is(err, nats.ErrAuthorization) {
			t.Fatalf("tokenless connection as %s failed with %v, want an authorization violation", id, err)
		}
	}

	// geekdojo-brain#140: the one revoke the api refuses. Proven here rather
	// than only at the handler, because the claim is about the bus — the
	// controlplane's agent must still be ON it afterwards.
	t.Run("revoking the controlplane's own agent token is refused and its session survives", func(t *testing.T) {
		cpID := busauth.HashToken(strings.TrimSpace(string(cpToken)))
		w := f.do(t, http.MethodDelete, "/api/bus/tokens/"+cpID, "", cookie)
		if w.Code != http.StatusConflict {
			t.Fatalf("revoke of the controlplane agent's token = %d %s, want 409", w.Code, w.Body.String())
		}
		assertLive(t, busSrv, cp)
		assertLive(t, busSrv, a)
		assertLive(t, busSrv, b)
		// Still a working credential: a fresh connection with it is admitted.
		again := dialAgent(t, busURL, "cp-1", strings.TrimSpace(string(cpToken)))
		again.nc.Close()
	})

	t.Run("API revoke closes the token's live session and its reconnect is refused", func(t *testing.T) {
		w := f.do(t, http.MethodDelete, "/api/bus/tokens/"+idA, "", cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("revoke = %d %s, want 200", w.Code, w.Body.String())
		}
		var got revokeBusTokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode revoke response: %v", err)
		}
		if got.ID != idA || got.Disconnected != 1 {
			t.Errorf("revoke response = %+v, want {ID:%s Disconnected:1}", got, idA)
		}
		assertEvicted(t, busSrv, a)
		assertLive(t, busSrv, b)
		assertLive(t, busSrv, rm)
		assertLive(t, busSrv, cp)
	})

	t.Run("node removal closes the removed node's live session and its reconnect is refused", func(t *testing.T) {
		w := f.do(t, http.MethodDelete, "/api/nodes/node-rm", "", cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("remove node = %d %s, want 200", w.Code, w.Body.String())
		}
		assertEvicted(t, busSrv, rm)
		assertLive(t, busSrv, b)
		assertLive(t, busSrv, cp)
	})

	t.Run("revoking an offline node's token reports nothing disconnected", func(t *testing.T) {
		w := f.do(t, http.MethodDelete, "/api/bus/tokens/"+idOff, "", cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("revoke = %d %s, want 200", w.Code, w.Body.String())
		}
		var got revokeBusTokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode revoke response: %v", err)
		}
		if got.Disconnected != 0 {
			t.Errorf("revoke of a token with no live session disconnected %d, want 0", got.Disconnected)
		}
		assertLive(t, busSrv, b)
		assertLive(t, busSrv, cp)
	})
}
