package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/nats-io/nats.go"
)

// Functional test for revoke = force-disconnect (certificates.md §4.2(1);
// geekdojo-brain#247): a real embedded bus with auth enforced, the real
// auth-callout responder, the real HTTP handlers, and agent clients configured
// the way the agent configures its own (agent/internal/bus/client.go).
//
// Transport: the bus listens on all interfaces. Node agents dial this machine's
// non-loopback IPv4 address, so the callout sees a non-loopback source and
// requires a join token — the path a LAN node takes. The controlplane's own
// agent dials 127.0.0.1 with no token and is trusted as loopback, exactly as in
// production.
//
// Every wait is event-driven (connection callbacks, server state read
// synchronously) and bounded by revokeWaitLimit.

const revokeWaitLimit = 10 * time.Second

// startAuthBus brings up an auth-enforced bus on all interfaces whose callout
// validates against tokens — the store the api handlers revoke through — wired
// as main.go does. It returns the server and the URLs a LAN node and the
// controlplane's loopback agent dial.
func startAuthBus(t *testing.T, tokens *busauth.Store) (srv *bus.Server, nodeURL, loopbackURL string) {
	t.Helper()
	ip := nonLoopbackIPv4ForBus(t)
	dir := t.TempDir()
	issuer, err := busauth.EnsureIssuer(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nats"), 0o755); err != nil {
		t.Fatalf("mkdir nats: %v", err)
	}
	srv, err = bus.Start(context.Background(), bus.Config{
		Host: "0.0.0.0", Port: -1,
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
	u, err := url.Parse(srv.ClientURL())
	if err != nil {
		t.Fatalf("parse client URL %q: %v", srv.ClientURL(), err)
	}
	return srv, "nats://" + net.JoinHostPort(ip, u.Port()), "nats://" + net.JoinHostPort("127.0.0.1", u.Port())
}

// nonLoopbackIPv4ForBus returns an up, non-loopback IPv4 address of this
// machine. A developer machine with none skips; CI must have one, so there it
// fails rather than silently not running the test.
func nonLoopbackIPv4ForBus(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
					return ip4.String()
				}
			}
		}
	}
	if os.Getenv("CI") != "" {
		t.Fatal("no non-loopback IPv4 interface in CI: the revoke test cannot exercise token authentication")
	}
	t.Skip("no non-loopback IPv4 interface on this machine; loopback would bypass the token check entirely")
	return ""
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
	w := f.do(t, http.MethodPost, "/api/bus/tokens", `{"label":"test","nodeId":"`+nodeID+`"}`, cookie)
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
	busSrv, nodeURL, loopbackURL := startAuthBus(t, f.srv.busTokens)

	tokA, idA := mintBoundViaAPI(t, f, cookie, "node-a")
	tokB, _ := mintBoundViaAPI(t, f, cookie, "node-b")
	tokRm, _ := mintBoundViaAPI(t, f, cookie, "node-rm")
	_, idOff := mintBoundViaAPI(t, f, cookie, "node-off")
	seedNodeWithCascade(t, f, "node-rm")

	// The controlplane's co-located agent: TCP loopback, no token.
	cp := dialAgent(t, loopbackURL, "cp-1", "")
	a := dialAgent(t, nodeURL, "node-a", tokA)
	b := dialAgent(t, nodeURL, "node-b", tokB)
	rm := dialAgent(t, nodeURL, "node-rm", tokRm)

	// Premise: a node dialing the non-loopback address really is on the token
	// path — without a token it is refused. If this ever stopped holding, the
	// nodes above would be loopback-trusted and never recorded for revocation.
	if nc, err := nats.Connect(nodeURL, nats.UserInfo("node-x", ""), nats.MaxReconnects(0)); err == nil {
		nc.Close()
		t.Fatal("tokenless node connection on the non-loopback address was accepted")
	} else if !errors.Is(err, nats.ErrAuthorization) {
		t.Fatalf("tokenless node connection failed with %v, want an authorization violation", err)
	}

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
