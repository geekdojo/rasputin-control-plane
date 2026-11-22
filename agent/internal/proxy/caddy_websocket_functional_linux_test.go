//go:build linux

package proxy

// Functional test for geekdojo/geekdojo-brain#1094 against a REAL Caddy
// binary: a WebSocket passes through the route the agent renders for an app
// leaf, in both directions, and the upgraded stream stays open.
//
// A custom app (no catalog tile) reaches the node as the same AppLeafCmd a
// tile does — the command has no tile field — so the route under test is the
// one every app gets: a bare reverse_proxy to 127.0.0.1:<port> (config.go
// httpRoute). Whether that route carries an HTTP Upgrade is Caddy's
// behaviour, not ours, so only a real Caddy shows it; a fake admin API would
// accept any config.
//
// The test drives the agent's own delivery path end to end: the leaf arrives
// as an app.leaf command over NATS (RegisterHandlers → handleLeaf →
// LeafStore.Write → Reconcile → /load), and Caddy runs under the agent's own
// supervisor (RunCaddy). A loopback upstream answers an Upgrade request with
// 101 Switching Protocols and then echoes bytes. A client opens TLS to the
// LAN listener on 127.0.0.1:443 with the app's .lan. name as SNI, verifying
// the served leaf against the test CA, and asserts:
//
//   - the Upgrade request comes back 101 with "Upgrade: websocket", so Caddy
//     passed the handshake through rather than answering it or dropping the
//     hop-by-hop headers;
//   - a payload written on the upgraded connection comes back unchanged;
//   - a second payload, written after the first round trip on the same
//     connection, also comes back unchanged, so the stream stays open and is
//     not a one-shot exchange.
//
// What it does not prove: a particular app's WebSocket client or framing
// (the payload is raw bytes after the handshake), the tailnet listener (the
// reconciler has no tailnet address here, as in the renewal test), or the
// HTTP/2 WebSocket path (RFC 8441): ALPN is pinned to http/1.1. Those belong
// to the bench case in geekdojo/geekdojo-brain#1095.
//
// How to run it: it needs root (the app server binds :443) and a caddy binary,
// so it skips unless RASPUTIN_CADDY_BIN is set. On a Linux box:
//
//	go test -c -race -o /tmp/proxy.test ./agent/internal/proxy
//	sudo env RASPUTIN_CADDY_BIN=/path/to/caddy RASPUTIN_CADDY_FUNCTIONAL=required \
//	    /tmp/proxy.test -test.v -test.count=1 -test.run TestCaddyPassesWebSocket_RealCaddy
//
// CI's proxy job runs the whole package that way against the pinned Caddy,
// and RASPUTIN_CADDY_FUNCTIONAL=required turns every skip into a failure.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// wsGUID is the fixed GUID RFC 6455 section 1.3 appends to the client's key
// before hashing it into Sec-WebSocket-Accept.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// newWSKey returns a fresh Sec-WebSocket-Key: 16 random bytes, base64
// encoded, as RFC 6455 section 4.1 requires of a client.
func newWSKey(t *testing.T) string {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("websocket key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(nonce)
}

// wsAcceptFor derives the Sec-WebSocket-Accept a server answers key with
// (RFC 6455 section 4.2.2). SHA-1 is what the protocol mandates for this
// handshake check; it is not used for any security property here.
func wsAcceptFor(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// TC-1094-02: a WebSocket passes through the node's Caddy route for an app
// delivered as an AppLeafCmd, in both directions, on one open stream.
func TestCaddyPassesWebSocket_RealCaddy(t *testing.T) {
	caddyBin := requireFunctional(t)

	base, err := os.MkdirTemp("", "cws")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "xdg-config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "xdg-data"))

	ca := newTestCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	// A fresh key per run. The upstream derives its accept value from the
	// key it actually received, and the client checks that value against
	// its own key, so a matching 101 shows the client's key reached the
	// upstream and the upstream's answer reached the client.
	wsKey := newWSKey(t)

	// The upstream: on an Upgrade request it takes over the connection,
	// answers 101 and echoes every byte it reads.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey := r.Header.Get("Sec-WebSocket-Key")
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || gotKey == "" {
			http.Error(w, "websocket upgrade with a Sec-WebSocket-Key required", http.StatusUpgradeRequired)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("upstream hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + wsAcceptFor(gotKey) + "\r\n\r\n")
		if err := brw.Flush(); err != nil {
			return
		}
		// Echo until the proxy closes its side. Reads go through brw, which
		// may already hold bytes sent right after the handshake.
		_, _ = io.Copy(conn, brw.Reader)
	}))
	t.Cleanup(up.Close)
	port := mustAtoi(t, up.URL[strings.LastIndexByte(up.URL, ':')+1:])

	app := testApp{id: "chat", lan: "chat.lan.bench.internal", tailnet: "chat.bench.internal", port: port}

	const nodeID = "node-1094"
	store := NewLeafStore(filepath.Join(base, "leaves"))
	sock := filepath.Join(base, "caddy", "admin.sock")
	r := NewReconciler(store, sock, func() string { return "" }, func() string { return "127.0.0.1" })
	r.legacyAdmin = ""

	nc := startNATS(t)
	sub, err := RegisterHandlers(nc, nodeID, store, r.Reconcile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	// The command the api sends for a custom app: names, port, plain HTTP.
	leaf := ca.leaf(t, app.lan)
	ack := requestLeaf(t, nc, nodeID, proto.AppLeafCmd{
		AppID: app.id, Name: app.id, CertPEM: leaf.certPEM, KeyPEM: leaf.keyPEM,
		TailnetFQDN: app.tailnet, LANFQDN: app.lan, UpstreamPort: app.port, UpstreamTLS: false,
	})
	if !ack.OK {
		t.Fatalf("deliver %s: agent refused: %s", app.id, ack.Detail)
	}

	stop := superviseCaddy(t, r, caddyBin)
	defer stop()
	waitFor(t, convergeWithin, "caddy serving "+app.lan+"'s leaf on 127.0.0.1:443", func() bool {
		serial, err := servedSerial(roots, app.lan)
		return err == nil && serial == leaf.serial
	})

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp",
		"127.0.0.1:"+strconv.Itoa(certPort), &tls.Config{
			ServerName: app.lan,
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		})
	if err != nil {
		t.Fatalf("TLS to caddy for %s: %v", app.lan, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	if _, err := io.WriteString(conn, "GET /socket HTTP/1.1\r\n"+
		"Host: "+app.lan+"\r\n"+
		"Connection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Key: "+wsKey+"\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("upgrade via caddy: status %d (%s), want 101", resp.StatusCode, b)
	}
	if got := resp.Header.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
		t.Fatalf("upgrade via caddy: Upgrade header %q, want websocket", got)
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), wsAcceptFor(wsKey); got != want {
		t.Errorf("Sec-WebSocket-Accept %q, want the upstream's %q", got, want)
	}

	// Both payloads ride the same upgraded connection, the second only after
	// the first has come back.
	for i, payload := range [][]byte{[]byte("ping over the custom app's route"), []byte("second frame, same stream")} {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("payload %d: write: %v", i+1, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(br, got); err != nil {
			t.Fatalf("payload %d: read back: %v (got %q)", i+1, err, got)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload %d: read back %q, want %q", i+1, got, payload)
		}
	}
}
