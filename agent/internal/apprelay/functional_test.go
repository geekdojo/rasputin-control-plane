package apprelay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// TC-1081-28, the functional test of the relay socket
// (docs/testing-app-relay.md): a real Unix socket under real TLS 1.3, a real
// NATS server, and a stub api answering on the relay subject the way
// api/internal/apprelay does. Only a client that trusts the CA the socket's
// mount carries, under relay.rasputin.internal, over TLS 1.3, gets through;
// a re-installed certificate is served from the next handshake with no
// restart; a new Manager's Restore serves the same app again.
func TestRelaySocket_Functional(t *testing.T) {
	nc := startNATS(t)
	stubAPI(t, nc)
	log, _ := logkittest.New()
	relay, err := NewRelay("n1", 5*time.Second, log)
	if err != nil {
		t.Fatal(err)
	}
	relay.Attach(nc)
	dir := filepath.Join(shortDir(t), "relay")
	ca := newTestCA(t)
	m, _ := newTestManager(t, dir, relay)
	installed(t, m, ca, appA, 101)
	mnt, _ := m.MountDir(appA)
	sock := filepath.Join(mnt, proto.AppRelaySocketName)

	// The app's trust anchor is the CA file in its mount, and nothing else.
	mounted := x509.NewCertPool()
	caFile, err := os.ReadFile(filepath.Join(mnt, proto.AppRelayCAName))
	if err != nil || !mounted.AppendCertsFromPEM(caFile) {
		t.Fatalf("the mount's CA does not load: %v", err)
	}
	good := client(sock, mounted, proto.AppRelayServerName, 0)

	t.Run("create and read through the socket", func(t *testing.T) {
		if status, body, err := do(t, good, http.MethodPost, "session-key", `{"value":"v1"}`); err != nil || status != http.StatusCreated {
			t.Fatalf("create = %d %v %v", status, body, err)
		}
		if status, body, err := do(t, good, http.MethodGet, "session-key", ""); err != nil || status != http.StatusOK || body["value"] != "v1" {
			t.Fatalf("read = %d %v %v", status, body, err)
		}
	})

	t.Run("other server names, TLS 1.2 and system roots fail", func(t *testing.T) {
		for name, c := range map[string]*http.Client{
			"another server name": client(sock, mounted, "other.rasputin.internal", 0),
			"TLS 1.2 only":        client(sock, mounted, proto.AppRelayServerName, tls.VersionTLS12),
			"system roots":        client(sock, nil, proto.AppRelayServerName, 0),
		} {
			if _, _, err := do(t, c, http.MethodGet, "session-key", ""); err == nil {
				t.Errorf("%s: the handshake succeeded", name)
			}
		}
	})

	t.Run("a re-install is served with no restart", func(t *testing.T) {
		der, err := m.Prepare(appA)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Install(appA, ca.sign(t, der, 202), ca.pem); err != nil {
			t.Fatal(err)
		}
		if got := servedSerial(t, sock, mounted); got != 202 {
			t.Errorf("served serial %d after the re-install, want 202", got)
		}
	})

	t.Run("a new Manager restores the socket", func(t *testing.T) {
		m.Close()
		m2, _ := newTestManager(t, dir, relay)
		m2.Restore()
		if status, body, err := do(t, client(sock, mounted, proto.AppRelayServerName, 0), http.MethodGet, "session-key", ""); err != nil || status != http.StatusOK || body["value"] != "v1" {
			t.Fatalf("read after Restore = %d %v %v", status, body, err)
		}
	})
}

// stubAPI answers every relay call on nc from an in-memory map, the way the
// api's handler answers: create, read, replace, delete.
func stubAPI(t *testing.T, nc *nats.Conn) {
	t.Helper()
	var mu sync.Mutex
	held := map[string]string{}
	sub, err := nc.Subscribe(proto.AppSecretCallFilter, func(m *nats.Msg) {
		var c proto.AppSecretCall
		_ = json.Unmarshal(m.Data, &c)
		mu.Lock()
		key := c.AppID + "/" + c.Name
		r := proto.AppSecretReply{Code: proto.AppSecretOK, CorrelationID: "api"}
		switch c.Op {
		case proto.AppSecretCreate:
			if _, ok := held[key]; ok {
				r.Code = proto.AppSecretExists
			} else {
				held[key] = c.Value
			}
		case proto.AppSecretRead:
			v, ok := held[key]
			if !ok {
				r.Code = proto.AppSecretNotFound
			}
			r.Value = v
		case proto.AppSecretReplace:
			held[key] = c.Value
		case proto.AppSecretDelete:
			delete(held, key)
		}
		mu.Unlock()
		b, _ := json.Marshal(r)
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

// servedSerial is the serial of the certificate a fresh handshake on sock
// presents.
func servedSerial(t *testing.T, sock string, roots *x509.CertPool) int64 {
	t.Helper()
	conn, err := tls.Dial("unix", sock, &tls.Config{RootCAs: roots, ServerName: proto.AppRelayServerName})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}
