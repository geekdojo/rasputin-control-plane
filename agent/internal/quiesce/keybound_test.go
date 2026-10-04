package quiesce

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

// The stager presents the node's agent key on backup transfer and restore
// fetch (geekdojo/geekdojo-brain#514), through its own production clients —
// no transportFor or fetcherFor override.

// peerLog records, per request, the client certificates the server saw, and
// counts the connections it accepted.
type peerLog struct {
	mu    sync.Mutex
	peers [][]string // SPKI hashes of each request's peer certificates
	conns atomic.Int32
}

func (p *peerLog) record(r *http.Request) {
	var hashes []string
	if r.TLS != nil {
		for _, c := range r.TLS.PeerCertificates {
			h, err := proto.NodeKeySPKIHash(c.PublicKey)
			if err != nil {
				h = "unhashable"
			}
			hashes = append(hashes, h)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.peers = append(p.peers, hashes)
}

func (p *peerLog) requests() [][]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][]string(nil), p.peers...)
}

// startPeerServer starts an HTTPS server under ca with clientAuth, recording
// what each request presented before h serves it. The leaf is ca's; any
// client certificate is accepted unverified, as the api's node listener does
// before it compares the key.
func startPeerServer(t *testing.T, ca *tlstest.CA, clientAuth tls.ClientAuthType, log *peerLog, h http.Handler) *httptest.Server {
	t.Helper()
	tmp := ca.NewServer(t, http.NotFoundHandler()) // only for a leaf ca signed
	leaf := tmp.TLS.Certificates
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		h.ServeHTTP(w, r)
	}))
	srv.TLS = &tls.Config{Certificates: leaf, ClientAuth: clientAuth, MinVersion: tls.VersionTLS12}
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			log.conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// caTrust is the stager's trust source for servers under ca.
func caTrust(ca *tlstest.CA) TrustSource {
	return func() (*tls.Config, error) { return proto.CATLSConfig(ca.PEM, "test bundle") }
}

// TC-514-22: on a server that asks for a client certificate, the stager's
// upload and its restore fetch each present exactly the node's agent key.
func TestStager_PresentsTheAgentKey(t *testing.T) {
	ca := tlstest.NewCA(t, "mesh")
	keys, cert := testNodeKeys(t)
	agent, collector := keys.Hashes()[proto.NodeKeyAgent], keys.Hashes()[proto.NodeKeyCollector]
	check := func(t *testing.T, what string, log *peerLog) {
		t.Helper()
		reqs := log.requests()
		if len(reqs) == 0 {
			t.Fatalf("%s: the server saw no request", what)
		}
		for i, peers := range reqs {
			if len(peers) != 1 || peers[0] != agent || peers[0] == collector {
				t.Errorf("%s request %d presented %v; want exactly the agent key %s", what, i, peers, agent)
			}
		}
	}

	t.Run("upload", func(t *testing.T) {
		log := &peerLog{}
		r := newXferRigOn(t, func(h http.Handler) *httptest.Server {
			return startPeerServer(t, ca, tls.RequireAnyClientCert, log, h)
		})
		rt := newFake(t)
		s := newStager(t, rt)
		s.trust, s.clientCert = caTrust(ca), cert
		staged := stageVault(t, rt, s)
		ack := s.Transfer(context.Background(), r.transferCmd(t, staged, proto.BackupMemberPath("vaultwarden", "vaultwarden-data")))
		if !ack.OK {
			t.Fatalf("transfer: %s %s", ack.Refusal, ack.Detail)
		}
		check(t, "upload", log)
	})

	t.Run("restore fetch", func(t *testing.T) {
		log := &peerLog{}
		r := newRestoreRig(t)
		r.s.trust, r.s.clientCert = caTrust(ca), cert
		tlsSrv := startPeerServer(t, ca, tls.RequireAnyClientCert, log, r.e.srv.Config.Handler)
		r.corrupt(t)
		cmd := r.cmd(t)
		src, err := backupxfer.EgressDestination(tlsSrv.URL)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Source = src
		ack := r.s.RestoreVolume(context.Background(), cmd)
		if !ack.OK {
			t.Fatalf("restore: %s %s", ack.Refusal, ack.Detail)
		}
		check(t, "restore fetch", log)
	})
}

// TC-514-23: an api that asks for no client certificate (the public
// listener, and every api before key-bound transfer) sees none, and the
// upload of an unbound credential succeeds as it always has.
func TestStager_SendsNoCertificateWhenNoneIsAsked(t *testing.T) {
	ca := tlstest.NewCA(t, "mesh")
	log := &peerLog{}
	r := newXferRigOn(t, func(h http.Handler) *httptest.Server {
		return startPeerServer(t, ca, tls.NoClientCert, log, h)
	})
	rt := newFake(t)
	s := newStager(t, rt)
	s.trust = caTrust(ca) // and the agent cert newStager gave it
	staged := stageVault(t, rt, s)
	ack := s.Transfer(context.Background(), r.transferCmd(t, staged, proto.BackupMemberPath("vaultwarden", "vaultwarden-data")))
	if !ack.OK {
		t.Fatalf("transfer: %s %s", ack.Refusal, ack.Detail)
	}
	for i, peers := range log.requests() {
		if len(peers) != 0 {
			t.Errorf("request %d presented %d certificate(s) to a server that asked for none", i, len(peers))
		}
	}
}

// TC-514-24: a stager built with no agent key refuses both verbs before any
// connection is made.
func TestStager_RefusesWithNoNodeKey(t *testing.T) {
	ca := tlstest.NewCA(t, "mesh")
	const want = "no node key wired"

	t.Run("upload", func(t *testing.T) {
		log := &peerLog{}
		r := newXferRigOn(t, func(h http.Handler) *httptest.Server {
			return startPeerServer(t, ca, tls.RequireAnyClientCert, log, h)
		})
		rt := newFake(t)
		s := newStagerWith(t, rt, caTrust(ca), nil)
		staged := stageVault(t, rt, s)
		ack := s.Transfer(context.Background(), r.transferCmd(t, staged, proto.BackupMemberPath("vaultwarden", "vaultwarden-data")))
		if ack.OK || ack.Refusal != proto.StorageRefusalBackendError || !strings.Contains(ack.Detail, want) {
			t.Fatalf("ack = ok %v %s %q; want %s naming %q", ack.OK, ack.Refusal, ack.Detail, proto.StorageRefusalBackendError, want)
		}
		if n := log.conns.Load(); n != 0 {
			t.Errorf("the server accepted %d connection(s), want 0", n)
		}
	})

	t.Run("restore fetch", func(t *testing.T) {
		log := &peerLog{}
		r := newRestoreRig(t)
		tlsSrv := startPeerServer(t, ca, tls.RequireAnyClientCert, log, r.e.srv.Config.Handler)
		r.s.trust, r.s.clientCert = caTrust(ca), nil
		before := r.snapshot(t)
		cmd := r.cmd(t)
		src, err := backupxfer.EgressDestination(tlsSrv.URL)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Source = src
		ack := r.s.RestoreVolume(context.Background(), cmd)
		if ack.OK || ack.Refusal != proto.StorageRefusalBackendError || !strings.Contains(ack.Detail, want) {
			t.Fatalf("ack = ok %v %s %q; want %s naming %q", ack.OK, ack.Refusal, ack.Detail, proto.StorageRefusalBackendError, want)
		}
		if n := log.conns.Load(); n != 0 {
			t.Errorf("the server accepted %d connection(s), want 0", n)
		}
		r.assertUntouched(t, before, ack)
	})
}
