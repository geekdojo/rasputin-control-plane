package apprelay

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

const (
	appA  = "01J9ZK3Q0M8X7Y6W5V4T3S2R1A"
	appB  = "01J9ZK3Q0M8X7Y6W5V4T3S2R1B"
	nodeN = "n"
	nodeM = "m"
)

func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// relayAgent is a fake agent answering app.relay on node n. fail names the
// op it refuses; noAnswer drops every request.
type relayAgent struct {
	mu       sync.Mutex
	ops      []string
	installs []proto.AppRelayCmd
	key      *ecdsa.PrivateKey
	fail     string
	badDER   bool
}

func newRelayAgent(t *testing.T, nc *nats.Conn) *relayAgent {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &relayAgent{key: key}
	sub, err := nc.Subscribe(proto.AppRelaySubject(nodeN), func(m *nats.Msg) {
		var cmd proto.AppRelayCmd
		_ = json.Unmarshal(m.Data, &cmd)
		a.mu.Lock()
		a.ops = append(a.ops, cmd.Op)
		if cmd.Op == proto.AppRelayInstall {
			a.installs = append(a.installs, cmd)
		}
		fail, bad := a.fail, a.badDER
		a.mu.Unlock()
		ack := proto.AppRelayAck{OK: true}
		switch {
		case fail == cmd.Op:
			ack = proto.AppRelayAck{Detail: "refused by the fake agent"}
		case cmd.Op == proto.AppRelayPrepare && bad:
			ack.PublicKeyDER = []byte("not a key")
		case cmd.Op == proto.AppRelayPrepare:
			ack.PublicKeyDER, _ = x509.MarshalPKIXPublicKey(key.Public())
		}
		b, _ := json.Marshal(ack)
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return a
}

func (a *relayAgent) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.ops)
}

// fakeSilence explains every silence as an agent below the floor.
type fakeSilence struct{}

func (fakeSilence) ExplainNoResponder(_ context.Context, subject string) inventory.NoResponder {
	floor, _ := proto.VerbMinAgentVersion(proto.AppRelayVerb)
	return inventory.NoResponder{NodeID: nodeN, Verb: proto.AppRelayVerb, Kind: inventory.SilenceOldAgent,
		AgentVersion: "2026.10.4", MinVersion: floor}
}

// recordingSigner signs through a real CA and records the spec and key.
type recordingSigner struct {
	ca   *tlsca.CA
	err  error
	spec tlsca.LeafSpec
	pub  crypto.PublicKey
	n    int
}

func (s *recordingSigner) SignLeaf(spec tlsca.LeafSpec, pub crypto.PublicKey) ([]byte, error) {
	s.n++
	s.spec, s.pub = spec, pub
	if s.err != nil {
		return nil, s.err
	}
	return s.ca.SignLeaf(spec, pub)
}

func testCA(t *testing.T) *tlsca.CA {
	t.Helper()
	return tlscatest.Controlplane(t, filepath.Join(t.TempDir(), "trust"))
}

func appOn(id, node string) *apps.App {
	return &apps.App{ID: id, Name: "app", TargetNode: node, SourceTile: "tile"}
}

// TC-1081-18: prepare, sign, install in that order; the leaf is serverAuth
// for relay.rasputin.internal alone, expires with the CA, is over the
// prepared key; install carries it and the CA alone. Revoke sends remove.
func TestIssuer_PrepareSignInstall(t *testing.T) {
	nc := startNATS(t)
	agent := newRelayAgent(t, nc)
	ca := testCA(t)
	signer := &recordingSigner{ca: ca}
	iss, err := NewIssuer(IssuerDeps{Bus: nc, Signer: signer, CACert: ca.Cert, CAPEM: ca.CertPEM, Silence: fakeSilence{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Issue(t.Context(), appOn(appA, nodeN)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got := agent.seen(); !slices.Equal(got, []string{"prepare", "install"}) || signer.n != 1 {
		t.Fatalf("ops = %v with %d signs, want [prepare install] with one sign between", got, signer.n)
	}
	inst := agent.installs[0]
	if string(inst.CAPEM) != string(ca.CertPEM) {
		t.Error("install did not carry the controlplane CA alone")
	}
	block, _ := pem.Decode(inst.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cert.DNSNames, []string{proto.AppRelayServerName}) || len(cert.IPAddresses) != 0 {
		t.Errorf("SANs = %v %v, want only %s", cert.DNSNames, cert.IPAddresses, proto.AppRelayServerName)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("EKU = %v, want serverAuth only", cert.ExtKeyUsage)
	}
	if !cert.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Errorf("NotAfter = %v, want the CA's %v", cert.NotAfter, ca.Cert.NotAfter)
	}
	want, _ := x509.MarshalPKIXPublicKey(agent.key.Public())
	got, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if string(got) != string(want) {
		t.Error("the leaf is not over the prepared key")
	}
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("the leaf does not chain to the CA: %v", err)
	}
	if err := iss.Revoke(t.Context(), appOn(appA, nodeN)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := agent.seen(); got[len(got)-1] != "remove" {
		t.Errorf("Revoke sent %v, want remove last", got)
	}
}

// TC-1081-18 (failures) and TC-1081-26 (an agent that predates app.relay):
// each failure returns an error and stops the later RPCs.
func TestIssuer_EachFailureStops(t *testing.T) {
	ca := testCA(t)
	for _, tc := range []struct {
		name    string
		setup   func(a *relayAgent, s *recordingSigner)
		noAgent bool
		wantOps []string
		want    string
	}{
		{name: "no responder", noAgent: true, wantOps: nil, want: "update the node"},
		{name: "prepare refused", setup: func(a *relayAgent, _ *recordingSigner) { a.fail = "prepare" }, wantOps: []string{"prepare"}, want: "refused to prepare"},
		{name: "malformed key", setup: func(a *relayAgent, _ *recordingSigner) { a.badDER = true }, wantOps: []string{"prepare"}, want: "does not parse"},
		{name: "sign error", setup: func(_ *relayAgent, s *recordingSigner) { s.err = errors.New("sign broke") }, wantOps: []string{"prepare"}, want: "sign broke"},
		{name: "install refused", setup: func(a *relayAgent, _ *recordingSigner) { a.fail = "install" }, wantOps: []string{"prepare", "install"}, want: "refused to install"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc := startNATS(t)
			signer := &recordingSigner{ca: ca}
			var agent *relayAgent
			if !tc.noAgent {
				agent = newRelayAgent(t, nc)
			}
			if tc.setup != nil {
				tc.setup(agent, signer)
			}
			iss, _ := NewIssuer(IssuerDeps{Bus: nc, Signer: signer, CACert: ca.Cert, CAPEM: ca.CertPEM, Silence: fakeSilence{}})
			err := iss.Issue(t.Context(), appOn(appA, nodeN))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Issue = %v, want an error containing %q", err, tc.want)
			}
			if agent != nil && !slices.Equal(agent.seen(), tc.wantOps) {
				t.Errorf("ops = %v, want %v", agent.seen(), tc.wantOps)
			}
			if strings.Contains(err.Error(), "BEGIN") {
				t.Errorf("the error carries PEM bytes: %v", err)
			}
		})
	}
	t.Run("install transport error", func(t *testing.T) {
		iss, _ := NewIssuer(IssuerDeps{Bus: &failSecond{}, Signer: &recordingSigner{ca: ca}, CACert: ca.Cert, CAPEM: ca.CertPEM, Silence: fakeSilence{}})
		if err := iss.Issue(t.Context(), appOn(appA, nodeN)); err == nil || !strings.Contains(err.Error(), "install") {
			t.Fatalf("Issue = %v, want the install's transport error", err)
		}
	})
}

// failSecond answers prepare with a real key and fails the next request at
// the transport.
type failSecond struct{ n int }

func (f *failSecond) RequestWithContext(_ context.Context, _ string, _ []byte) (*nats.Msg, error) {
	f.n++
	if f.n > 1 {
		return nil, nats.ErrConnectionClosed
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(key.Public())
	b, _ := json.Marshal(proto.AppRelayAck{OK: true, PublicKeyDER: der})
	return &nats.Msg{Data: b}, nil
}

// F-1081-05: the Issuer is always built; with no CA it refuses each Issue and
// sends nothing.
func TestIssuer_NoCARefusesAtIssue(t *testing.T) {
	nc := startNATS(t)
	agent := newRelayAgent(t, nc)
	iss, err := NewIssuer(IssuerDeps{Bus: nc, Silence: fakeSilence{}})
	if err != nil {
		t.Fatalf("NewIssuer with no CA refused: %v", err)
	}
	if err := iss.Issue(t.Context(), appOn(appA, nodeN)); !errors.Is(err, ErrNoCA) {
		t.Fatalf("Issue = %v, want ErrNoCA", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := agent.seen(); len(got) != 0 {
		t.Errorf("sent %v with no CA", got)
	}
	for _, d := range []IssuerDeps{{Silence: fakeSilence{}}, {Bus: nc}} {
		if _, err := NewIssuer(d); err == nil {
			t.Errorf("NewIssuer(%+v) accepted a missing collaborator", d)
		}
	}
}
