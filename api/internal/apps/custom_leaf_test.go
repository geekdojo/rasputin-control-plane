package apps

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// A custom app — one the operator wrote the compose for, with no source tile —
// that declares a web port must get the same per-app certificate a catalog
// tile gets (geekdojo/geekdojo-brain#1093). The existing custom-app tests drive
// a stub rotator whose certificate is the string "C", so these drive the real
// controlplane CA and the real disk-backed rotator through the deploy leaf
// step, and assert on the certificate bytes the node receives.

const (
	customLeafCluster = "home1"
	customLeafNode    = "n"
	customLeafName    = "mine"
	customLeafPort    = 8080
	customTailnetFQDN = "mine.home1.internal"
	customLANFQDN     = "mine.lan.home1.internal"
)

var customLeafSANs = []string{customTailnetFQDN, customLANFQDN}

// deliverRealLeaf runs the deploy leaf step for appID against a fresh
// controlplane CA, a fresh leaf root and a fake node that acks, and returns the
// one command the node received. A step that skips the app delivers nothing,
// and receiveWithin then fails the test at its deadline instead of hanging.
func deliverRealLeaf(t *testing.T, store *Store, inv *inventory.Store, appID string) proto.AppLeafCmd {
	t.Helper()
	nc := startNATS(t)
	ca, err := tlsca.Ensure(tlsca.ControlplaneConfig(), t.TempDir(), customLeafCluster, tlscatest.Deps())
	if err != nil {
		t.Fatalf("controlplane CA: %v", err)
	}
	rotate := realRotator(t, ca, t.TempDir(), customLeafCluster)

	got := make(chan proto.AppLeafCmd, 2)
	sub := fakeLeafAgent(t, nc, customLeafNode, got)
	defer func() { _ = sub.Unsubscribe() }()

	if _, err := deployLeaf(store, inv, nc, rotate)(newStepCtxNATS(`{"appId":"`+appID+`"}`, nc)); err != nil {
		t.Fatalf("deployLeaf: %v", err)
	}
	cmd := receiveWithin(t, got, "no leaf command reached the node")
	select {
	case extra := <-got:
		t.Fatalf("node received a second leaf command for one deploy: %+v", extra)
	default:
	}
	return cmd
}

// parseLeafCert decodes the delivered PEM and parses it as an x509 certificate.
func parseLeafCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("delivered CertPEM is not a PEM certificate: %q", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("delivered certificate does not parse as x509: %v", err)
	}
	return cert
}

func assertCustomLeafNames(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	if !slices.Equal(cert.DNSNames, customLeafSANs) {
		t.Errorf("certificate names = %v, want exactly %v", cert.DNSNames, customLeafSANs)
	}
	if cert.Subject.CommonName != customTailnetFQDN {
		t.Errorf("certificate common name = %q, want %q", cert.Subject.CommonName, customTailnetFQDN)
	}
}

// customAppRow seeds a custom app (no source tile) with a declared web port,
// and checks the row really carries no tile so the test proves what it claims.
func customAppRow(t *testing.T, exposeLAN bool) (*Store, *inventory.Store) {
	t.Helper()
	store, inv := seedAppWithPort(t, customLeafNode, testAppID, customLeafName, customLeafPort, exposeLAN)
	app, err := store.Get(context.Background(), testAppID)
	if err != nil || app == nil {
		t.Fatalf("get seeded app: %v", err)
	}
	if app.SourceTile != "" || app.PublishedPort != customLeafPort || app.ExposeLAN != exposeLAN {
		t.Fatalf("seeded row is not a custom app with port %d, exposeLAN %v: tile %q port %d exposeLAN %v",
			customLeafPort, exposeLAN, app.SourceTile, app.PublishedPort, app.ExposeLAN)
	}
	return store, inv
}

// TC-1093-01: a custom app with a declared web port and LAN exposure on gets a
// real controlplane-CA certificate carrying both its names, and its route
// command carries the port and both hosts.
func TestDeployLeaf_CustomAppWithPortGetsBothNames(t *testing.T) {
	store, inv := customAppRow(t, true)
	cmd := deliverRealLeaf(t, store, inv, testAppID)

	assertCustomLeafNames(t, parseLeafCert(t, cmd.CertPEM))
	if cmd.UpstreamPort != customLeafPort {
		t.Errorf("UpstreamPort = %d, want %d", cmd.UpstreamPort, customLeafPort)
	}
	if cmd.TailnetFQDN != customTailnetFQDN {
		t.Errorf("TailnetFQDN = %q, want %q", cmd.TailnetFQDN, customTailnetFQDN)
	}
	if cmd.LANFQDN != customLANFQDN {
		t.Errorf("LANFQDN = %q, want %q for a LAN-exposed app", cmd.LANFQDN, customLANFQDN)
	}
}

// TC-1093-02: a tailnet-only custom app's certificate still carries both names;
// only the route drops the LAN host.
func TestDeployLeaf_TailnetOnlyCustomAppCertKeepsLANName(t *testing.T) {
	store, inv := customAppRow(t, false)
	cmd := deliverRealLeaf(t, store, inv, testAppID)

	assertCustomLeafNames(t, parseLeafCert(t, cmd.CertPEM))
	if cmd.TailnetFQDN != customTailnetFQDN {
		t.Errorf("TailnetFQDN = %q, want %q", cmd.TailnetFQDN, customTailnetFQDN)
	}
	if cmd.LANFQDN != "" {
		t.Errorf("LANFQDN = %q, want empty for a tailnet-only app", cmd.LANFQDN)
	}
	if cmd.UpstreamPort != customLeafPort {
		t.Errorf("UpstreamPort = %d, want %d", cmd.UpstreamPort, customLeafPort)
	}
}

// TC-1093-03: a catalog tile app with the same name and port gets a certificate
// with the same names and common name as the custom app's. Each runs on its own
// store, CA and leaf root, so neither certificate is read back from the other's
// leaf directory; differing bytes prove both were freshly minted.
func TestDeployLeaf_CustomAppCertMatchesTileCert(t *testing.T) {
	ctx := context.Background()

	customStore, customInv := customAppRow(t, true)
	customCert := parseLeafCert(t, deliverRealLeaf(t, customStore, customInv, testAppID).CertPEM)

	tileStore := newStore(t)
	tileInv := newInventory(t)
	now := time.Now().UTC()
	if err := tileInv.Insert(ctx, &proto.Node{ID: customLeafNode, Role: proto.RoleCompute, Hostname: customLeafNode + ".test", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	tile := makeApp(otherAppID, customLeafName)
	tile.TargetNode = customLeafNode
	tile.PublishedPort = customLeafPort
	tile.ExposeLAN = true
	tile.SourceTile = "uptime-kuma"
	if err := tileStore.Create(ctx, tile); err != nil {
		t.Fatalf("create tile app: %v", err)
	}
	if got, err := tileStore.Get(ctx, otherAppID); err != nil || got == nil || got.SourceTile != "uptime-kuma" {
		t.Fatalf("seeded tile row lost its source tile: %+v %v", got, err)
	}
	tileCert := parseLeafCert(t, deliverRealLeaf(t, tileStore, tileInv, otherAppID).CertPEM)

	if !slices.Equal(tileCert.DNSNames, customCert.DNSNames) {
		t.Errorf("tile certificate names %v differ from the custom app's %v", tileCert.DNSNames, customCert.DNSNames)
	}
	if tileCert.Subject.CommonName != customCert.Subject.CommonName {
		t.Errorf("tile common name %q differs from the custom app's %q", tileCert.Subject.CommonName, customCert.Subject.CommonName)
	}
	if bytes.Equal(tileCert.Raw, customCert.Raw) {
		t.Error("tile and custom certificates are byte-identical; one was not freshly minted")
	}
}
