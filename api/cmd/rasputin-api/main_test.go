package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
)

// Secure is derived from whether this process terminates TLS, because that is
// the condition under which the cookie can only travel over TLS. The bug this
// replaces was an opt-in env var that defaulted OFF and was set nowhere, so
// the appliance — which serves https on :443 — shipped session cookies without
// Secure. The unset-override row is the one that regressed.
func TestSecureCookies(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name      string
		httpsAddr string
		override  *bool
		want      bool
	}{
		{"appliance: https listener, no override", ":443", nil, true},
		{"dev: no https listener, no override", "", nil, false},
		{"override forces on behind a TLS-terminating proxy", "", &yes, true},
		{"override forces off despite an https listener", ":443", &no, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := secureCookies(tc.httpsAddr, tc.override); got != tc.want {
				t.Errorf("secureCookies(%q, %v) = %v, want %v",
					tc.httpsAddr, tc.override, got, tc.want)
			}
		})
	}
}

func TestAPILeafSpec_SANs(t *testing.T) {
	spec := apiLeafSpec("nodex", net.ParseIP("192.168.7.2"))

	wantDNS := []string{"rasputin.local", "localhost", "nodex", "nodex.local"}
	if !slices.Equal(spec.DNSNames, wantDNS) {
		t.Errorf("DNSNames = %v, want %v", spec.DNSNames, wantDNS)
	}
	if len(spec.IPAddresses) != 2 {
		t.Fatalf("IPAddresses = %v, want 127.0.0.1 + LAN IP", spec.IPAddresses)
	}
	if !spec.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("first IP SAN = %v, want 127.0.0.1", spec.IPAddresses[0])
	}
	if !spec.IPAddresses[1].Equal(net.ParseIP("192.168.7.2")) {
		t.Errorf("second IP SAN = %v, want 192.168.7.2", spec.IPAddresses[1])
	}
}

func TestAPILeafSpec_FQDNHostnameNoDoubleLocal(t *testing.T) {
	// Hostname already carries a dot → no "<host>.local" appended on top.
	spec := apiLeafSpec("nodex.local", nil)
	want := []string{"rasputin.local", "localhost", "nodex.local"}
	if !slices.Equal(spec.DNSNames, want) {
		t.Errorf("DNSNames = %v, want %v", spec.DNSNames, want)
	}
	if len(spec.IPAddresses) != 1 { // air-gapped: just loopback
		t.Errorf("IPAddresses = %v, want only 127.0.0.1", spec.IPAddresses)
	}
}

func TestAPILeafSpec_HostnameIsRasputinLocal_NoDup(t *testing.T) {
	spec := apiLeafSpec("rasputin.local", nil)
	want := []string{"rasputin.local", "localhost"}
	if !slices.Equal(spec.DNSNames, want) {
		t.Errorf("DNSNames = %v, want %v", spec.DNSNames, want)
	}
}

// End-to-end: mint the api leaf via ensureAPILeaf's underlying path and
// assert the SANs survive onto the actual certificate.
func TestEnsureAPILeaf_CertCarriesSANs(t *testing.T) {
	dir := t.TempDir()
	ca, err := mesh.EnsureMeshCA(dir, "test")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}

	spec := apiLeafSpec("nodex", net.ParseIP("10.0.0.5"))
	certPEM, _, err := mesh.MintLeaf(ca, spec)
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("leaf is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	for _, dns := range []string{"rasputin.local", "localhost", "nodex", "nodex.local"} {
		if !slices.Contains(cert.DNSNames, dns) {
			t.Errorf("leaf missing DNS SAN %q (have %v)", dns, cert.DNSNames)
		}
	}
	wantIPs := []string{"127.0.0.1", "10.0.0.5"}
	for _, want := range wantIPs {
		found := false
		for _, ip := range cert.IPAddresses {
			if ip.String() == want {
				found = true
			}
		}
		if !found {
			t.Errorf("leaf missing IP SAN %s (have %v)", want, cert.IPAddresses)
		}
	}
	// And the browser-facing check that actually matters:
	if err := cert.VerifyHostname("rasputin.local"); err != nil {
		t.Errorf("VerifyHostname(rasputin.local): %v", err)
	}
}

func TestLoadBusPreseed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := busauth.OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Missing file is normal — (0, nil), no error.
	if n, err := loadBusPreseed(ctx, store, filepath.Join(dir, "nope.json")); err != nil || n != 0 {
		t.Fatalf("missing preseed = (%d,%v); want (0,nil)", n, err)
	}

	// A valid preseed loads and the bound hashes validate.
	pt, h, _ := busauth.GenerateToken()
	path := filepath.Join(dir, "preseed.json")
	body := `[{"hash":"` + h + `","nodeId":"node-a","label":"compute"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write preseed: %v", err)
	}
	if n, err := loadBusPreseed(ctx, store, path); err != nil || n != 1 {
		t.Fatalf("loadBusPreseed = (%d,%v); want (1,nil)", n, err)
	}
	if ok, _ := store.Validate(ctx, pt, "node-a"); !ok {
		t.Error("preloaded token must validate for its bound node")
	}
	if ok, _ := store.Validate(ctx, pt, "node-b"); ok {
		t.Error("preloaded token must not validate for another node")
	}

	// Malformed JSON surfaces an error (caller logs and continues).
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	if _, err := loadBusPreseed(ctx, store, bad); err == nil {
		t.Error("malformed preseed should error")
	}
}

func TestSeedBMCHostNode(t *testing.T) {
	ctx := context.Background()
	st, err := setup.OpenStore(ctx, filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Empty host id: nothing seeded (and IsSet stays false).
	seedBMCHostNode(ctx, st, "")
	if set, _ := st.IsSet(ctx, setup.KeyBMCHostNode); set {
		t.Error("empty id must not seed")
	}

	// First boot: env value seeds.
	seedBMCHostNode(ctx, st, "cp-env")
	if v, _ := st.Get(ctx, setup.KeyBMCHostNode); v != "cp-env" {
		t.Errorf("seeded: %q", v)
	}

	// Operator choice wins permanently: a later boot never re-seeds.
	if err := st.Set(ctx, setup.KeyBMCHostNode, "cp-chosen"); err != nil {
		t.Fatal(err)
	}
	seedBMCHostNode(ctx, st, "cp-env")
	if v, _ := st.Get(ctx, setup.KeyBMCHostNode); v != "cp-chosen" {
		t.Errorf("re-seeded over operator choice: %q", v)
	}
}

// --- cluster-name derivation (ADR-0003) --------------------------------------

// RASPUTIN_CLUSTER_ID is written by firstboot and by nothing else, so its
// PRESENCE is what distinguishes a provisioned appliance from a dev box. Get
// this wrong and every developer's origin silently renames, breaking the local
// passkey flow.
func TestClusterHostname(t *testing.T) {
	t.Setenv("RASPUTIN_CLUSTER_ID", "")
	if got := clusterHostname(); got != "" {
		t.Errorf("unset cluster id should yield %q (dev box), got %q", "", got)
	}
	t.Setenv("RASPUTIN_CLUSTER_ID", "home1")
	if got := clusterHostname(); got != "home1.local" {
		t.Errorf("clusterHostname() = %q, want home1.local", got)
	}
	// Whitespace from a hand-edited node.env must not produce " home1 .local".
	t.Setenv("RASPUTIN_CLUSTER_ID", "  home1  ")
	if got := clusterHostname(); got != "home1.local" {
		t.Errorf("clusterHostname() = %q, want the id trimmed", got)
	}
}

// The whole no-migration promise of ADR-0003 rests on this: a node whose
// cluster id is the default derives EXACTLY the values the OS image hardcodes
// today. If this drifts, every existing installation renames on upgrade.
func TestDefaultClusterIDDerivesTodaysApplianceValues(t *testing.T) {
	t.Setenv("RASPUTIN_CLUSTER_ID", "rasputin")
	host := func(h string) string { return h }
	https := func(h string) string { return "https://" + h }
	hs := func(h string) string { return "https://" + h + ":18080" }

	for _, tc := range []struct{ name, got, want string }{
		{"RP ID", applianceOr(host, "localhost"), "rasputin.local"},
		{"RP origin", applianceOr(https, "dev"), "https://rasputin.local"},
		{"public base URL", applianceOr(https, "dev"), "https://rasputin.local"},
		{"headscale server_url", applianceOr(hs, ""), "https://rasputin.local:18080"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q — an existing installation would RENAME on upgrade", tc.name, tc.got, tc.want)
		}
	}
}

// A dev box keeps its localhost defaults untouched.
func TestNoClusterIDKeepsDevDefaults(t *testing.T) {
	t.Setenv("RASPUTIN_CLUSTER_ID", "")
	if got := applianceOr(func(h string) string { return h }, "localhost"); got != "localhost" {
		t.Errorf("RP ID default = %q, want localhost on a dev box", got)
	}
	if got := applianceOr(func(h string) string { return "https://" + h }, ""); got != "" {
		t.Errorf("headscale ServerURL default = %q, want empty so the supervisor falls back to resolveServerHost", got)
	}
}

// A non-default cluster id derives its own name everywhere.
func TestNonDefaultClusterIDDerivesItsOwnName(t *testing.T) {
	t.Setenv("RASPUTIN_CLUSTER_ID", "home1")
	if got := applianceOr(func(h string) string { return h }, "localhost"); got != "home1.local" {
		t.Errorf("RP ID = %q, want home1.local", got)
	}
	if got := applianceOr(func(h string) string { return "https://" + h + ":18080" }, ""); got != "https://home1.local:18080" {
		t.Errorf("headscale server_url = %q, want https://home1.local:18080", got)
	}
}
