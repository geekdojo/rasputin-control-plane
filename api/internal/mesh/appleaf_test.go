package mesh

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"slices"
	"testing"
)

func TestAppLeafDNSNames(t *testing.T) {
	want := []string{"jellyfin.home1.internal", "jellyfin.lan.home1.internal"}
	if got := AppLeafDNSNames("home1", "jellyfin"); !slices.Equal(got, want) {
		t.Errorf("SANs = %v, want %v (bare name first — it is the CommonName)", got, want)
	}
	// Empty cluster id → the baseDomainFor dev fallback.
	if got := AppLeafDNSNames("", "app"); got[0] != "app.rasputin.internal" {
		t.Errorf("dev-fallback SAN = %v", got)
	}
}

// The leaf is identity, the route is policy. AppRouteHosts is the ONLY place on
// the delivery path that reads exposure, and an empty lan host is what keeps an
// app off the node's LAN listener.
func TestAppRouteHosts(t *testing.T) {
	tailnet, lan := AppRouteHosts("home1", "jellyfin", false)
	if tailnet != "jellyfin.home1.internal" {
		t.Errorf("tailnet host = %q", tailnet)
	}
	if lan != "" {
		t.Errorf("a tailnet-only app must have NO lan route host, got %q", lan)
	}
	if _, lan := AppRouteHosts("home1", "jellyfin", true); lan != "jellyfin.lan.home1.internal" {
		t.Errorf("lan-exposed host = %q", lan)
	}
	// Whatever the exposure, a route host that IS produced must be a name the
	// leaf actually carries, or TLS breaks at the listener.
	sans := AppLeafDNSNames("home1", "jellyfin")
	for _, expose := range []bool{false, true} {
		tailnet, lan := AppRouteHosts("home1", "jellyfin", expose)
		for _, h := range []string{tailnet, lan} {
			if h != "" && !slices.Contains(sans, h) {
				t.Errorf("route host %q is not in the leaf SANs %v", h, sans)
			}
		}
	}
}

// The SAN set does not move with exposure. A certificate asserts identity, not
// permission — what a node will answer for is a route on a bound listener — so
// both names are always present and an exposure toggle costs no re-mint.
func TestMintAppLeaf_SANsAreExposureIndependent(t *testing.T) {
	ca := newCAForTest(t)
	wantSANs := []string{"jellyfin.home1.internal", "jellyfin.lan.home1.internal"}

	certPEM, keyPEM, err := MintAppLeaf(ca, "home1", "jellyfin")
	if err != nil {
		t.Fatalf("MintAppLeaf: %v", err)
	}
	if len(keyPEM) == 0 {
		t.Error("empty key PEM")
	}
	cert := parseLeaf(t, certPEM)
	if !slices.Equal(cert.DNSNames, wantSANs) {
		t.Errorf("cert DNSNames = %v, want %v", cert.DNSNames, wantSANs)
	}
	if cert.Subject.CommonName != wantSANs[0] {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, wantSANs[0])
	}
	// It's a server-auth leaf, and it chains to the Mesh CA.
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Errorf("leaf missing serverAuth EKU: %v", cert.ExtKeyUsage)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("leaf does not verify against the Mesh CA: %v", err)
	}
}

// TestPrepareAppLeaf_RenewsUntilCommitted proves the commit-on-delivery
// contract: a freshly-prepared leaf is not persisted, so it keeps renewing
// until CommitAppLeaf runs — after which it's returned unchanged (renewed=false).
func TestPrepareAppLeaf_RenewsUntilCommitted(t *testing.T) {
	ca := newCAForTest(t)
	dir := t.TempDir()

	certPEM, keyPEM, renewed, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", false)
	if err != nil {
		t.Fatalf("PrepareAppLeaf: %v", err)
	}
	if !renewed {
		t.Fatal("first prepare (no disk leaf) must mint fresh: renewed=true")
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("empty PEM from fresh mint")
	}

	// Uncommitted → a second prepare must STILL renew (offline-retry safety).
	if _, _, renewed2, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", false); err != nil || !renewed2 {
		t.Fatalf("uncommitted leaf must keep renewing: renewed=%v err=%v", renewed2, err)
	}

	// Commit, then the same still-valid leaf comes back with renewed=false.
	if err := CommitAppLeaf(dir, certPEM, keyPEM, false); err != nil {
		t.Fatalf("CommitAppLeaf: %v", err)
	}
	got, _, renewed3, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", false)
	if err != nil {
		t.Fatalf("PrepareAppLeaf after commit: %v", err)
	}
	if renewed3 {
		t.Error("committed, still-valid leaf must not renew")
	}
	if !bytes.Equal(got, certPEM) {
		t.Error("prepare returned a different cert than was committed")
	}
}

// TestPrepareAppLeaf_RedeliversOnRouteDrift: changing exposeLAN must make the
// app due for a delivery even though its certificate is untouched.
//
// This is the load-bearing test of the exposure/identity split. Exposure used to
// live in the SAN set, so a toggle re-minted the leaf and THAT re-mint was what
// shipped the new route. With the leaf now carrying both names always, nothing
// about the cert changes when exposure does — so if the delivered-route marker
// failed to notice, revoking LAN exposure would go back to being a database
// write the node never hears about. That is #197's original defect, and it went
// unseen for ten months.
//
// BOTH DIRECTIONS. Revoke is the one that matters for security; grant is the one
// that would break the feature.
func TestPrepareAppLeaf_RedeliversOnRouteDrift(t *testing.T) {
	for _, tc := range []struct {
		name       string
		from, want bool
	}{
		{"grant LAN exposure", false, true},
		{"revoke LAN exposure", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCAForTest(t)
			dir := t.TempDir()

			certPEM, keyPEM, _, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", tc.from)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if err := CommitAppLeaf(dir, certPEM, keyPEM, tc.from); err != nil {
				t.Fatalf("commit: %v", err)
			}

			after, _, renewed, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", tc.want)
			if err != nil {
				t.Fatalf("prepare after toggle: %v", err)
			}
			if !renewed {
				t.Fatal("an exposeLAN toggle must mark the app due for delivery: nothing is shipped otherwise, and the node keeps the route it already had")
			}
			// The cert itself must NOT have been re-minted — that churn is what
			// this design removes, and a changing identity is a worse one.
			if !bytes.Equal(after, certPEM) {
				t.Error("a route change re-minted the leaf; the cert covers both names and must be reused")
			}
			if got := parseLeaf(t, after).DNSNames; !slices.Equal(got, AppLeafDNSNames("home1", "jellyfin")) {
				t.Errorf("SANs = %v, want both names regardless of exposure", got)
			}
		})
	}
}

// A leaf committed before the delivered-route marker existed has a valid cert
// and no record of what route the node holds. It must re-deliver ONCE — which
// also migrates the leaf to the two-name SAN set — rather than assume.
func TestPrepareAppLeaf_LegacyLeafWithoutMarkerRedelivers(t *testing.T) {
	ca := newCAForTest(t)
	dir := t.TempDir()

	certPEM, keyPEM, _, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", false)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := CommitAppLeaf(dir, certPEM, keyPEM, false); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// Simulate the pre-marker on-disk state: PEMs present, no route.json.
	if err := os.Remove(appRoutePath(dir)); err != nil {
		t.Fatalf("remove marker: %v", err)
	}
	if _, _, renewed, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", false); err != nil || !renewed {
		t.Fatalf("a leaf with no delivered-route marker must re-deliver: renewed=%v err=%v", renewed, err)
	}
}

// And it must SETTLE. Exact SAN matching plus a route marker would be a
// re-delivery loop if a committed leaf never satisfied its own spec — every
// sweep would ship to the node forever.
func TestPrepareAppLeaf_SettlesAfterCommit(t *testing.T) {
	ca := newCAForTest(t)
	dir := t.TempDir()

	for _, expose := range []bool{false, true, false} {
		certPEM, keyPEM, _, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", expose)
		if err != nil {
			t.Fatalf("prepare(%v): %v", expose, err)
		}
		if err := CommitAppLeaf(dir, certPEM, keyPEM, expose); err != nil {
			t.Fatalf("commit(%v): %v", expose, err)
		}
		if _, _, renewed, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin", expose); err != nil || renewed {
			t.Fatalf("expose=%v: a committed leaf at an unchanged exposure must be reused, got renewed=%v err=%v", expose, renewed, err)
		}
	}
}

func TestPrepareAppLeaf_NilCA(t *testing.T) {
	if _, _, _, err := PrepareAppLeaf(nil, t.TempDir(), "home1", "app", false); err == nil {
		t.Error("nil CA must error")
	}
}

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("cert PEM did not decode")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}
