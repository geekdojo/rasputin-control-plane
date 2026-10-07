package quiesce

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

// The transfer and restore clients verify the api with the node's controlplane CA
// bundle and nothing else (geekdojo/geekdojo-brain#590). These drive the
// Stager's own transport and fetcher — no transportFor or fetcherFor
// override — so what is under test is the production client.

const trustBundlePath = "/var/lib/rasputin/mesh/tailscaled-ca.pem"

// failingTrust stands in for MeshTrust on a node whose bundle is missing.
func failingTrust() (*tls.Config, error) {
	return nil, fmt.Errorf("controlplane CA bundle %s: no such file or directory: this node trusts no controlplane CA", trustBundlePath)
}

func tlsXferRig(t *testing.T, ca *tlstest.CA) *xferRig {
	t.Helper()
	return newXferRigOn(t, func(h http.Handler) *httptest.Server { return ca.NewServer(t, h) })
}

// TC-590-15: a transfer on a node whose trust fails — a trust error, or no
// trust source at all — is refused as a backend error naming why, and the
// endpoint receives nothing.
func TestTransfer_RefusesWhenTrustFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		trust      TrustSource
		wantDetail string
	}{
		{"(a) trust returns an error naming the bundle", failingTrust, trustBundlePath},
		{"(b) no trust source", nil, "quiesce: no mesh trust source wired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tlsXferRig(t, tlstest.NewCA(t, "mesh"))
			rt := newFake(t)
			s := newStager(t, rt)
			staged := stageVault(t, rt, s)
			s.trust = tc.trust

			ack := s.Transfer(context.Background(), r.transferCmd(t, staged, proto.BackupMemberPath("vaultwarden", "vaultwarden-data")))
			if ack.OK || ack.Landed {
				t.Fatal("transfer succeeded with no usable trust")
			}
			if ack.Refusal != proto.StorageRefusalBackendError {
				t.Errorf("refusal = %q, want %q", ack.Refusal, proto.StorageRefusalBackendError)
			}
			if !strings.Contains(ack.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to contain %q", ack.Detail, tc.wantDetail)
			}
			if n := r.hits.Load(); n != 0 {
				t.Errorf("endpoint received %d request(s), want 0", n)
			}
		})
	}
}

// TC-590-16: a restore on a node whose trust fails is refused with the trust
// error in the detail, the source receives nothing, and the live volume is
// exactly as it was.
func TestRestoreVolume_RefusesWhenTrustFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		trust      TrustSource
		wantDetail string
	}{
		{"(a) trust returns an error naming the bundle", failingTrust, trustBundlePath},
		{"(b) no trust source", nil, "quiesce: no mesh trust source wired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRestoreRig(t)
			r.corrupt(t)
			before := r.snapshot(t)
			r.s.trust = tc.trust

			ack := r.s.RestoreVolume(context.Background(), r.cmd(t))
			if ack.OK || ack.Replaced {
				t.Fatal("restore succeeded with no usable trust")
			}
			if !strings.Contains(ack.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to contain %q", ack.Detail, tc.wantDetail)
			}
			if n := r.e.requests(); n != 0 {
				t.Errorf("source received %d request(s), want 0", n)
			}
			r.assertUntouched(t, before, ack)
		})
	}
}

// TC-590-17: trust is resolved for every transfer, so a CA re-delivered
// between two transfers is the one the second verifies with.
func TestTransfer_ResolvesTrustOnEveryTransfer(t *testing.T) {
	caA := tlstest.NewCA(t, "mesh-before")
	caB := tlstest.NewCA(t, "mesh-after")
	rigA := tlsXferRig(t, caA)
	rigB := tlsXferRig(t, caB)

	var calls atomic.Int32
	current := caA
	rt := newFake(t)
	s := newStager(t, rt)
	s.trust = func() (*tls.Config, error) {
		calls.Add(1)
		return proto.CATLSConfig(current.PEM, "test bundle")
	}
	staged := stageVault(t, rt, s)
	member := proto.BackupMemberPath("vaultwarden", "vaultwarden-data")

	if ack := s.Transfer(context.Background(), rigA.transferCmd(t, staged, member)); !ack.OK {
		t.Fatalf("first transfer (server under A, trust A): %s %s", ack.Refusal, ack.Detail)
	}
	current = caB // the CA is re-delivered
	if ack := s.Transfer(context.Background(), rigB.transferCmd(t, staged, member)); !ack.OK {
		t.Fatalf("second transfer (server under B, trust B): %s %s", ack.Refusal, ack.Detail)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("trust source called %d times for two transfers, want 2", n)
	}
}

// A trust failure never masks an unsupported destination: the scheme is
// still refused as unsupported, so the api's classification is unchanged.
func TestTransfer_UnsupportedDestinationStillClassifiedWithoutTrust(t *testing.T) {
	r := newXferRig(t)
	rt := newFake(t)
	s := newStager(t, rt)
	staged := stageVault(t, rt, s)
	s.trust = nil
	cmd := r.transferCmd(t, staged, proto.BackupMemberPath("vaultwarden", "vaultwarden-data"))
	cmd.Destination = "s3://bucket/prefix"
	ack := s.Transfer(context.Background(), cmd)
	if ack.Refusal != proto.BackupRefusalDestinationUnsupported {
		t.Errorf("refusal = %q, want %q", ack.Refusal, proto.BackupRefusalDestinationUnsupported)
	}
}
