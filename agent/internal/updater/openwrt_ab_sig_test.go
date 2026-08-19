package updater

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/artifactsig"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// These cover the publisher gate the firewall shipped without: until
// geekdojo/geekdojo-brain#154 the only check on an OTA artifact was a sha256
// compare over mesh TLS, which authenticates the transport and not the
// publisher. The cases below are all about REFUSING, because the failure mode
// that matters here is a check that quietly does nothing — which is exactly
// what the previous implementation did for its whole life.

// artifactServer serves body at /bundle and sig at /bundle/sig, recording
// whether each was actually fetched. The counters are the point of several
// tests below: "did the node avoid moving half a gigabyte" is not observable
// from the returned error.
type artifactServer struct {
	srv        *httptest.Server
	bundleHits atomic.Int32
	sigHits    atomic.Int32
	sigStatus  int
	sigBody    []byte
	body       []byte
}

func newArtifactServer(t *testing.T, body, sig []byte) *artifactServer {
	t.Helper()
	as := &artifactServer{body: body, sigBody: sig, sigStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/bundle/sig", func(w http.ResponseWriter, r *http.Request) {
		as.sigHits.Add(1)
		if as.sigStatus != http.StatusOK {
			w.WriteHeader(as.sigStatus)
			return
		}
		_, _ = w.Write(as.sigBody)
	})
	mux.HandleFunc("/bundle", func(w http.ResponseWriter, r *http.Request) {
		as.bundleHits.Add(1)
		_, _ = w.Write(as.body)
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

func (a *artifactServer) bundleURL() string { return a.srv.URL + "/bundle" }
func (a *artifactServer) sigURL() string    { return a.srv.URL + "/bundle/sig" }

func TestOpenWrtDownload_StagesTheSignatureBesideTheArtifact(t *testing.T) {
	body := []byte("SQUASHFS-BYTES")
	sum := sha256.Sum256(body)
	as := newArtifactServer(t, body, []byte("detached-cms-bytes"))

	b, err := NewOpenWrtABBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path, observed, err := b.Download(context.Background(), "b1", as.bundleURL(), as.sigURL(),
		hex.EncodeToString(sum[:]), int64(len(body)), nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if observed != hex.EncodeToString(sum[:]) {
		t.Errorf("observed sha = %s", observed)
	}
	got, err := os.ReadFile(artifactsig.SigPathFor(path))
	if err != nil {
		t.Fatalf("signature not staged beside the artifact: %v", err)
	}
	if string(got) != "detached-cms-bytes" {
		t.Errorf("staged signature = %q", got)
	}
}

// An api too old to send a signature URL must not get an unsigned artifact
// installed on the strength of the sha gate — and must not cost a transfer to
// find that out.
func TestOpenWrtDownload_RefusesWithoutASignatureURL(t *testing.T) {
	as := newArtifactServer(t, []byte("SQUASHFS-BYTES"), nil)
	b, err := NewOpenWrtABBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = b.Download(context.Background(), "b1", as.bundleURL(), "", "", 0, nil)
	if err == nil {
		t.Fatal("Download accepted an artifact with no signature URL")
	}
	if !strings.Contains(err.Error(), "will not install an unsigned artifact") {
		t.Errorf("error should say why it refused, got: %v", err)
	}
	if n := as.bundleHits.Load(); n != 0 {
		t.Errorf("artifact was fetched %d times; the refusal must precede the transfer", n)
	}
}

// A bundle staged before the api knew to stage signatures. The distinction
// between "nobody staged one" and "someone tampered with this" is the whole
// value of the message.
func TestOpenWrtDownload_MissingStagedSignatureSaysRepull(t *testing.T) {
	as := newArtifactServer(t, []byte("SQUASHFS-BYTES"), nil)
	as.sigStatus = http.StatusNotFound

	b, err := NewOpenWrtABBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = b.Download(context.Background(), "b1", as.bundleURL(), as.sigURL(), "", 0, nil)
	if err == nil {
		t.Fatal("Download accepted an artifact whose signature 404'd")
	}
	if !strings.Contains(err.Error(), "re-pull the release") {
		t.Errorf("error should tell the operator what to do, got: %v", err)
	}
	if n := as.bundleHits.Load(); n != 0 {
		t.Errorf("artifact was fetched %d times; the signature is fetched first for exactly this reason", n)
	}
}

func TestOpenWrtDownload_RejectsAnOversizedSignature(t *testing.T) {
	as := newArtifactServer(t, []byte("SQUASHFS-BYTES"), make([]byte, maxSignatureBytes+1))
	b, err := NewOpenWrtABBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Download(context.Background(), "b1", as.bundleURL(), as.sigURL(), "", 0, nil); err == nil {
		t.Fatal("Download accepted a signature larger than the cap")
	}
	if n := as.bundleHits.Load(); n != 0 {
		t.Errorf("artifact was fetched %d times", n)
	}
}

func TestOpenWrtDownload_EmptySignatureRejected(t *testing.T) {
	as := newArtifactServer(t, []byte("SQUASHFS-BYTES"), []byte{})
	b, err := NewOpenWrtABBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Download(context.Background(), "b1", as.bundleURL(), as.sigURL(), "", 0, nil); err == nil {
		t.Fatal("Download accepted an empty signature")
	}
}

// The production Install path, with the production verifySig — no test seam.
// This is the assertion that the gate is actually WIRED: every other test in
// this package overrides verifySig, and the shipped default returning nil is
// precisely the bug #154 describes.
func TestOpenWrtInstall_FailsClosedWithoutAValidSignature(t *testing.T) {
	trustRoot := filepath.Join(t.TempDir(), "root-ca.pem")
	writeSelfSignedRoot(t, trustRoot)

	for _, tc := range []struct {
		name      string
		trustRoot string
		writeSig  []byte
		wantIn    string
	}{
		{name: "no signature staged", trustRoot: trustRoot, wantIn: "signature file is missing"},
		{name: "signature is not a CMS object", trustRoot: trustRoot, writeSig: []byte("hello"), wantIn: "signature verify"},
		{name: "no trust root on the box", trustRoot: filepath.Join(t.TempDir(), "absent.pem"), wantIn: "trust root is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(artifactsig.TrustRootEnv, tc.trustRoot)
			stateDir := t.TempDir()
			b, err := NewOpenWrtABBackend(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			art := b.bundlePath("b1")
			if err := os.WriteFile(art, []byte("SQUASHFS-BYTES"), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.writeSig != nil {
				if err := os.WriteFile(artifactsig.SigPathFor(art), tc.writeSig, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, err = b.Install(context.Background(), "b1", art, proto.SlotB, nil)
			if err == nil {
				t.Fatal("Install applied an artifact with no valid publisher signature")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantIn)
			}
		})
	}
}

func writeSelfSignedRoot(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}
