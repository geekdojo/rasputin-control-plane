package secretstoretest

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Adopt against the real pinned store (geekdojo/geekdojo-brain#765): store
// B, stopped, takes store A's cold copy — data, seal key, fragment and store
// CA — comes up unsealed under A's key id, and serves A's entry to a client
// whose leaf B minted from the adopted CA. Adopt refuses a running store and
// one without an external seal.
func TestAdopt_AgainstTheRealStore(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelInfo}))
	h, err := New(Config{BinaryPath: bin, TempParent: t.TempDir(), Logger: logger, Now: time.Now, Rand: rand.Reader, ExternalSeal: true})
	if err != nil {
		t.Fatal(err)
	}
	start := func() *Store {
		s, err := h.Start(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close(context.Background()) })
		return s
	}
	a, b := start(), start()
	if err := b.Adopt(t.Context(), Restored{}); err == nil || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("Adopt on a running store = %v, want a refusal", err)
	}
	p, err := secretstore.NewKVPath(KVMount, "adopt/kept")
	if err != nil {
		t.Fatal(err)
	}
	clientFor := func(s *Store) *secretstore.Client {
		u, _ := url.Parse(s.URL())
		c, err := secretstore.New(secretstore.Config{Addr: u, TLS: s.ClientTLS(), CallTimeout: 10 * time.Second, Logger: logger})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.CloseIdleConnections)
		return c
	}
	tok, err := a.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientFor(a).Write(t.Context(), tok, p, map[string]secret.Value{"k": secret.New([]byte("adopted-value"))}, 0); err != nil {
		t.Fatal(err)
	}
	if err := a.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := b.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	r := Restored{
		DataDir: a.DataDir(), SealKey: filepath.Join(a.SealDir(), "seal-key"), SealHCL: filepath.Join(a.SealDir(), "seal.hcl"),
		CAKey: filepath.Join(a.CADir(), tlsca.StoreKeyFile), CACert: filepath.Join(a.CADir(), tlsca.StoreCertFile),
	}
	if err := b.Adopt(t.Context(), r); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	if string(b.StoreCA().CertPEM) != string(a.StoreCA().CertPEM) {
		t.Fatal("B did not load A's store CA")
	}
	wantFrag, _ := os.ReadFile(r.SealHCL)
	gotFrag, _ := os.ReadFile(filepath.Join(b.SealDir(), "seal.hcl"))
	if id := currentKeyIDRE.FindSubmatch(gotFrag); id == nil || !strings.Contains(string(wantFrag), string(id[1])) {
		t.Fatalf("B's fragment %q does not name A's key id", gotFrag)
	}
	bc := clientFor(b)
	if hl, err := bc.Health(t.Context()); err != nil || hl.Sealed || !hl.Initialized {
		t.Fatalf("B's health = (%+v, %v)", hl, err)
	}
	tok2, err := b.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	kv, err := bc.Read(t.Context(), tok2, p, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer kv.Destroy()
	if string(kv.Data["k"].Reveal()) != "adopted-value" {
		t.Fatal("B does not serve A's entry")
	}
}

// Adopt refuses a store started without an external seal, and a fragment
// that names no key id, before it changes anything.
func TestAdopt_Refusals(t *testing.T) {
	s := &Store{exited: make(chan struct{})}
	close(s.exited)
	if err := s.Adopt(context.Background(), Restored{}); err == nil || !strings.Contains(err.Error(), "no external seal") {
		t.Errorf("Adopt without an external seal = %v", err)
	}
	dir := t.TempDir()
	s.sealDir = dir
	frag := filepath.Join(dir, "frag.hcl")
	if err := os.WriteFile(frag, []byte("seal \"static\" {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Adopt(context.Background(), Restored{SealHCL: frag}); err == nil || !strings.Contains(err.Error(), "names no rasputin key id") {
		t.Errorf("Adopt of a fragment with no key id = %v", err)
	}
	if err := s.Adopt(context.Background(), Restored{SealHCL: filepath.Join(dir, "absent")}); err == nil {
		t.Error("Adopt of a missing fragment succeeded")
	}
}
