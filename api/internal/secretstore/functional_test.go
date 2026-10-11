package secretstore_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The functional switch and binary are the smoke test's
// (docs/testing-secret-store.md): CI installs the pinned release and sets
// RASPUTIN_SECRETSTORE_FUNCTIONAL=required, so a missing binary fails the
// backend job instead of skipping (TC-758-32).
const (
	binEnv    = "RASPUTIN_SECRETSTORE_BIN"
	switchEnv = "RASPUTIN_SECRETSTORE_FUNCTIONAL"
)

// TestClient_AgainstTheRealStore runs secretstore.Client against the pinned
// OpenBao through the secretstoretest harness: the contract table
// (TC-758-27), a client with no certificate and one with a foreign-CA leaf
// (TC-758-30), a sealed store (TC-758-28), a stopped store (TC-758-29), and a
// redaction scan across all of it (TC-758-31). The steps share one store and
// run in that order, because sealing and stopping are one-way.
func TestClient_AgainstTheRealStore(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}

	log, rec := logkittest.New()
	text := slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(slog.NewMultiHandler(log.Handler(), text))
	h, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin, TempParent: t.TempDir(), Logger: logger, Now: time.Now, Rand: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := h.Start(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// t.Context() is cancelled before Cleanup runs; Background lets the store
	// stop cleanly.
	t.Cleanup(func() {
		if err := store.Close(context.Background()); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})
	token, err := store.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tokenText := string(token.Reveal())
	client := newClient(t, store.URL(), store.ClientTLS(), logger)
	var errs []error
	var outs []any

	t.Run("TC-758-27 contract", func(t *testing.T) {
		contractTable(t, client, token, kvPath(t, secretstoretest.KVMount, "contract/a"),
			kvPath(t, secretstoretest.KVMount, "contract/missing"), time.Time{})
		p := kvPath(t, secretstoretest.KVMount, "redaction")
		if _, err := client.Write(t.Context(), token, p, map[string]secret.Value{"k": tok(sentinelValue)}, 0); err != nil {
			t.Fatal(err)
		}
		kv, err := client.Read(t.Context(), token, p, 0)
		if err != nil || string(kv.Data["k"].Reveal()) != sentinelValue {
			t.Fatalf("read back the sentinel = %v", err)
		}
		_, casErr := client.Write(t.Context(), token, p, map[string]secret.Value{"k": tok(sentinelValue)}, 0)
		_, nfErr := client.Read(t.Context(), token, kvPath(t, secretstoretest.KVMount, "never"), 0)
		_, deniedErr := client.Read(t.Context(), tok(sentinelToken), p, 0)
		if !errors.Is(deniedErr, secretstore.ErrDenied) {
			t.Errorf("a bad token: err = %v, want ErrDenied", deniedErr)
		}
		outs = append(outs, kv)
		errs = append(errs, casErr, nfErr, deniedErr)
	})

	t.Run("TC-758-30 refused client certificate", func(t *testing.T) {
		noCert := store.ClientTLS()
		noCert.GetClientCertificate = nil
		foreignCA, err := tlsca.Ensure(tlsca.StoreConfig(), t.TempDir(), "foreign", tlscatest.Deps())
		if err != nil {
			t.Fatal(err)
		}
		foreignLeaf, err := foreignCA.MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: secretstoretest.ClientRole})
		if err != nil {
			t.Fatal(err)
		}
		foreignCert, err := tls.LoadX509KeyPair(foreignLeaf.CertPath, foreignLeaf.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		foreign := store.ClientTLS()
		foreign.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &foreignCert, nil }
		for name, tc := range map[string]*tls.Config{"no certificate": noCert, "foreign-CA leaf": foreign} {
			c := newClient(t, store.URL(), tc, logger)
			_, healthErr := c.Health(t.Context())
			_, readErr := c.Read(t.Context(), token, kvPath(t, secretstoretest.KVMount, "redaction"), 0)
			for op, err := range map[string]error{"Health": healthErr, "Read": readErr} {
				if !errors.Is(err, secretstore.ErrDenied) || errors.Is(err, secretstore.ErrUnreachable) {
					t.Errorf("%s %s: err = %v, want ErrDenied and not ErrUnreachable", name, op, err)
				}
			}
			errs = append(errs, healthErr, readErr)
		}
	})

	t.Run("TC-758-28 sealed", func(t *testing.T) {
		client.CloseIdleConnections()
		if err := store.RestartSealed(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, healthErr := client.Health(t.Context())
		_, readErr := client.Read(t.Context(), token, kvPath(t, secretstoretest.KVMount, "redaction"), 0)
		for op, err := range map[string]error{"Health": healthErr, "Read": readErr} {
			if !errors.Is(err, secretstore.ErrSealed) {
				t.Errorf("%s: err = %v, want ErrSealed", op, err)
			}
		}
		errs = append(errs, healthErr, readErr)
	})

	t.Run("TC-758-29 stopped", func(t *testing.T) {
		client.CloseIdleConnections()
		if err := store.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		p := kvPath(t, secretstoretest.KVMount, "redaction")
		for op, call := range map[string]func() error{
			"Health": func() error { _, err := client.Health(t.Context()); return err },
			"Read":   func() error { _, err := client.Read(t.Context(), token, p, 0); return err },
			"Write": func() error {
				_, err := client.Write(t.Context(), token, p, map[string]secret.Value{"k": tok(sentinelValue)}, 1)
				return err
			},
			"Versions": func() error { _, err := client.Versions(t.Context(), token, p); return err },
		} {
			err := call()
			if !errors.Is(err, secretstore.ErrUnreachable) {
				t.Errorf("%s: err = %v, want ErrUnreachable", op, err)
			}
			errs = append(errs, err)
		}
	})

	t.Run("TC-758-31 redaction", func(t *testing.T) {
		assertRedacted(t, rec, outs, errs, tokenText)
	})
}
