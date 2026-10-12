package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// tlsValue is a stand-in token.
func tlsValue() secret.Value { return secret.New([]byte("test-token")) }

type noRestores struct{}

func (noRestores) Active() (string, bool) { return "", false }

// sealDeps is a complete set of wiring inputs for mode.
func sealDeps(t *testing.T, mode string) sealRotateDeps {
	t.Helper()
	log, _ := logkittest.New()
	ca, err := tlsca.Ensure(tlsca.StoreConfig(), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	mon, err := storestate.New(storestate.Deps{
		Store: secretstore.Disabled{}, Now: time.Now, Log: log,
		JobRunning: func(context.Context, string) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return sealRotateDeps{
		mode: mode, addr: "https://127.0.0.1:8200", storeCA: ca, store: secretstore.Disabled{},
		run:        func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
		monitor:    mon,
		restores:   noRestores{},
		jobRunning: func(context.Context, string) (bool, error) { return false, nil },
		rand:       rand.Reader, now: time.Now, log: log,
	}
}

// TC-830-14: the workflow is registered in every mode and never scheduled;
// under openbao the capture lock is the rotator's gate and SetStoreAlerts
// gets the joined source; outside it there is no lock and readiness passes
// through unchanged.
func TestSealRotateWiring_EveryMode(t *testing.T) {
	readiness := func(context.Context, time.Time) []proto.Alert {
		return []proto.Alert{{ID: "secret-store:sealed"}}
	}
	for _, mode := range []string{storeModeOpenBao, storeModeMock, storeModeOff} {
		t.Run(mode, func(t *testing.T) {
			w, err := sealRotateWiring(sealDeps(t, mode))
			if err != nil {
				t.Fatal(err)
			}
			if w.workflow.Kind != sealrotate.Kind || len(w.workflow.Steps) != 6 || w.workflow.OnTerminal == nil {
				t.Fatalf("workflow = %q with %d steps", w.workflow.Kind, len(w.workflow.Steps))
			}
			if w.storeAlerts(nil) != nil {
				t.Error("a store-alert source with no readiness source")
			}
			got := w.storeAlerts(readiness)(t.Context(), time.Now())
			if mode != storeModeOpenBao {
				if w.captureLock() != nil || w.gate != nil {
					t.Error("a capture lock outside openbao")
				}
				if len(got) != 1 {
					t.Errorf("alerts = %+v, want readiness's alone", got)
				}
				return
			}
			if w.gate == nil || w.captureLock() != w.gate {
				t.Fatal("RunConfig.CaptureLock is not the rotator's gate")
			}
			// The production seal dir is absent here, so the incomplete
			// alert reads the unreadable tree and joins readiness's.
			ids := []string{}
			for _, a := range got {
				ids = append(ids, a.ID)
			}
			if !slices.Equal(ids, []string{"secret-store:sealed", sealrotate.IncompleteAlertID}) {
				t.Errorf("joined alerts = %v", ids)
			}
		})
	}
	// Never scheduled: no entry main builds has the rotation's kind.
	entries := append(reconcileEntries(time.Minute, time.Minute, time.Minute, time.Minute),
		backupRunEntry(time.Hour, func(context.Context) (bool, string) { return false, "" }))
	aud, err := storeAuditWiring(storeModeOpenBao, t.TempDir(), secretstore.Disabled{},
		func(context.Context, string, ...string) ([]byte, error) { return nil, nil }, sealDeps(t, storeModeOff).log)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range append(entries, aud.entries()...) {
		if e.Kind == sealrotate.Kind {
			t.Errorf("a scheduler entry has kind %s", e.Kind)
		}
	}
}

// TC-830-14, F-830-04: in mock mode a submitted rotation (what POST /api/jobs
// does, through SubmitRawSpec) is a job, not "unknown job kind", and it fails
// at validate with the not-openbao sentence and a job-failed record.
func TestSealRotateWiring_MockModeRecordsAJob(t *testing.T) {
	w, err := sealRotateWiring(sealDeps(t, storeModeMock))
	if err != nil {
		t.Fatal(err)
	}
	js := openJobStore(t)
	r := jobs.NewRunner(js, nil)
	r.Register(w.workflow)
	j, err := r.SubmitRawSpec(t.Context(), sealrotate.Kind, nil, "operator")
	if err != nil {
		t.Fatalf("submit = %v, want a job", err)
	}
	r.Wait()
	got, err := js.GetJob(t.Context(), j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != jobs.StatusFailed || got.Error == "" || got.Error[0] != 'T' {
		t.Fatalf("job %s: %q", got.Status, got.Error)
	}
}

// TC-830-14: wiring refuses what it cannot build with.
func TestSealRotateWiring_Refuses(t *testing.T) {
	for name, mut := range map[string]func(*sealRotateDeps){
		"nil logger":        func(d *sealRotateDeps) { d.log = nil },
		"nil store CA":      func(d *sealRotateDeps) { d.storeCA = nil },
		"nil monitor":       func(d *sealRotateDeps) { d.monitor = nil },
		"nil store":         func(d *sealRotateDeps) { d.store = nil },
		"nil run":           func(d *sealRotateDeps) { d.run = nil },
		"nil restores":      func(d *sealRotateDeps) { d.restores = nil },
		"nil jobRunning":    func(d *sealRotateDeps) { d.jobRunning = nil },
		"nil rand":          func(d *sealRotateDeps) { d.rand = nil },
		"nil clock":         func(d *sealRotateDeps) { d.now = nil },
		"a refused address": func(d *sealRotateDeps) { d.addr = "http://example.com" },
	} {
		d := sealDeps(t, storeModeOpenBao)
		mut(&d)
		if _, err := sealRotateWiring(d); err == nil {
			t.Errorf("%s: wiring accepted", name)
		}
	}
}

// The off-mode stand-ins all refuse.
func TestOffSealDeps_Refuse(t *testing.T) {
	log, _ := logkittest.New()
	d := offSealDeps(log)
	ctx := context.Background()
	off := offSeal{}
	if _, err := off.CertLogin(ctx, "r"); err == nil {
		t.Error("CertLogin")
	}
	if off.RotateRoot(ctx, tlsValue()) == nil || d.Restart(ctx) == nil {
		t.Error("RotateRoot or Restart")
	}
	if _, err := off.State(); err == nil {
		t.Error("State")
	}
	if off.WriteRotationKey("", tlsValue()) == nil || off.WriteSealKey(tlsValue()) == nil ||
		off.WriteFragment(sealrotate.Fragment{}) == nil || off.RemoveRotation() == nil || off.TryAcquire("j") == nil {
		t.Error("a write")
	}
	if _, err := off.ReadRotationKey(""); err == nil {
		t.Error("ReadRotationKey")
	}
	if _, err := off.Read(make([]byte, 1)); err == nil {
		t.Error("Read")
	}
	if _, err := d.KeyID(); err == nil {
		t.Error("KeyID")
	}
	if _, err := d.JobRunning(ctx, "j"); err == nil {
		t.Error("JobRunning")
	}
	off.Release("j")
	d.Quiesce("j", storestate.QuiesceSealRotation)()
	if off.RotationHolder() != "" {
		t.Error("RotationHolder")
	}
	if _, active := off.Active(); active {
		t.Error("Active")
	}
}

// TC-830-13: the rotation client presents a new leaf on each handshake (a
// new serial), CN rasputin-seal-rotate, clientAuth only, signed by the store
// CA, over TLS 1.3 to a server trusted only through the store CA; nothing is
// written to disk.
func TestSealRotateMint_EachHandshakeANewLeaf(t *testing.T) {
	ca, err := tlsca.Ensure(tlsca.StoreConfig(), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ca.MintLeafToDisk(t.TempDir(), storeServerLeafSpec())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(server.CertPath, server.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	var mu sync.Mutex
	var seen []*x509.Certificate
	var versions []uint16
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.TLS.PeerCertificates[0])
		versions = append(versions, r.TLS.Version)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	before := listDir(t, cwd)
	tlsCfg, err := secretstore.NewMintedTLSConfig(ca.CertPEM, sealRotateMint(ca))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	lg, _ := logkittest.New()
	c, err := secretstore.New(secretstore.Config{Addr: u, TLS: tlsCfg, CallTimeout: 5 * time.Second, Logger: lg})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := c.RotateRoot(t.Context(), tlsValue()); err != nil {
			t.Fatal(err)
		}
		c.CloseIdleConnections() // the next call makes a new handshake
	}
	if len(seen) != 2 {
		t.Fatalf("%d requests", len(seen))
	}
	if seen[0].SerialNumber.Cmp(seen[1].SerialNumber) == 0 {
		t.Error("both handshakes presented the same leaf")
	}
	for i, leaf := range seen {
		if leaf.Subject.CommonName != sealrotate.RotationRole {
			t.Errorf("leaf %d CN = %q", i, leaf.Subject.CommonName)
		}
		if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
			t.Errorf("leaf %d EKU = %v, want clientAuth only", i, leaf.ExtKeyUsage)
		}
		if err := leaf.CheckSignatureFrom(ca.Cert); err != nil {
			t.Errorf("leaf %d is not signed by the store CA: %v", i, err)
		}
		if versions[i] != tls.VersionTLS13 {
			t.Errorf("handshake %d version %x, want TLS 1.3", i, versions[i])
		}
	}
	if after := listDir(t, cwd); !slices.Equal(before, after) {
		t.Errorf("the working directory changed: %v -> %v", before, after)
	}

	// A mint that fails fails the handshake as unreachable.
	broken := sealRotateMint(nil)
	if _, err := broken(); err == nil {
		t.Fatal("a mint with no CA succeeded")
	}
	badCfg, err := secretstore.NewMintedTLSConfig(ca.CertPEM, broken)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := secretstore.New(secretstore.Config{Addr: u, TLS: badCfg, CallTimeout: 5 * time.Second, Logger: lg})
	if err != nil {
		t.Fatal(err)
	}
	if err := bad.RotateRoot(t.Context(), tlsValue()); !errors.Is(err, secretstore.ErrUnreachable) {
		t.Errorf("RotateRoot with a failing mint = %v, want unreachable", err)
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}
