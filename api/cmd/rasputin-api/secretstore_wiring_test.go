package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// recordedRun is a runFunc that records each command and returns err.
type recordedRun struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (r *recordedRun) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return nil, r.err
}

func (r *recordedRun) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// noRestartHook is the after-restart hook a test that does not observe it passes.
func noRestartHook(context.Context) {}

var restartPair = []string{"systemctl reset-failed openbao.service", "systemctl restart openbao.service"}

// testClock is a settable clock for a CA's Deps.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func ensureStoreCA(t *testing.T, trustDir string, d tlsca.Deps) *tlsca.CA {
	t.Helper()
	ca, err := tlsca.Ensure(tlsca.StoreConfig(), trustDir, "test", d)
	if err != nil {
		t.Fatalf("store CA: %v", err)
	}
	return ca
}

func storeLeafDirs(dataDir string) []string {
	return []string{filepath.Join(dataDir, "tls", storeServerLeafName), filepath.Join(dataDir, "tls", storeClientLeafName),
		filepath.Join(dataDir, "tls", storeProvisionerLeafName)}
}

func assertNoStoreLeafDirs(t *testing.T, dataDir string) {
	t.Helper()
	for _, d := range storeLeafDirs(dataDir) {
		if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists (stat %v), want no store leaf directory", d, err)
		}
	}
}

// waitSweep receives the startup sweep's one report.
func waitSweep(t *testing.T, done <-chan tlsca.LeafSweepReport) tlsca.LeafSweepReport {
	t.Helper()
	if done == nil {
		t.Fatal("startStoreSweep started nothing")
	}
	rep, ok := <-done
	if !ok {
		t.Fatal("the startup sweep closed without a report")
	}
	return rep
}

// TC-758-17: the selector and the address decide the mode, and every refused
// setting is Disabled with one configfault record; nothing exits.
func TestWireSecretStore_Selection(t *testing.T) {
	ca := ensureStoreCA(t, t.TempDir(), tlscatest.Deps())
	const goodAddr = "https://127.0.0.1:8200"
	for _, tc := range []struct {
		name, backend, addr string
		nilCA               bool
		mode                string
		level               slog.Level
		msg, setting        string
		configfault         bool
	}{
		{name: "unset", backend: "", addr: goodAddr, mode: storeModeOff, level: slog.LevelInfo, msg: "secret store off: not configured"},
		{name: "mock", backend: "mock", addr: goodAddr, mode: storeModeMock, level: slog.LevelWarn, msg: "in-memory mock"},
		{name: "wrong case", backend: "OpenBao", addr: goodAddr, mode: storeModeOff, level: slog.LevelError, setting: "RASPUTIN_SECRETSTORE_BACKEND", configfault: true},
		{name: "padded", backend: " openbao", addr: goodAddr, mode: storeModeOff, level: slog.LevelError, setting: "RASPUTIN_SECRETSTORE_BACKEND", configfault: true},
		{name: "blank", backend: " ", addr: goodAddr, mode: storeModeOff, level: slog.LevelError, setting: "RASPUTIN_SECRETSTORE_BACKEND", configfault: true},
		{name: "padded mock", backend: "mock ", addr: goodAddr, mode: storeModeOff, level: slog.LevelError, setting: "RASPUTIN_SECRETSTORE_BACKEND", configfault: true},
		{name: "unknown", backend: "vault", addr: goodAddr, mode: storeModeOff, level: slog.LevelError, setting: "RASPUTIN_SECRETSTORE_BACKEND", configfault: true},
		{name: "http address", backend: "openbao", addr: "http://127.0.0.1:8200", mode: storeModeOff, level: slog.LevelError, setting: "RASPUTIN_SECRETSTORE_ADDR", configfault: true},
		{name: "non-loopback address", backend: "openbao", addr: "https://10.0.0.1:8200", mode: storeModeOff, level: slog.LevelError, setting: "RASPUTIN_SECRETSTORE_ADDR", configfault: true},
		{name: "address with a path", backend: "openbao", addr: "https://127.0.0.1:8200/v1", mode: storeModeOff, level: slog.LevelError, setting: "RASPUTIN_SECRETSTORE_ADDR", configfault: true},
		{name: "no store CA", backend: "openbao", addr: goodAddr, nilCA: true, mode: storeModeOff, level: slog.LevelError, setting: "RASPUTIN_SECRETSTORE_BACKEND", configfault: true},
		{name: "openbao, blank address resolved", backend: "openbao", addr: "blank", mode: storeModeOpenBao},
		{name: "openbao, padded address resolved", backend: "openbao", addr: "padded", mode: storeModeOpenBao},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := tc.addr
			switch addr {
			case "blank":
				t.Setenv("RASPUTIN_SECRETSTORE_ADDR", "   ")
				addr = secretStoreAddrFromEnv()
			case "padded":
				t.Setenv("RASPUTIN_SECRETSTORE_ADDR", "  https://127.0.0.1:8300  ")
				addr = secretStoreAddrFromEnv()
			}
			sca := ca
			if tc.nilCA {
				sca = nil
			}
			dataDir := t.TempDir()
			log, rec := logkittest.New()
			run := &recordedRun{}
			w, err := wireSecretStore(t.Context(), log, tc.backend, addr, sca, dataDir, run.run, noRestartHook)
			if err != nil {
				t.Fatalf("wireSecretStore = %v", err)
			}
			if w.mode != tc.mode {
				t.Fatalf("mode = %q, want %q", w.mode, tc.mode)
			}
			switch tc.mode {
			case storeModeOff:
				if _, ok := w.store.(secretstore.Disabled); !ok {
					t.Errorf("store = %T, want secretstore.Disabled", w.store)
				}
				if w.sweeper != nil || w.registeredNames() != nil {
					t.Errorf("an off store registered leaves: %v", w.registeredNames())
				}
			case storeModeMock:
				if _, ok := w.store.(*secretstore.Mock); !ok {
					t.Errorf("store = %T, want *secretstore.Mock", w.store)
				}
			case storeModeOpenBao:
				if w.client == nil || w.store != secretStore(w.client) {
					t.Errorf("store = %T, want the real client", w.store)
				}
				if !slices.Equal(w.registeredNames(), []string{storeClientLeafName, storeProvisionerLeafName, storeServerLeafName}) {
					t.Errorf("registered = %v", w.registeredNames())
				}
				if errs := rec.AtLevel(slog.LevelError); len(errs) != 0 {
					t.Errorf("%d ERROR records, want none:\n%s", len(errs), rec.Text())
				}
				return
			}
			recs := rec.Records()
			if len(recs) != 1 || recs[0].Level != tc.level {
				t.Fatalf("records = %s; want exactly one at %v", rec.Text(), tc.level)
			}
			if tc.msg != "" && !strings.Contains(recs[0].Message, tc.msg) {
				t.Errorf("message = %q, want it to contain %q", recs[0].Message, tc.msg)
			}
			if tc.configfault {
				cf, _ := logkittest.Attr(recs[0], "configfault")
				setting, _ := logkittest.Attr(recs[0], "setting")
				value, _ := logkittest.Attr(recs[0], "value")
				if cf != "true" || setting != tc.setting {
					t.Errorf("configfault=%q setting=%q, want true and %s", cf, setting, tc.setting)
				}
				if want := map[string]string{"RASPUTIN_SECRETSTORE_BACKEND": tc.backend, "RASPUTIN_SECRETSTORE_ADDR": addr}[tc.setting]; value != want {
					t.Errorf("value = %q, want %q", value, want)
				}
			}
			assertNoStoreLeafDirs(t, dataDir)
			if len(run.got()) != 0 {
				t.Errorf("run called %v", run.got())
			}
		})
	}
}

// TC-758-18, TC-758-19, TC-758-20: on first boot the absent leaves are no
// fault; the startup sweep, which runs while start has already returned and
// with no HTTPS address, mints both, restarts the store once, and reloads the
// client; a second start finds them usable and restarts nothing; a failed
// restart is one WARN and the leaf stays.
func TestStoreStartupSweep(t *testing.T) {
	t.Setenv("RASPUTIN_HTTPS_ADDR", "")
	if err := os.Unsetenv("RASPUTIN_HTTPS_ADDR"); err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	deps := tlscatest.Deps()
	deps.LeafClock = func() bool { <-gate; return true }
	trustDir, dataDir := t.TempDir(), t.TempDir()
	ca := ensureStoreCA(t, trustDir, deps)
	log, rec := logkittest.New()
	run := &recordedRun{}

	w, err := wireSecretStore(t.Context(), log, "openbao", defaultSecretStoreAddr, ca, dataDir, run.run, noRestartHook)
	if err != nil || w.mode != storeModeOpenBao {
		t.Fatalf("wireSecretStore = %v, %v; want openbao", w.mode, err)
	}
	if errs := rec.AtLevel(slog.LevelError); len(errs) != 0 {
		t.Fatalf("first boot logged %d ERROR records:\n%s", len(errs), rec.Text())
	}
	assertNoStoreLeafDirs(t, dataDir) // wiring touched no leaf path
	done := startStoreSweep(t.Context(), w.sweeper, log)
	// Both calls have returned while the clock gate is still shut.
	if len(run.got()) != 0 {
		t.Fatalf("run called before the gate opened: %v", run.got())
	}
	close(gate)
	rep := waitSweep(t, done)
	if !slices.Equal(run.got(), restartPair) {
		t.Errorf("run calls = %v, want %v", run.got(), restartPair)
	}
	if !slices.Equal(rep.Renewed, []string{storeProvisionerLeafName, storeServerLeafName, storeClientLeafName}) ||
		!slices.Equal(rep.Reloaded, []string{storeServerLeafName, storeClientLeafName}) || len(rep.Failed) != 0 {
		t.Errorf("report = %+v, want all three minted, and the server and client leaves reloaded once", rep)
	}

	// TC-758-19: the leaves' content.
	cp := tlscatest.Controlplane(t, "")
	server := parseLeaf(t, filepath.Join(dataDir, "tls", storeServerLeafName, "leaf.pem"))
	client := parseLeaf(t, filepath.Join(dataDir, "tls", storeClientLeafName, "leaf.pem"))
	if !slices.Equal(server.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) ||
		len(server.IPAddresses) != 1 || !server.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) || len(server.DNSNames) != 0 {
		t.Errorf("server leaf EKU %v IPs %v DNS %v; want serverAuth, [127.0.0.1], none", server.ExtKeyUsage, server.IPAddresses, server.DNSNames)
	}
	if !slices.Equal(client.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || client.Subject.CommonName != "rasputin-api" {
		t.Errorf("client leaf EKU %v CN %q; want clientAuth and rasputin-api", client.ExtKeyUsage, client.Subject.CommonName)
	}
	for name, leaf := range map[string]struct {
		c   *x509.Certificate
		eku x509.ExtKeyUsage
	}{"server": {server, x509.ExtKeyUsageServerAuth}, "client": {client, x509.ExtKeyUsageClientAuth}} {
		if err := verifyAgainst(leaf.c, ca.CertPEM, leaf.eku); err != nil {
			t.Errorf("%s leaf does not verify against the store CA: %v", name, err)
		}
		if err := verifyAgainst(leaf.c, cp.CertPEM, leaf.eku); err == nil {
			t.Errorf("%s leaf verifies against the controlplane CA", name)
		}
	}

	// A second start: both leaves usable, nothing restarted.
	run2 := &recordedRun{}
	w2, err := wireSecretStore(t.Context(), log, "openbao", defaultSecretStoreAddr, ca, dataDir, run2.run, noRestartHook)
	if err != nil {
		t.Fatal(err)
	}
	if rep := waitSweep(t, startStoreSweep(t.Context(), w2.sweeper, log)); len(rep.Renewed) != 0 || len(run2.got()) != 0 {
		t.Errorf("second start renewed %v and ran %v, want nothing", rep.Renewed, run2.got())
	}

	// A failed restart: one WARN naming the leaf and the error; the leaf stays.
	failDir := t.TempDir()
	failLog, failRec := logkittest.New()
	failing := &recordedRun{err: errors.New("unit openbao.service not found")}
	w3, err := wireSecretStore(t.Context(), failLog, "openbao", defaultSecretStoreAddr, ensureStoreCA(t, t.TempDir(), tlscatest.Deps()), failDir, failing.run, noRestartHook)
	if err != nil {
		t.Fatal(err)
	}
	rep3 := waitSweep(t, startStoreSweep(t.Context(), w3.sweeper, failLog))
	warns := failRec.AtLevel(slog.LevelWarn)
	if len(warns) != 1 || !strings.Contains(warns[0].Message, storeServerLeafName) || !strings.Contains(warns[0].Message, "unit openbao.service not found") {
		t.Errorf("WARN records = %s; want one naming %s and the error", failRec.Text(), storeServerLeafName)
	}
	if !slices.Equal(rep3.Failed, []string{storeServerLeafName}) || !slices.Equal(failing.got(), restartPair[:1]) {
		t.Errorf("report %+v, run %v; want the server reload failed after reset-failed", rep3, failing.got())
	}
	if _, err := os.Stat(filepath.Join(failDir, "tls", storeServerLeafName, "leaf.pem")); err != nil {
		t.Errorf("the fresh server leaf is gone after a failed restart: %v", err)
	}
}

func parseLeaf(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func verifyAgainst(c *x509.Certificate, caPEM []byte, eku x509.ExtKeyUsage) error {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	_, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{eku}})
	return err
}

// TC-758-21: the one leaf-sweep job renews both store leaves, beside the
// controlplane-CA leaves, once the clock is inside the renew window, and
// nothing on the next run.
func TestLeafSweepJob_RenewsTheStoreLeaves(t *testing.T) {
	clock := &testClock{now: time.Now()}
	deps := tlsca.Deps{Now: clock.Now, Rand: rand.Reader, Log: slog.New(slog.DiscardHandler)}
	cp := tlscatest.ControlplaneWith(t, t.TempDir(), deps)
	store := ensureStoreCA(t, t.TempDir(), deps)
	dataDir := t.TempDir()
	cpSweeper := tlsca.NewLeafSweeper(cp)
	if err := cpSweeper.Register(tlsca.LeafConsumer{
		Name: "api-https", Dir: filepath.Join(dataDir, "tls", "api"),
		Spec: func() (tlsca.LeafSpec, error) { return apiLeafSpec("cp", net.IPv4(192, 0, 2, 1)), nil },
	}); err != nil {
		t.Fatal(err)
	}
	run := &recordedRun{}
	w, err := wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), "openbao", defaultSecretStoreAddr, store, dataDir, run.run, noRestartHook)
	if err != nil {
		t.Fatal(err)
	}
	step := tlsca.LeafSweepWorkflow(tlsca.LeafSweepDeps{Sweepers: []*tlsca.LeafSweeper{cpSweeper, w.sweeper}}).Steps[0]
	sweep := func() tlsca.LeafSweepReport {
		raw, err := step.Do(&jobs.StepCtx{Ctx: t.Context(), Log: func(string, string) {}})
		if err != nil {
			t.Fatal(err)
		}
		var rep tlsca.LeafSweepReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	sweep() // mint everything
	before := serials(t, dataDir)
	calls := len(run.got())

	clock.advance(310 * 24 * time.Hour) // 55 days left of a 365-day leaf: inside the 60-day window
	rep := sweep()
	want := []string{"api-https", storeProvisionerLeafName, storeServerLeafName, storeClientLeafName}
	if !slices.Equal(rep.Renewed, want) || !slices.Equal(rep.Reloaded, []string{storeServerLeafName, storeClientLeafName}) || rep.Checked != 4 {
		t.Errorf("report = %+v, want renewed %v and both store reloads", rep, want)
	}
	after := serials(t, dataDir)
	for name, s := range before {
		if after[name].Cmp(s) == 0 {
			t.Errorf("%s keeps serial %v after renewal", name, s)
		}
	}
	if got := run.got()[calls:]; !slices.Equal(got, restartPair) {
		t.Errorf("renewal ran %v, want one restart pair", got)
	}

	calls = len(run.got())
	if rep := sweep(); len(rep.Renewed) != 0 || len(rep.Reloaded) != 0 || len(run.got()) != calls {
		t.Errorf("a sweep within the window renewed %v reloaded %v", rep.Renewed, rep.Reloaded)
	}
}

// TC-758-20 (F-758-08): the client leaf's reload closes the client's idle
// connections, so the call after a renewal makes a new handshake presenting
// the new leaf rather than reusing a kept-alive connection on the old one.
func TestStoreClientLeafReload_ClosesIdleConnections(t *testing.T) {
	clock := &testClock{now: time.Now()}
	deps := tlsca.Deps{Now: clock.Now, Rand: rand.Reader, Log: slog.New(slog.DiscardHandler)}
	store := ensureStoreCA(t, t.TempDir(), deps)
	certPEM, key, err := store.MintLeaf(storeServerLeafSpec())
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, key.Reveal())
	key.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(store.CertPEM)
	var mu sync.Mutex
	var seen []*big.Int // the client leaf's serial on each request's connection
	var handshakes int
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.TLS.PeerCertificates[0].SerialNumber)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"initialized":true,"sealed":false,"standby":false,"version":"2.7.1"}`)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		Time:         clock.Now, // the renewed leaf is dated by the test clock
	}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			mu.Lock()
			handshakes++
			mu.Unlock()
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	dataDir := t.TempDir()
	run := &recordedRun{}
	w, err := wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), "openbao", srv.URL, store, dataDir, run.run, noRestartHook)
	if err != nil || w.mode != storeModeOpenBao {
		t.Fatalf("wireSecretStore = %v, %v; want openbao", w.mode, err)
	}
	t.Cleanup(w.client.CloseIdleConnections)
	waitSweep(t, startStoreSweep(t.Context(), w.sweeper, slog.New(slog.DiscardHandler)))
	health := func() {
		t.Helper()
		if _, err := w.store.Health(t.Context()); err != nil {
			t.Fatalf("Health: %v", err)
		}
	}
	health()
	health() // a kept-alive connection serves the second call
	first := serials(t, dataDir)[storeClientLeafName]

	clock.advance(310 * 24 * time.Hour) // inside the 60-day renew window
	if rep := w.sweeper.Sweep(t.Context(), func(string, string) {}); !slices.Contains(rep.Reloaded, storeClientLeafName) {
		t.Fatalf("renewal report %+v, want %s reloaded", rep, storeClientLeafName)
	}
	renewed := serials(t, dataDir)[storeClientLeafName]
	health()

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || seen[0].Cmp(first) != 0 || seen[1].Cmp(first) != 0 {
		t.Fatalf("serials seen %v, want the first leaf %v on the first two calls", seen, first)
	}
	if handshakes != 2 || seen[2].Cmp(renewed) != 0 {
		t.Errorf("after the renewal: %d connections, the call presented %v; want a second connection presenting the renewed leaf %v", handshakes, seen[2], renewed)
	}
}

func serials(t *testing.T, dataDir string) map[string]*big.Int {
	t.Helper()
	out := map[string]*big.Int{}
	for _, name := range []string{storeServerLeafName, storeClientLeafName, storeProvisionerLeafName} {
		out[name] = parseLeaf(t, filepath.Join(dataDir, "tls", name, "leaf.pem")).SerialNumber
	}
	return out
}

// TC-758-23: startup refuses a configuration that selects the store but did
// not register its client leaf.
func TestRequiredLeafConsumers_StoreSelected(t *testing.T) {
	required := requiredLeafConsumers(false, false, true)
	if !slices.Equal(required, []string{storeServerLeafName, storeClientLeafName, storeProvisionerLeafName}) {
		t.Fatalf("required = %v", required)
	}
	err := verifyLeafConsumers([]string{storeServerLeafName, storeProvisionerLeafName}, required)
	if err == nil || !strings.Contains(err.Error(), storeClientLeafName) {
		t.Errorf("err = %v, want it to name %s", err, storeClientLeafName)
	}
	for _, n := range requiredLeafConsumers(true, true, false) {
		if strings.HasPrefix(n, "openbao-") {
			t.Errorf("store not selected, yet %s is required", n)
		}
	}
}

// TC-758-24: upgrading from the previous release. With the selector unset
// nothing changes; set to openbao, both leaves are minted from the existing
// store CA, which is not regenerated, with one restart pair.
func TestSecretStore_UpgradeFromThePreviousRelease(t *testing.T) {
	dataDir := t.TempDir()
	trustDir := filepath.Join(dataDir, "trust")
	cp := tlscatest.Controlplane(t, trustDir)
	store := ensureStoreCA(t, trustDir, tlscatest.Deps())
	if _, err := ensureAPILeaf(cp, dataDir, net.IPv4(192, 0, 2, 1)); err != nil {
		t.Fatal(err)
	}
	cpSweeper := tlsca.NewLeafSweeper(cp)
	if err := cpSweeper.Register(tlsca.LeafConsumer{
		Name: "api-https", Dir: filepath.Join(dataDir, "tls", "api"),
		Spec: func() (tlsca.LeafSpec, error) { return apiLeafSpec("cp", net.IPv4(192, 0, 2, 1)), nil },
	}); err != nil {
		t.Fatal(err)
	}
	report := func(sweepers ...*tlsca.LeafSweeper) tlsca.LeafSweepReport {
		raw, err := tlsca.LeafSweepWorkflow(tlsca.LeafSweepDeps{Sweepers: sweepers}).Steps[0].Do(
			&jobs.StepCtx{Ctx: t.Context(), Log: func(string, string) {}})
		if err != nil {
			t.Fatal(err)
		}
		var rep tlsca.LeafSweepReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	previous := report(cpSweeper)

	run := &recordedRun{}
	w, err := wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), "", defaultSecretStoreAddr, store, dataDir, run.run, noRestartHook)
	if err != nil || w.mode != storeModeOff {
		t.Fatalf("unset selector: %v, %v", w.mode, err)
	}
	if done := startStoreSweep(t.Context(), w.sweeper, slog.New(slog.DiscardHandler)); done != nil {
		t.Error("startStoreSweep started a sweep with the store off")
	}
	if got := report(cpSweeper, w.sweeper); got.Checked != previous.Checked || len(got.Renewed) != 0 || len(got.Failed) != 0 {
		t.Errorf("report with the store off = %+v, want the previous release's (%+v)", got, previous)
	}
	assertNoStoreLeafDirs(t, dataDir)
	if len(run.got()) != 0 {
		t.Errorf("run called %v with the store off", run.got())
	}

	caSerial := store.Cert.SerialNumber
	reloaded := ensureStoreCA(t, trustDir, tlscatest.Deps())
	if reloaded.Cert.SerialNumber.Cmp(caSerial) != 0 {
		t.Fatal("the store CA was regenerated on upgrade")
	}
	w, err = wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), "openbao", defaultSecretStoreAddr, reloaded, dataDir, run.run, noRestartHook)
	if err != nil {
		t.Fatal(err)
	}
	waitSweep(t, startStoreSweep(t.Context(), w.sweeper, slog.New(slog.DiscardHandler)))
	for _, name := range []string{storeServerLeafName, storeClientLeafName, storeProvisionerLeafName} {
		if err := verifyAgainst(parseLeaf(t, filepath.Join(dataDir, "tls", name, "leaf.pem")), store.CertPEM, map[string]x509.ExtKeyUsage{
			storeServerLeafName: x509.ExtKeyUsageServerAuth, storeClientLeafName: x509.ExtKeyUsageClientAuth,
			storeProvisionerLeafName: x509.ExtKeyUsageClientAuth,
		}[name]); err != nil {
			t.Errorf("%s does not chain to the existing store CA: %v", name, err)
		}
	}
	if !slices.Equal(run.got(), restartPair) {
		t.Errorf("run calls = %v, want exactly one restart pair", run.got())
	}
}

// TC-805-05: in openbao mode the api registers, mints and renews the store
// provisioner's leaf: clientAuth, CN rasputin-provisioner, in
// <data>/tls/openbao-provisioner, with no reload; it is on disk before the
// server leaf's reload restarts the store, whose start runs the provisioner;
// it is required only when the store is selected; and a configuration that
// does not register it is refused at startup.
func TestStoreProvisionerLeaf(t *testing.T) {
	dataDir := t.TempDir()
	ca := ensureStoreCA(t, t.TempDir(), tlscatest.Deps())
	leafPEM := filepath.Join(dataDir, "tls", storeProvisionerLeafName, "leaf.pem")
	// The run func records, with each systemctl call, whether the
	// provisioner's leaf was on disk when the call was made.
	var mu sync.Mutex
	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		_, err := os.Stat(leafPEM)
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, fmt.Sprintf("%s %s provisioner-leaf=%t", name, strings.Join(args, " "), err == nil))
		return nil, nil
	}
	w, err := wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), "openbao", defaultSecretStoreAddr, ca, dataDir, run, noRestartHook)
	if err != nil || w.mode != storeModeOpenBao {
		t.Fatalf("wireSecretStore = %v, %v; want openbao", w.mode, err)
	}
	if !slices.Contains(w.registeredNames(), storeProvisionerLeafName) {
		t.Fatalf("registered = %v, want %s among them", w.registeredNames(), storeProvisionerLeafName)
	}
	rep := waitSweep(t, startStoreSweep(t.Context(), w.sweeper, slog.New(slog.DiscardHandler)))
	if !slices.Contains(rep.Renewed, storeProvisionerLeafName) || slices.Contains(rep.Reloaded, storeProvisionerLeafName) {
		t.Errorf("report = %+v, want %s minted and never reloaded", rep, storeProvisionerLeafName)
	}
	want := []string{
		"systemctl reset-failed openbao.service provisioner-leaf=true",
		"systemctl restart openbao.service provisioner-leaf=true",
	}
	mu.Lock()
	got := slices.Clone(calls)
	mu.Unlock()
	if !slices.Equal(got, want) {
		t.Errorf("run calls = %v, want %v: the provisioner's leaf on disk before the store restarts", got, want)
	}
	leaf := parseLeaf(t, leafPEM)
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || leaf.Subject.CommonName != storeProvisionerCN ||
		len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
		t.Errorf("provisioner leaf EKU %v CN %q DNS %v IP %v; want clientAuth, %s, no SAN",
			leaf.ExtKeyUsage, leaf.Subject.CommonName, leaf.DNSNames, leaf.IPAddresses, storeProvisionerCN)
	}
	if storeProvisionerCN != "rasputin-provisioner" {
		t.Errorf("storeProvisionerCN = %q, want rasputin-provisioner, the role init.json creates", storeProvisionerCN)
	}
	if err := verifyAgainst(leaf, ca.CertPEM, x509.ExtKeyUsageClientAuth); err != nil {
		t.Errorf("the provisioner leaf does not chain to the store CA: %v", err)
	}
	for _, f := range []string{"leaf.pem", "leaf.key"} {
		if _, err := os.Stat(filepath.Join(dataDir, "tls", storeProvisionerLeafName, f)); err != nil {
			t.Errorf("%s is not in <data>/tls/%s: %v", f, storeProvisionerLeafName, err)
		}
	}

	if !slices.Contains(requiredLeafConsumers(false, false, true), storeProvisionerLeafName) {
		t.Error("the provisioner's leaf is not required with the store selected")
	}
	if slices.Contains(requiredLeafConsumers(true, true, false), storeProvisionerLeafName) {
		t.Error("the provisioner's leaf is required with the store off")
	}
	// The Register removed: the names the wiring would then carry.
	var without []string
	for _, n := range w.registeredNames() {
		if n != storeProvisionerLeafName {
			without = append(without, n)
		}
	}
	if err := verifyLeafConsumers(without, requiredLeafConsumers(false, false, true)); err == nil ||
		!strings.Contains(err.Error(), storeProvisionerLeafName) {
		t.Errorf("verifyLeafConsumers without the provisioner = %v, want an error naming %s", err, storeProvisionerLeafName)
	}
}

// TC-833-25: under openbao a nil after-restart hook is refused; the store
// restart runs the hook exactly once after its reset-failed/restart pair
// returns, whether the pair succeeded or restart failed, and still returns
// the restart's error.
func TestStoreRestartHook(t *testing.T) {
	ca := ensureStoreCA(t, t.TempDir(), tlscatest.Deps())
	if _, err := wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), storeModeOpenBao, defaultSecretStoreAddr,
		ca, t.TempDir(), (&recordedRun{}).run, nil); err == nil {
		t.Error("openbao with a nil after-restart hook was accepted")
	}
	for _, backend := range []string{"", storeModeMock} {
		if _, err := wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), backend, defaultSecretStoreAddr,
			ca, t.TempDir(), (&recordedRun{}).run, nil); err != nil {
			t.Errorf("backend %q with no hook: %v", backend, err)
		}
	}

	for _, tc := range []struct {
		name    string
		failOn  string
		wantErr bool
		want    []string
	}{
		{"pair succeeds", "", false, append(slices.Clone(restartPair), "hook")},
		{"restart fails", "restart", true, append(slices.Clone(restartPair), "hook")},
		{"reset-failed fails", "reset-failed", true, []string{restartPair[0], "hook"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var order []string
			note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }
			restartErr := errors.New("unit failed")
			run := func(_ context.Context, name string, args ...string) ([]byte, error) {
				note(strings.Join(append([]string{name}, args...), " "))
				if tc.failOn != "" && args[0] == tc.failOn {
					return nil, restartErr
				}
				return nil, nil
			}
			err := restartStoreUnit(run, func(context.Context) { note("hook") })(t.Context(), tlsca.LeafPaths{})
			if tc.wantErr != errors.Is(err, restartErr) || (!tc.wantErr && err != nil) {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !slices.Equal(order, tc.want) {
				t.Errorf("order = %v, want %v", order, tc.want)
			}
		})
	}
}
