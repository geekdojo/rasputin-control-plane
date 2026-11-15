package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/recoveradmin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The identity client's wiring (geekdojo/geekdojo-brain#978).

func noRunEnv(context.Context, []string, string, ...string) ([]byte, error) {
	return nil, errors.New("not run")
}

// attrsOf is a record's attributes as strings.
func attrsOf(r slog.Record) map[string]string {
	out := map[string]string{}
	r.Attrs(func(a slog.Attr) bool { out[a.Key] = a.Value.String(); return true })
	return out
}

// assertRefuses checks every client and session call refuses with kind.
func assertRefuses(t *testing.T, w identityWiring, kind error) {
	t.Helper()
	_, e1 := w.client.ClientCredentials(t.Context(), identityRealm, identityAdminClient, nil)
	_, e2 := w.client.Admin(t.Context(), secret.Value{}, http.MethodGet, "/admin/realms/rasputin", nil, nil)
	e3 := w.client.Ready(t.Context())
	_, e4 := w.session.Admin(t.Context(), http.MethodGet, "/admin/realms/rasputin", nil, nil)
	for i, err := range []error{e1, e2, e3, e4} {
		if !errors.Is(err, kind) {
			t.Errorf("call %d: err = %v, want %v", i, err, kind)
		}
	}
}

// assertKindUnknown checks the runner the wiring registered into does not
// know identity.recover_admin.
func assertKindUnknown(t *testing.T, w identityWiring) {
	t.Helper()
	r := jobs.NewRunner(openJobStore(t), nil)
	w.register(r)
	if _, err := r.Submit(t.Context(), recoveradmin.Kind, nil, "system"); err == nil || !strings.Contains(err.Error(), "unknown job kind") {
		t.Errorf("Submit(%s) = %v, want unknown job kind", recoveradmin.Kind, err)
	}
}

// TC-978-01, TC-978-02, TC-978-03: absent and empty are off at INFO; exactly
// mock is one WARN and ErrMock; any other value is off with one configfault
// naming the setting and the value. Outside keycloak the job is not
// registered.
func TestWireIdentity_Selection(t *testing.T) {
	ca := ensureIdentityCA(t, t.TempDir(), tlscatest.Deps())
	for _, tc := range []struct {
		backend string
		mode    string
		kind    error
		level   slog.Level
		fault   bool
	}{
		{"", identityModeOff, idclient.ErrDisabled, slog.LevelInfo, false},
		{"mock", identityModeMock, idclient.ErrMock, slog.LevelWarn, false},
		{"Keycloak", identityModeOff, idclient.ErrDisabled, slog.LevelError, true},
		{"KEYCLOAK", identityModeOff, idclient.ErrDisabled, slog.LevelError, true},
		{" keycloak", identityModeOff, idclient.ErrDisabled, slog.LevelError, true},
		{"keycloak ", identityModeOff, idclient.ErrDisabled, slog.LevelError, true},
		{"openbao", identityModeOff, idclient.ErrDisabled, slog.LevelError, true},
		{"keycloakx", identityModeOff, idclient.ErrDisabled, slog.LevelError, true},
	} {
		t.Run("backend="+tc.backend, func(t *testing.T) {
			log, rec := logkittest.New()
			w, err := wireIdentity(t.Context(), log, tc.backend, defaultIdentityAddr, defaultIdentityMgmtAddr, ca, t.TempDir(), (&scriptedRun{}).run, noRunEnv)
			if err != nil {
				t.Fatalf("wireIdentity: %v", err)
			}
			if w.mode != tc.mode || w.recoverer != nil || w.reload != nil {
				t.Errorf("mode %q recoverer %v reload set %v, want %q and neither", w.mode, w.recoverer, w.reload != nil, tc.mode)
			}
			recs := rec.Records()
			if len(recs) != 1 || recs[0].Level != tc.level {
				t.Fatalf("records:\n%s\nwant exactly one at %v", rec.Text(), tc.level)
			}
			a := attrsOf(recs[0])
			if a["setting"] != "RASPUTIN_IDENTITY_BACKEND" {
				t.Errorf("the record names setting %q", a["setting"])
			}
			if tc.fault && (a["configfault"] != "true" || a["value"] != tc.backend || a["reason"] == "") {
				t.Errorf("configfault record attrs = %v", a)
			}
			assertRefuses(t, w, tc.kind)
			assertKindUnknown(t, w)
		})
	}
}

// TC-978-04: under keycloak, every malformed address turns identity off with
// one configfault naming that setting, and no client is built.
func TestWireIdentity_RefusedAddresses(t *testing.T) {
	ca := ensureIdentityCA(t, t.TempDir(), tlscatest.Deps())
	malformed := []string{"http://127.0.0.1:8543", "https://localhost:8543", "https://127.0.0.1", "https://127.0.0.1:0",
		"https://127.0.0.1:65536", "https://10.0.0.5:8543", "https://127.0.0.1:8543/path", "https://127.0.0.1:8543?q=1",
		"https://user@127.0.0.1:8543"}
	for _, setting := range []string{"RASPUTIN_IDENTITY_ADDR", "RASPUTIN_IDENTITY_MGMT_ADDR"} {
		for _, v := range malformed {
			t.Run(setting+"="+v, func(t *testing.T) {
				addr, mgmt := defaultIdentityAddr, defaultIdentityMgmtAddr
				if setting == "RASPUTIN_IDENTITY_ADDR" {
					addr = v
				} else {
					mgmt = v
				}
				log, rec := logkittest.New()
				w, err := wireIdentity(t.Context(), log, "keycloak", addr, mgmt, ca, t.TempDir(), (&scriptedRun{}).run, noRunEnv)
				if err != nil {
					t.Fatal(err)
				}
				if _, isClient := w.client.(*idclient.Client); w.mode != identityModeOff || isClient || w.recoverer != nil {
					t.Errorf("mode %q, a real client %v, recoverer %v; want off and none", w.mode, isClient, w.recoverer)
				}
				errs := rec.AtLevel(slog.LevelError)
				if len(errs) != 1 || attrsOf(errs[0])["setting"] != setting || attrsOf(errs[0])["configfault"] != "true" {
					t.Errorf("records:\n%s\nwant one configfault naming %s", rec.Text(), setting)
				}
				assertRefuses(t, w, idclient.ErrDisabled)
			})
		}
	}
}

// identityServer is a mutual-TLS server on a leaf of ca that records the
// client leaf's serial and answers a token.
type identityServer struct {
	*httptest.Server
	n      atomic.Int64
	serial atomic.Pointer[string]
}

func newIdentityServer(t *testing.T, ca *tlsca.CA) *identityServer {
	t.Helper()
	sp, err := ca.MintLeafToDisk(t.TempDir(), identityServerLeafSpec())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(sp.CertPath, sp.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &identityServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.n.Add(1)
		serial := r.TLS.PeerCertificates[0].SerialNumber.String()
		s.serial.Store(&serial)
		_, _ = io.WriteString(w, `{"access_token":"tok"}`)
	}))
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.Config.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.Server = srv
	return s
}

// TC-978-05: an identity CA that did not load is off with one configfault;
// with a CA but no client leaf on disk, every call is ErrUnreachable and the
// server sees no request.
func TestWireIdentity_UnreadableInputsFailClosed(t *testing.T) {
	log, rec := logkittest.New()
	w, err := wireIdentity(t.Context(), log, "keycloak", defaultIdentityAddr, defaultIdentityMgmtAddr, nil, t.TempDir(), (&scriptedRun{}).run, noRunEnv)
	if err != nil {
		t.Fatal(err)
	}
	errs := rec.AtLevel(slog.LevelError)
	if w.mode != identityModeOff || len(errs) != 1 || attrsOf(errs[0])["configfault"] != "true" ||
		!strings.Contains(attrsOf(errs[0])["reason"], "identity CA") {
		t.Errorf("no CA: mode %q, records:\n%s", w.mode, rec.Text())
	}
	assertRefuses(t, w, idclient.ErrDisabled)

	ca := ensureIdentityCA(t, t.TempDir(), tlscatest.Deps())
	srv := newIdentityServer(t, ca)
	w, err = wireIdentity(t.Context(), slog.New(slog.DiscardHandler), "keycloak", srv.URL, srv.URL, ca, t.TempDir(), (&scriptedRun{}).run, noRunEnv)
	if err != nil || w.mode != identityModeKeycloak {
		t.Fatalf("wireIdentity = %v, %v", w.mode, err)
	}
	_, e1 := w.client.ClientCredentials(t.Context(), identityRealm, identityAdminClient, nil)
	e2 := w.client.Ready(t.Context())
	_, e3 := w.session.Admin(t.Context(), http.MethodGet, "/admin/realms/rasputin", nil, nil)
	for i, err := range []error{e1, e2, e3} {
		if !errors.Is(err, idclient.ErrUnreachable) {
			t.Errorf("call %d with no leaf: %v, want ErrUnreachable", i, err)
		}
	}
	if srv.n.Load() != 0 {
		t.Errorf("the server saw %d requests, want 0", srv.n.Load())
	}
}

// TC-978-06: keycloak wiring registers identity.recover_admin as a system
// job, the api client leaf's reload drops idle connections, and after the
// leaf on disk is replaced and the reload runs the next call presents the
// new leaf. main logs the mode.
func TestWireIdentity_KeycloakAndLeafReload(t *testing.T) {
	ca := ensureIdentityCA(t, t.TempDir(), tlscatest.Deps())
	srv := newIdentityServer(t, ca)
	dataDir := t.TempDir()
	log, rec := logkittest.New()
	w, err := wireIdentity(t.Context(), log, "keycloak", srv.URL, srv.URL, ca, dataDir, (&scriptedRun{}).run, noRunEnv)
	if err != nil || w.mode != identityModeKeycloak || w.recoverer == nil || w.reload == nil {
		t.Fatalf("wireIdentity = %+v, %v", w, err)
	}
	if n := len(rec.Records()); n != 0 {
		t.Errorf("keycloak wiring wrote %d records:\n%s", n, rec.Text())
	}
	r := jobs.NewRunner(openJobStore(t), nil)
	w.register(r)
	if _, err := r.SubmitOperatorSpec(t.Context(), recoveradmin.Kind, nil, "operator"); !errors.Is(err, jobs.ErrSystemKind) {
		t.Errorf("an operator submit of %s = %v, want ErrSystemKind (registered as a system job)", recoveradmin.Kind, err)
	}

	s, err := wireIdentityLeaves(ca, dataDir, (&scriptedRun{}).run, w.reload)
	if err != nil {
		t.Fatal(err)
	}
	identitySweep(t, s, slog.New(slog.DiscardHandler))
	call := func() string {
		t.Helper()
		v, err := w.client.ClientCredentials(t.Context(), identityRealm, identityAdminClient, nil)
		if err != nil {
			t.Fatalf("ClientCredentials: %v", err)
		}
		v.Destroy()
		return *srv.serial.Load()
	}
	first := call()
	leaf := tlsca.LeafPathsIn(identityDir(dataDir, identityAPIClientLeafName))
	fresh, err := ca.MintLeafToDisk(t.TempDir(), identityAPIClientLeafSpec())
	if err != nil {
		t.Fatal(err)
	}
	for from, to := range map[string]string{fresh.CertPath: leaf.CertPath, fresh.KeyPath: leaf.KeyPath} {
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.reload(t.Context(), leaf); err != nil {
		t.Fatal(err)
	}
	if next := call(); next == first {
		t.Errorf("after the reload the call presented the old leaf %s", first)
	}
}

// TC-978-07: a data directory as Identity 3.1 leaves it, with the identity CA
// and its leaves and no RASPUTIN_IDENTITY_* setting: identity is off at INFO,
// the leaf sweep registers every identity leaf without error, identity
// wiring writes no WARN or ERROR, and an operator's job of an existing kind
// is still created.
func TestWireIdentity_UpgradeFromThePreviousRelease(t *testing.T) {
	trustDir, dataDir := t.TempDir(), t.TempDir()
	ca := ensureIdentityCA(t, trustDir, tlscatest.Deps())
	prev, err := wireIdentityLeaves(ca, dataDir, (&scriptedRun{}).run, nil)
	if err != nil {
		t.Fatal(err)
	}
	identitySweep(t, prev, slog.New(slog.DiscardHandler))
	for _, k := range []string{"RASPUTIN_IDENTITY_BACKEND", "RASPUTIN_IDENTITY_ADDR", "RASPUTIN_IDENTITY_MGMT_ADDR"} {
		setOrUnset(t, k, true, "")
	}

	log, rec := logkittest.New()
	w, err := wireIdentity(t.Context(), log, identityBackendFromEnv(), identityAddrFromEnv(), identityMgmtAddrFromEnv(),
		ca, dataDir, (&scriptedRun{}).run, noRunEnv)
	if err != nil || w.mode != identityModeOff {
		t.Fatalf("wireIdentity = %q, %v; want off", w.mode, err)
	}
	if len(rec.AtLevel(slog.LevelWarn)) != 0 || len(rec.AtLevel(slog.LevelError)) != 0 || len(rec.Matching(slog.LevelInfo, "not configured")) != 1 {
		t.Errorf("records:\n%s\nwant one INFO and nothing at WARN or ERROR", rec.Text())
	}
	s, err := wireIdentityLeaves(ca, dataDir, (&scriptedRun{}).run, w.reload)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.RegisteredNames(), slices.Sorted(slices.Values(identityLeafOrder)); !slices.Equal(got, want) {
		t.Errorf("registered %v, want %v", got, want)
	}
	rep := identitySweep(t, s, log)
	if len(rep.Failed) != 0 || len(rec.AtLevel(slog.LevelWarn)) != 0 {
		t.Errorf("sweep after the upgrade failed %v:\n%s", rep.Failed, rec.Text())
	}

	r := jobs.NewRunner(openJobStore(t), nil)
	r.Register(jobs.Workflow{Kind: "diag.ping", Steps: []jobs.WorkflowStep{{Name: "noop",
		Do: func(*jobs.StepCtx) (json.RawMessage, error) { return nil, nil }}}})
	w.register(r)
	if j, err := r.SubmitOperatorSpec(t.Context(), "diag.ping", nil, "operator"); err != nil || j == nil {
		t.Errorf("an operator job of an existing kind = %v, %v; want it created", j, err)
	}
	r.Wait()
}

// The production unit control: systemctl stop, start and is-active on
// keycloak.service, and is-active's printed state read before its exit code.
func TestIdentityUnits(t *testing.T) {
	run := &scriptedRun{}
	u := identityUnits{run: run.run}
	_ = u.Stop(t.Context())
	_ = u.Start(t.Context())
	if got := run.got(); !slices.Equal(got, []string{"systemctl stop keycloak.service", "systemctl start keycloak.service"}) {
		t.Errorf("commands = %v", got)
	}
	exit3 := errors.New("exit status 3")
	for _, tc := range []struct {
		out    string
		err    error
		active bool
		fails  bool
	}{
		{"active\n", nil, true, false},
		{"activating\n", exit3, true, false},
		{"inactive\n", exit3, false, false},
		{"failed\n", exit3, false, false},
		{"", errors.New("systemctl: not found"), false, true},
		{"weird\n", nil, false, true},
	} {
		u := identityUnits{run: func(context.Context, string, ...string) ([]byte, error) { return []byte(tc.out), tc.err }}
		active, err := u.Active(t.Context())
		if active != tc.active || (err != nil) != tc.fails {
			t.Errorf("is-active %q/%v = %v, %v", tc.out, tc.err, active, err)
		}
	}
}

// The production recovery command: the installed kc.sh with the config file
// first, the unit's JVM environment and PATH, plus the secret's variable, and
// nothing inherited (F-978-03).
func TestIdentityBootstrap_CommandAndEnvironment(t *testing.T) {
	var gotEnv []string
	var gotName string
	var gotArgs []string
	boot := identityBootstrap(func(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
		gotEnv, gotName, gotArgs = slices.Clone(env), name, args
		return nil, nil
	})
	if err := boot(t.Context(), []string{"bootstrap-admin", "service"}, []string{"RASPUTIN_RECOVER_CLIENT_SECRET=s3cr3t"}); err != nil {
		t.Fatal(err)
	}
	if gotName != "/usr/lib/keycloak/bin/kc.sh" || !slices.Equal(gotArgs, []string{"--config-file=/etc/rasputin/identity/keycloak.conf", "bootstrap-admin", "service"}) {
		t.Errorf("command = %s %v", gotName, gotArgs)
	}
	names := map[string]bool{}
	for _, e := range gotEnv {
		k, _, _ := strings.Cut(e, "=")
		names[k] = true
	}
	for _, k := range []string{"PATH", "JAVA_HOME", "MALLOC_ARENA_MAX", "JAVA_OPTS_KC_HEAP", "JAVA_OPTS_APPEND", "RASPUTIN_RECOVER_CLIENT_SECRET"} {
		if !names[k] {
			t.Errorf("env lacks %s", k)
		}
	}
	if len(gotEnv) != 6 || !slices.Contains(gotEnv, "PATH=/usr/bin:/bin") {
		t.Errorf("env = %d entries, want exactly the six", len(gotEnv))
	}
}
