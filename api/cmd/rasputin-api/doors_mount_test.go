package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// mountReady is the identity service's readiness, settable.
type mountReady struct {
	mu  sync.Mutex
	err error
}

func (r *mountReady) Ready(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *mountReady) set(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

// mountVersionSource reports one resource version.
type mountVersionSource struct{}

func (mountVersionSource) ResourceVersion(context.Context, string) (string, error) {
	return "ab12c", nil
}

// mountUpstream is the fake identity service: TLS under the identity CA for
// 127.0.0.1, requiring a client leaf under the same CA, recording each
// request's client CommonName.
type mountUpstream struct {
	srv *httptest.Server
	mu  sync.Mutex
	cns []string
}

func (u *mountUpstream) seen() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.cns)
}

// mountFixture is everything mountDoors takes, built for cluster ci.
type mountFixture struct {
	deps  doorMountDeps
	ca    *tlsca.CA
	up    *mountUpstream
	ready *mountReady
	rec   *logkittest.Recorder
}

func newMountFixture(t *testing.T) *mountFixture {
	t.Helper()
	dir := t.TempDir()
	ca, err := tlsca.Ensure(tlsca.IdentityConfig(), filepath.Join(dir, "trust"), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	theme := filepath.Join(dir, "theme")
	for name, body := range map[string]string{
		"resource-allowlist.json":            `{"keycloak":"26.8.2","login":["css/signin.css"],"common":[]}`,
		"login/resources/css/tokens.css":     ":root{}",
		"login/resources/css/components.css": ".rasp-btn{}",
		"login/resources/css/signin.css":     ".rasp-card{}",
		"login/resources/img/favicon.svg":    "<svg/>",
	} {
		p := filepath.Join(theme, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	up := &mountUpstream{}
	serverLeaf, err := ca.MintLeafToDisk(filepath.Join(dir, "upstream"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "identity", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(serverLeaf.CertPath, serverLeaf.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	up.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.mu.Lock()
		up.cns = append(up.cns, r.TLS.PeerCertificates[0].Subject.CommonName)
		up.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://sso-ci.local/realms/rasputin"}`))
	}))
	up.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	up.srv.StartTLS()
	t.Cleanup(up.srv.Close)
	upURL, err := url.Parse(up.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	table, err := doors.New("ci")
	if err != nil {
		t.Fatal(err)
	}
	th, err := policy.NewThrottle(policy.ThrottleDeps{Table: table, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()
	v, err := door.NewResourceVersion(mountVersionSource{}, log)
	if err != nil {
		t.Fatal(err)
	}
	v.Learn(context.Background())
	ready := &mountReady{}
	return &mountFixture{ca: ca, up: up, ready: ready, rec: rec, deps: doorMountDeps{
		mode: identityModeKeycloak, table: table, doorsOn: true, readiness: ready, throttle: th, version: v,
		identityCA: ca.CertPEM, dataDir: dir, upstream: upURL, themeDir: theme, consoleOrigin: "https://ci.local",
		installName: func(context.Context) (string, error) { return "CI", nil },
		dirty:       events.NewSignal(time.Now), now: time.Now, ids: func() string { return "corr" }, log: log,
		removed: removednames.Unavailable{Err: errors.New("no list in this fixture")},
		network: mountRegistration{}, waiting: mountRegistration{}, emails: mountRegistration{},
		resetDone: mountResetDone{},
	}}
}

// mountRegistration is registration's facts, count and email check; these
// cases never reach them.
type mountRegistration struct{}

func (mountRegistration) Facts(context.Context) (policy.NetworkFacts, error) {
	return policy.NetworkFacts{}, errors.New("unused")
}
func (mountRegistration) Full(context.Context) (bool, error) { return false, errors.New("unused") }
func (mountRegistration) EmailInUse(context.Context, string) (bool, error) {
	return false, errors.New("unused")
}

// mountResetDone is the app door's reset return; these cases never reach it.
type mountResetDone struct{}

func (mountResetDone) Finish(context.Context, url.Values) (string, string) { return "reset-failed", "" }

// discovery asks h for the realm's discovery document.
func discovery(h http.Handler) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/realms/rasputin/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TC-986-15: identity off or mock builds no doors, with one INFO naming the
// mode; under keycloak a missing or malformed allowlist or missing theme
// files is one configfault ERROR and no doors; a collaborator startEvents or
// the monitor wiring did not build is no doors; the full set builds both.
func TestMountDoors_BuildsBothOrNone(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{identityModeOff, identityModeMock} {
		f := newMountFixture(t)
		f.deps.mode = mode
		if h, a := mountDoors(ctx, f.deps); h != nil || a != nil {
			t.Errorf("mode %s built doors", mode)
		}
		got := f.rec.Matching(slog.LevelInfo, "sign-in doors not served: no identity service")
		if len(got) != 1 {
			t.Fatalf("mode %s: %d INFO records, want 1:\n%s", mode, len(got), f.rec.Text())
		}
		if v, _ := logkittest.Attr(got[0], "mode"); v != mode {
			t.Errorf("mode %s: the record's mode is %q", mode, v)
		}
	}

	f := newMountFixture(t)
	f.deps.doorsOn = false
	if h, a := mountDoors(ctx, f.deps); h != nil || a != nil || strings.Contains(f.rec.Text(), "sign-in doors") {
		t.Errorf("doors off: built %v %v, records %s", h, a, f.rec.Text())
	}

	for name, break_ := range map[string]func(*testing.T, *mountFixture){
		"a missing allowlist": func(t *testing.T, f *mountFixture) {
			if err := os.Remove(filepath.Join(f.deps.themeDir, "resource-allowlist.json")); err != nil {
				t.Fatal(err)
			}
		},
		"a malformed allowlist": func(t *testing.T, f *mountFixture) {
			if err := os.WriteFile(filepath.Join(f.deps.themeDir, "resource-allowlist.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"missing theme files": func(t *testing.T, f *mountFixture) {
			if err := os.RemoveAll(filepath.Join(f.deps.themeDir, "login")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newMountFixture(t)
			break_(t, f)
			if h, a := mountDoors(ctx, f.deps); h != nil || a != nil {
				t.Fatal("built doors")
			}
			got := f.rec.Matching(slog.LevelError, "sign-in doors not served")
			if len(got) != 1 {
				t.Fatalf("%d ERROR records, want 1:\n%s", len(got), f.rec.Text())
			}
			for k, want := range map[string]string{"configfault": "true", "component": "signin-door"} {
				if v, _ := logkittest.Attr(got[0], k); v != want {
					t.Errorf("%s = %q, want %q", k, v, want)
				}
			}
			if v, _ := logkittest.Attr(got[0], "err"); v == "" {
				t.Error("the record names no error")
			}
		})
	}

	for name, unset := range map[string]func(*doorMountDeps){
		"no throttle":  func(d *doorMountDeps) { d.throttle = nil },
		"no version":   func(d *doorMountDeps) { d.version = nil },
		"no readiness": func(d *doorMountDeps) { d.readiness = nil },
		// #990: registration's facts, count and email check.
		"no network": func(d *doorMountDeps) { d.network = nil },
		"no waiting": func(d *doorMountDeps) { d.waiting = nil },
		"no emails":  func(d *doorMountDeps) { d.emails = nil },
	} {
		f := newMountFixture(t)
		unset(&f.deps)
		if h, a := mountDoors(ctx, f.deps); h != nil || a != nil {
			t.Errorf("%s: built doors", name)
		}
	}

	f = newMountFixture(t)
	home, app := mountDoors(ctx, f.deps)
	if home == nil || app == nil || home.Kind() != door.Home || app.Kind() != door.App {
		t.Fatalf("the full set built %v %v:\n%s", home, app, f.rec.Text())
	}
}

// TC-986-15: the relay presents the door's client leaf, CN rasputin-door,
// read at each handshake: missing at mount, the relay's handshake fails and
// nothing reaches the identity service; written later, it is presented with
// no rebuild.
func TestMountDoors_RelayReadsTheDoorLeafAtHandshake(t *testing.T) {
	f := newMountFixture(t)
	home, _ := mountDoors(context.Background(), f.deps)
	if home == nil {
		t.Fatalf("no doors:\n%s", f.rec.Text())
	}
	if w := discovery(home); w.Code != http.StatusBadGateway {
		t.Errorf("with no door leaf: %d, want 502", w.Code)
	}
	if got := f.up.seen(); len(got) != 0 {
		t.Fatalf("with no door leaf the identity service saw %q", got)
	}
	if _, err := f.ca.MintLeafToDisk(filepath.Join(f.deps.dataDir, "tls", identityDoorClientLeafName), identityDoorClientLeafSpec()); err != nil {
		t.Fatal(err)
	}
	if w := discovery(home); w.Code != http.StatusOK {
		t.Fatalf("with the door leaf: %d %s", w.Code, w.Body.String())
	}
	if got := f.up.seen(); !slices.Equal(got, []string{identityDoorClientCN}) {
		t.Errorf("the identity service saw client %q, want %q", got, identityDoorClientCN)
	}
}

// TC-986-13 (composition): the dispatcher's door hosts are the certificate
// map's keys, both built from the one door table; with the doors off it has
// none.
func TestDoorSites_HostsAreTheCertificateKeys(t *testing.T) {
	table, err := doors.New("bench")
	if err != nil {
		t.Fatal(err)
	}
	log, _ := logkittest.New()
	ca := tlscatest.Controlplane(t, filepath.Join(t.TempDir(), "trust"))
	keys := slices.Sorted(func(yield func(string) bool) {
		for h := range newDoorLeaves(ca, t.TempDir(), table, appDoorWithholding{}).byHost() {
			if !yield(h) {
				return
			}
		}
	})
	cfg := sitesConfig(http.NotFoundHandler(), table, true, nil, nil, log)
	if got := slices.Sorted(slices.Values([]string{cfg.HomeHost, cfg.AppHost})); !slices.Equal(got, keys) {
		t.Errorf("dispatcher hosts %q, certificate keys %q", got, keys)
	}
	if cfg.Home != nil || cfg.App != nil {
		t.Error("a door not built is not a nil handler")
	}
	if _, err := doorSites(http.NotFoundHandler(), table, true, nil, nil, log); err != nil {
		t.Errorf("doorSites refused the wiring: %v", err)
	}
	if off := sitesConfig(http.NotFoundHandler(), table, false, nil, nil, log); off.HomeHost != "" || off.AppHost != "" {
		t.Errorf("doors off: hosts %q %q", off.HomeHost, off.AppHost)
	}
}

// TC-986-14 (main's half): one configfault ERROR per refused door origin,
// naming the setting and the origin, and the kept list.
func TestConsoleRPOrigins_LogsEachRefusedOrigin(t *testing.T) {
	table, err := doors.New("x")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RASPUTIN_CLUSTER_ID", "x")
	t.Setenv("RASPUTIN_RP_ORIGINS", "https://x.local,https://sso-x.local,https://signin.x.internal")
	log, rec := logkittest.New()
	got := consoleRPOrigins(context.Background(), log, table, true)
	if !slices.Equal(got, []string{"https://x.local"}) {
		t.Errorf("kept %q", got)
	}
	records := rec.Matching(slog.LevelError, "console origin refused: it is a sign-in door's")
	if len(records) != 2 {
		t.Fatalf("%d ERROR records, want 2:\n%s", len(records), rec.Text())
	}
	for i, want := range []string{"https://sso-x.local", "https://signin.x.internal"} {
		for k, v := range map[string]string{"configfault": "true", "setting": "RASPUTIN_RP_ORIGINS", "origin": want} {
			if a, _ := logkittest.Attr(records[i], k); a != v {
				t.Errorf("record %d: %s = %q, want %q", i, k, a, v)
			}
		}
	}
}

// fakeNameState is the sign-in name's state.
type fakeNameState struct{ state string }

func (f *fakeNameState) MetricState(time.Time) (string, bool) { return f.state, true }

// TC-986-16: each door reads 1 with every fact held, drops to 0 when any one
// fails, and reads 1 again when it clears. Each reading is a call; nothing
// waits on a timer.
func TestDoorMetrics_DoorUpFollowsEachFact(t *testing.T) {
	ctx := context.Background()
	f := newMountFixture(t)
	home, app := mountDoors(ctx, f.deps)
	if home == nil {
		t.Fatalf("no doors:\n%s", f.rec.Text())
	}
	loaded := func() *apiLeaf {
		l := &apiLeaf{}
		l.cert.Store(&tls.Certificate{})
		return l
	}
	name := &fakeNameState{state: "ok"}
	var (
		withheld  bool
		withErr   error
		online    = true
		onlineErr error
	)
	m := &doorMetrics{ready: f.ready, name: name, now: time.Now,
		withheld:  func() (string, bool, error) { return "", withheld, withErr },
		appOnline: func(context.Context) (bool, error) { return online, onlineErr },
	}
	m.setDoors(home, app, f.deps.throttle)
	m.setLeaves(&doorLeaves{home: doorLeaf{holder: loaded()}, app: doorLeaf{holder: loaded()}})
	m.bound.Store(true)
	want := func(fact, door string, up bool) {
		t.Helper()
		got, _ := m.DoorUp(ctx, door)
		if got != up {
			t.Errorf("%s: %s door up = %v, want %v", fact, door, got, up)
		}
	}
	for _, d := range []string{"home", "app"} {
		want("every fact held", d, true)
	}
	store := errors.New("store down")
	for _, c := range []struct {
		fact   string
		doors  []string
		break_ func()
		clear  func()
	}{
		{":443 not bound", []string{"home", "app"}, func() { m.bound.Store(false) }, func() { m.bound.Store(true) }},
		{"no home leaf", []string{"home"}, func() { m.homeLeaf.Store(&apiLeaf{}) }, func() { m.homeLeaf.Store(loaded()) }},
		{"no app leaf", []string{"app"}, func() { m.appLeaf.Store(&apiLeaf{}) }, func() { m.appLeaf.Store(loaded()) }},
		{"not ready", []string{"home", "app"}, func() { f.ready.set(errors.New("not ready")) }, func() { f.ready.set(nil) }},
		{"no handlers", []string{"home", "app"}, func() { m.setDoors(nil, nil, f.deps.throttle) }, func() { m.setDoors(home, app, f.deps.throttle) }},
		{"name in conflict", []string{"home"}, func() { name.state = "conflict" }, func() { name.state = "ok" }},
		{"app door withheld", []string{"app"}, func() { withheld = true }, func() { withheld = false }},
		{"apps store error", []string{"app"}, func() { withErr = store }, func() { withErr = nil }},
		{"not online", []string{"app"}, func() { online = false }, func() { online = true }},
		{"mesh store error", []string{"app"}, func() { onlineErr = store }, func() { onlineErr = nil }},
	} {
		c.break_()
		for _, d := range c.doors {
			want(c.fact, d, false)
		}
		c.clear()
		for _, d := range c.doors {
			want(c.fact+" cleared", d, true)
		}
	}
	if _, err := m.DoorUp(ctx, "elsewhere"); err == nil {
		t.Error("an unknown door read without an error")
	}
	if up, err := (&doorMetrics{}).DoorUp(ctx, "home"); up || err != nil {
		t.Errorf("nothing bound: %v %v, want down", up, err)
	}

	// The counts: the handler's requests and the throttle's waiting sources;
	// 0 while not built.
	discovery(home)
	if n, w := m.DoorCounts("home", time.Now()); n != 1 || w != 0 {
		t.Errorf("home counts = %d, %d; want 1, 0", n, w)
	}
	if n, w := m.DoorCounts("app", time.Now()); n != 0 || w != 0 {
		t.Errorf("app counts = %d, %d; want 0, 0", n, w)
	}
	m.setDoors(nil, nil, nil)
	if n, w := m.DoorCounts("home", time.Now()); n != 0 || w != 0 {
		t.Errorf("unbuilt counts = %d, %d", n, w)
	}
}

// doorMetricsFanout adds the door sink with door metrics, a VM sink and a
// self node id, and leaves inner unchanged without any of them.
func TestDoorMetricsFanout(t *testing.T) {
	log, _ := logkittest.New()
	inner := &countingSink{}
	if got := doorMetricsFanout(inner, &obs.VMSink{}, &doorMetrics{}, "cp", log); got == metrics.Sink(inner) {
		t.Error("with door metrics: the door sink was not added")
	}
	for name, got := range map[string]metrics.Sink{
		"no VM sink":      doorMetricsFanout(inner, nil, &doorMetrics{}, "cp", log),
		"no door metrics": doorMetricsFanout(inner, &obs.VMSink{}, nil, "cp", log),
		"no self node":    doorMetricsFanout(inner, &obs.VMSink{}, &doorMetrics{}, "", log),
	} {
		if got != metrics.Sink(inner) {
			t.Errorf("%s: the fan-out changed", name)
		}
	}
}

// mountDoors' inputs read nil outside keycloak, never a panic: no events
// holder (identity off or mock) and no identity CA.
func TestDoorMountInputs_NilOutsideKeycloak(t *testing.T) {
	var none *identityEvents
	if none.doorThrottle() != nil || none.doorVersion() != nil || identityCAPEM(nil) != nil {
		t.Error("a nil holder or CA read non-nil")
	}
	f := newMountFixture(t)
	ev := &identityEvents{}
	ev.throttle.Store(f.deps.throttle)
	ev.version.Store(f.deps.version)
	if ev.doorThrottle() != f.deps.throttle || ev.doorVersion() != f.deps.version {
		t.Error("the bound throttle or version was not read")
	}
}

// fixedNodes is an inventory's node list.
type fixedNodes struct {
	nodes []*proto.Node
	err   error
}

func (n fixedNodes) List(context.Context) ([]*proto.Node, error) { return n.nodes, n.err }

// TC-990-15 (wiring part): the door's network facts are the LAN watcher's
// home subnets, the mesh's TailnetPrefixes and the inventory's node
// addresses, read per request; an inventory error is an error.
func TestDoorNetwork_TC990_15(t *testing.T) {
	snap := lanaddr.Select([]lanaddr.Addr{{IP: net.ParseIP("192.0.2.5").To4(), Link: "end0", Index: 2, Bits: 24}})
	nodes := fixedNodes{nodes: []*proto.Node{{LANIP: "192.0.2.10"}, {LANIP: ""}}}
	src, err := doorNetwork(func() lanaddr.Snapshot { return snap }, nodes)
	if err != nil {
		t.Fatal(err)
	}
	f, err := src.Facts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.HomeSubnets, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) ||
		!slices.Equal(f.Tailnet, mesh.TailnetPrefixes()) || !slices.Equal(f.Nodes, []netip.Addr{netip.MustParseAddr("192.0.2.10")}) {
		t.Errorf("facts %+v", f)
	}
	bad, _ := doorNetwork(func() lanaddr.Snapshot { return snap }, fixedNodes{err: errors.New("inventory")})
	if _, err := bad.Facts(t.Context()); err == nil {
		t.Error("an inventory error was not an error")
	}
	if _, err := doorNetwork(nil, nodes); err == nil {
		t.Error("no LAN watcher was accepted")
	}
}
