package main

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	apipkg "github.com/geekdojo/rasputin-control-plane/api/internal/api"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breachcheck"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// The sign-in doors' mount (geekdojo/geekdojo-brain#986, Identity 4.4): main
// builds both door handlers here from the door table and the identity
// service's wiring, serves them with the console on :443 through
// apipkg.NewSites, keeps the console's origin allowlist free of the doors'
// origins, and publishes rasputin_signin_door_up and the doors' counts.

const (
	// identityTheme is the built login theme the api tarball installs beside
	// identityBaseline (scripts/build-release.sh): resource-allowlist.json and
	// login/resources, whose css/ and img/ the doors serve at /_signin/.
	identityTheme = "/usr/share/rasputin/identity/theme"
	// doorRequestLifetime bounds one door request's I/O: its body read and its
	// answer written. It decides no state; it only closes a connection that is
	// far outside normal bounds, so it cannot hold the sign-in history drain's
	// floor (apipkg.SitesConfig.RequestLifetime).
	doorRequestLifetime = 60 * time.Second
	// hibpRangeBase is the breached-password list's range endpoint: only the
	// first 5 hex characters of a new password's SHA-1 are sent to it
	// (geekdojo/geekdojo-brain#1145).
	hibpRangeBase = "https://api.pwnedpasswords.com/range"
	// breachCheckCallLifetime bounds the one range request a password post
	// makes. It decides no state: when it is reached, the post is relayed
	// without the warning (EXCEPTIONS.md EX-1).
	breachCheckCallLifetime = 5 * time.Second
)

// doorMountDeps are mountDoors' collaborators.
type doorMountDeps struct {
	mode    string
	table   doors.Table
	doorsOn bool
	// readiness is the identity service's readiness (identitystate.Monitor);
	// throttle and version are startEvents' (identityEvents).
	readiness policy.Readiness
	throttle  *policy.Throttle
	version   *door.ResourceVersion
	// bindings is the identity converger's client pause
	// (identityConverge.doorBindings, geekdojo/geekdojo-brain#987); nil
	// pauses every client outside the door table.
	bindings policy.Bindings
	// removed is the removed-name list registration checks (#991): the
	// accounts wiring's store, or Unavailable; nil outside keycloak.
	removed policy.RemovedNames
	// identityCA is the identity CA's certificate: the relay trusts it alone
	// and presents the door's client leaf from dataDir.
	identityCA    []byte
	dataDir       string
	upstream      *url.URL
	themeDir      string
	consoleOrigin string
	installName   func(ctx context.Context) (string, error)
	dirty         *events.Signal
	now           func() time.Time
	ids           func() string
	log           *slog.Logger
}

// mountDoors builds both door handlers, or none. With the doors off it builds
// none, silently: wireDoorTable has logged why. Under identity off or mock it
// logs one INFO. Under keycloak with a collaborator that startEvents or the
// monitor wiring did not build, it builds none; they have logged the ERROR.
// Any other failure (the theme's allowlist or files, the relay's TLS, the
// policy or the doors) is one configfault ERROR. With no doors, their sites
// answer the not-ready page and the console is unaffected.
func mountDoors(ctx context.Context, d doorMountDeps) (home, app *door.Handler) {
	if !d.doorsOn {
		return nil, nil
	}
	if d.mode != identityModeKeycloak {
		d.log.InfoContext(ctx, "sign-in doors not served: no identity service", "mode", d.mode)
		return nil, nil
	}
	if d.readiness == nil || d.throttle == nil || d.version == nil || d.dirty == nil || d.upstream == nil {
		return nil, nil
	}
	home, app, err := buildDoors(d)
	if err != nil {
		d.log.ErrorContext(ctx, "sign-in doors not served", "configfault", true, "component", "signin-door", "err", err.Error())
		return nil, nil
	}
	return home, app
}

// buildDoors is mountDoors' construction, each failure an error.
func buildDoors(d doorMountDeps) (home, app *door.Handler, err error) {
	raw, err := os.ReadFile(filepath.Join(d.themeDir, "resource-allowlist.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("the theme's allowlist: %w", err)
	}
	allow, err := door.ParseAllowlist(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("the theme's allowlist: %w", err)
	}
	// The door's own client leaf (CN rasputin-door, never the api's), read
	// from disk at each handshake, so one the sweep mints or renews later is
	// presented with no rebuild.
	leaf := tlsca.LeafPathsIn(filepath.Join(d.dataDir, "tls", identityDoorClientLeafName))
	tlsCfg, err := looptls.NewClientTLS(d.identityCA, leaf.CertPath, leaf.KeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("the relay's client TLS: %w", err)
	}
	pol, err := policy.New(doorPolicyDeps(d))
	if err != nil {
		return nil, nil, err
	}
	base, err := url.Parse(hibpRangeBase)
	if err != nil {
		return nil, nil, fmt.Errorf("the breach check's endpoint: %w", err)
	}
	breach, err := breachcheck.New(breachcheck.Config{Client: &http.Client{}, Base: base, CallTimeout: breachCheckCallLifetime})
	if err != nil {
		return nil, nil, err
	}
	return door.Build(d.table, door.Shared{
		ConsoleOrigin: d.consoleOrigin, Policy: pol, Throttle: d.throttle,
		Transport: idclient.NewTransport(tlsCfg), Upstream: d.upstream,
		Theme: allow, Assets: os.DirFS(filepath.Join(d.themeDir, "login", "resources")),
		Version: d.version, InstallName: d.installName, Dirty: d.dirty, IDs: d.ids, Breach: breach, Log: d.log,
	})
}

// doorPolicyDeps are the door policy's collaborators.
func doorPolicyDeps(d doorMountDeps) policy.Deps {
	return policy.Deps{
		Table: d.table, Readiness: d.readiness, Throttle: d.throttle,
		// The fail-closed stand-ins until Identity 7.3 (app clients), the
		// launcher (actions) and Identity 4.8 (registration) wire theirs.
		AppClients: policy.NoAppClients{}, Actions: policy.NoActionsIssued{},
		Network: policy.RegistrationClosed{}, Waiting: policy.RegistrationClosed{},
		Removed: d.removed, Now: d.now, Bindings: d.bindings,
	}
}

// doorThrottle is startEvents' throttle, nil outside keycloak or before
// start.
func (e *identityEvents) doorThrottle() *policy.Throttle {
	if e == nil {
		return nil
	}
	return e.throttle.Load()
}

// doorVersion is startEvents' resource version, nil outside keycloak or
// before start.
func (e *identityEvents) doorVersion() *door.ResourceVersion {
	if e == nil {
		return nil
	}
	return e.version.Load()
}

// identityCAPEM is the identity CA's certificate, nil with no identity CA.
func identityCAPEM(ca *tlsca.CA) []byte {
	if ca == nil {
		return nil
	}
	return ca.CertPEM
}

// sitesConfig is :443's site table: the console, and with the doors on the
// door table's two hosts, the same table sniCertificate's leaves are keyed by.
// A door not built is a nil handler, never a nil *door.Handler in an
// interface, so its site answers the not-ready page.
func sitesConfig(console http.Handler, table doors.Table, doorsOn bool, home, app *door.Handler, log *slog.Logger) apipkg.SitesConfig {
	cfg := apipkg.SitesConfig{Console: console, RequestLifetime: doorRequestLifetime, Now: time.Now, IDs: cryptorand.Text, Log: log}
	if doorsOn {
		cfg.HomeHost, cfg.AppHost = table.Home.Host, table.App.Host
	}
	if home != nil {
		cfg.Home = home
	}
	if app != nil {
		cfg.App = app
	}
	return cfg
}

// doorSites is :443's handler.
func doorSites(console http.Handler, table doors.Table, doorsOn bool, home, app *door.Handler, log *slog.Logger) (http.Handler, error) {
	return apipkg.NewSites(sitesConfig(console, table, doorsOn, home, app, log))
}

// consoleRPOrigins is the console's passkey origin allowlist, with any door
// origin refused: one configfault ERROR for each, and the rest of the list
// kept.
func consoleRPOrigins(ctx context.Context, logger *slog.Logger, table doors.Table, doorsOn bool) []string {
	var hosts []string
	if doorsOn {
		hosts = []string{table.Home.Host, table.App.Host}
	}
	origins, refused := rpOriginsFromEnv(hosts...)
	for _, o := range refused {
		logger.ErrorContext(ctx, "console origin refused: it is a sign-in door's",
			"configfault", true, "setting", "RASPUTIN_RP_ORIGINS", "origin", o)
	}
	return origins
}

// signinNameState is the home sign-in name's state (*signinname.Responder,
// whose MetricState is nil-safe).
type signinNameState interface {
	MetricState(now time.Time) (string, bool)
}

// doorMetrics are the doors' metric readings (signin-origin.md §14). It is
// built before the metrics fan-out, and the HTTPS block binds what exists
// only later: the handlers and the throttle (setDoors), each door's leaf
// holder (setLeaves) and the listener (bound). Each is read through an atomic,
// unset until bound, which reads down.
type doorMetrics struct {
	home, app         atomic.Pointer[door.Handler]
	throttle          atomic.Pointer[policy.Throttle]
	homeLeaf, appLeaf atomic.Pointer[apiLeaf]
	bound             atomic.Bool

	ready     policy.Readiness
	name      signinNameState
	withheld  func() (app string, withheld bool, err error)
	appOnline func(ctx context.Context) (bool, error)
	now       func() time.Time
}

// setDoors binds the built handlers and the throttle they share.
func (m *doorMetrics) setDoors(home, app *door.Handler, th *policy.Throttle) {
	m.home.Store(home)
	m.app.Store(app)
	m.throttle.Store(th)
}

// setLeaves binds each door's leaf holder.
func (m *doorMetrics) setLeaves(l *doorLeaves) {
	m.homeLeaf.Store(l.home.holder)
	m.appLeaf.Store(l.app.holder)
}

// errNoReadiness is the door-up reading with no identity readiness wired.
var errNoReadiness = errors.New("the identity service's readiness is not wired")

// DoorUp is door's §14 up fact: 1 only while :443 is bound, the door's leaf
// is loaded, its handler is built, the identity service is ready, and, at the
// home door, its name is published (ok); at the app door, it is not withheld
// and the control plane is online on the private network. Any unread fact is
// an error, which reads down.
func (m *doorMetrics) DoorUp(ctx context.Context, name string) (bool, error) {
	var leaf *apiLeaf
	var h *door.Handler
	switch name {
	case "home":
		leaf, h = m.homeLeaf.Load(), m.home.Load()
	case "app":
		leaf, h = m.appLeaf.Load(), m.app.Load()
	default:
		return false, fmt.Errorf("no door %q", name)
	}
	if !m.bound.Load() || leaf == nil || !leaf.has() || h == nil {
		return false, nil
	}
	if m.ready == nil {
		return false, errNoReadiness
	}
	if err := m.ready.Ready(ctx); err != nil {
		return false, err
	}
	if name == "home" {
		state, ok := m.name.MetricState(m.now())
		return ok && state == "ok", nil
	}
	_, withheld, err := m.withheld()
	if err != nil {
		return false, err
	}
	if withheld {
		return false, nil
	}
	online, err := m.appOnline(ctx)
	if err != nil {
		return false, err
	}
	return online, nil
}

// DoorCounts are door's request count and the sources waiting at it; both 0
// while the door is not built.
func (m *doorMetrics) DoorCounts(name string, now time.Time) (uint64, int) {
	h := m.home.Load()
	if name == "app" {
		h = m.app.Load()
	}
	th := m.throttle.Load()
	if h == nil || th == nil {
		return 0, 0
	}
	c := h.Counts(th, now)
	return c.Requests, c.ThrottledSources
}

// doorMetricsFanout adds the doors' metrics to the control plane's own
// sample. With no door metrics (the doors off), no self node id or no VM sink
// it returns inner unchanged.
func doorMetricsFanout(inner metrics.Sink, vm *obs.VMSink, m *doorMetrics, selfNodeID string, logger *slog.Logger) metrics.Sink {
	if m == nil || selfNodeID == "" || vm == nil {
		return inner
	}
	sink, err := obs.NewSigninDoorSink(inner, obs.SigninDoorDeps{
		Reading: m, Counts: m, Writer: vm, SelfNodeID: selfNodeID, Now: time.Now, Log: logger,
	})
	if err != nil {
		logger.Error("sign-in door metrics off", "component", "obs", "reason", "wiring", "err", err.Error())
		return inner
	}
	return sink
}
