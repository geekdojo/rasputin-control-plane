package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nameserver"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The sign-in doors' wiring (geekdojo/geekdojo-brain#983), over the real
// pieces main wires: a controlplane CA, the sqlite apps and mesh stores, a
// nameserver bound on loopback, real TLS handshakes and a real bus.

const (
	rigCID     = "bench"
	rigCPNode  = "cp1"
	rigCPTail  = "100.64.0.5"
	rigAppTail = "100.64.0.2"
)

var rigLAN = net.ParseIP("192.168.1.10")

// recordingSupervisor records each tailnet projection the mesh writes.
type recordingSupervisor struct {
	mesh.NoopSupervisor
	got   map[string]string
	calls int
}

func (r *recordingSupervisor) ReconcileAppRecords(m map[string]string) error {
	r.got, r.calls = m, r.calls+1
	return nil
}

// failingApps is an apps store whose List always errors.
type failingApps struct{}

func (failingApps) List(context.Context) ([]*apps.App, error) {
	return nil, errors.New("database is locked")
}

type doorRig struct {
	t       *testing.T
	ctx     context.Context
	dir     string
	ca      *tlsca.CA
	store   *apps.Store
	rec     *logkittest.Recorder
	log     *slog.Logger
	table   doors.Table
	appDoor appDoorWithholding
	api     *apiLeaf
	leaves  doorLeaves
	sweeper *tlsca.LeafSweeper
	sup     *recordingSupervisor
	mesh    *mesh.Service
	nsAddr  string
}

// newDoorRig builds everything main builds for the doors, except loading the
// door leaves (start does that). lister is the apps store the withheld
// predicate reads; nil means the rig's real store. deps, when set, are the
// CA's collaborators (a clock gate).
func newDoorRig(t *testing.T, lister appLister, deps *tlsca.Deps) *doorRig {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	r := &doorRig{t: t, ctx: ctx, dir: dir}
	r.log, r.rec = logkittest.New()
	var err error
	r.store, err = apps.OpenStore(ctx, filepath.Join(dir, "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.store.Close() })
	if lister == nil {
		lister = r.store
	}
	if deps != nil {
		r.ca = tlscatest.ControlplaneWith(t, filepath.Join(dir, "trust"), *deps)
	} else {
		r.ca = tlscatest.Controlplane(t, filepath.Join(dir, "trust"))
	}
	r.table, err = doors.New(rigCID)
	if err != nil {
		t.Fatal(err)
	}
	r.appDoor = appDoorWithholding{ctx: ctx, apps: lister, log: r.log}
	r.api = &apiLeaf{mint: func(ip net.IP) (tlsca.LeafPaths, error) {
		return r.ca.MintLeafToDisk(filepath.Join(dir, "tls", "api"), apiLeafSpec(rigCID, ip))
	}}
	r.leaves = newDoorLeaves(r.ca, dir, r.table, r.appDoor)
	r.sweeper = tlsca.NewLeafSweeper(r.ca)
	if err := r.leaves.register(r.sweeper); err != nil {
		t.Fatal(err)
	}

	// The mesh projection, as main configures it.
	mstore, err := mesh.OpenStore(ctx, filepath.Join(dir, "mesh.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mstore.Close() })
	for _, d := range []*mesh.Device{
		{HSID: "h-cp", RasputinNodeID: rigCPNode, TailnetIP: rigCPTail, Tags: []string{}, AdvertisedRoutes: []string{}},
		{HSID: "h-a", RasputinNodeID: "node-a", TailnetIP: rigAppTail, Tags: []string{}, AdvertisedRoutes: []string{}},
	} {
		if err := mstore.UpsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	r.sup = &recordingSupervisor{}
	r.mesh = mesh.NewService(mesh.Config{
		ClusterID: rigCID, AppDoorHost: r.table.App.Host, SelfNodeID: rigCPNode,
		AppDoorWithheld: r.appDoor.withheld, Log: r.log,
	}, mstore, mesh.NewUnavailableClient("test"), r.sup)
	r.mesh.SetAppLister(func() []mesh.AppDNS {
		list, err := lister.List(ctx)
		if err != nil {
			return nil
		}
		out := make([]mesh.AppDNS, 0, len(list))
		for _, a := range list {
			out = append(out, mesh.AppDNS{Name: a.Name, TargetNode: a.TargetNode})
		}
		return out
	})

	// The nameserver, as main wires it with doors on.
	zone := proto.BaseDomain(rigCID)
	lan := func() net.IP { return rigLAN }
	resp := nameserver.NewResponder(zone,
		controlPlaneSources(zone, rigCID+".local", r.table, true, lan, r.appDoor.withheld)...)
	srv := nameserver.NewServer(func() net.IP { return net.IPv4(127, 0, 0, 1) }, 0, resp)
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	if err := srv.Start(sctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	r.nsAddr = srv.UDPAddr()
	return r
}

// addApp writes an app row straight to the store, as a pre-upgrade row is.
func (r *doorRig) addApp(id, name string) {
	r.t.Helper()
	now := time.Now().UTC()
	if err := r.store.Create(r.ctx, &apps.App{ID: id, Name: name, ComposeYAML: "services: {}", TargetNode: "node-a",
		LastStatus: proto.AppStatusUnknown, CreatedAt: now, UpdatedAt: now}); err != nil {
		r.t.Fatal(err)
	}
}

// start is what main does at start with doors and HTTPS on: the table's log,
// the start-up withheld WARN, the api leaf, and each door leaf loaded once.
func (r *doorRig) start() {
	r.t.Helper()
	if !wireDoorTable(r.ctx, r.log, r.table, nil) {
		r.t.Fatal("doors off")
	}
	warnIfWithheld(r.ctx, r.log, r.appDoor)
	if err := r.api.load(rigLAN); err != nil {
		r.t.Fatal(err)
	}
	r.leaves.load(r.ctx, r.log)
}

func (r *doorRig) sni() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return sniCertificate(r.api, r.leaves.byHost())
}

// query asks the rig's nameserver for name's A record over UDP.
func (r *doorRig) query(name string) *dns.Msg {
	r.t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m, _, err := (&dns.Client{Net: "udp", Timeout: 3 * time.Second}).Exchange(req, r.nsAddr)
	if err != nil {
		r.t.Fatal(err)
	}
	return m
}

func (r *doorRig) leafFile(door string) string {
	return filepath.Join(r.dir, "tls", door, "leaf.pem")
}

// doorHandshake runs a real TLS handshake over net.Pipe against a server whose
// certificate selection is getCert, with SNI sni ("" sends none). It returns
// the leaf the client received, the client's error and the server's.
func doorHandshake(t *testing.T, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), sni string) (*x509.Certificate, error, error) {
	t.Helper()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	srvErr := make(chan error, 1)
	go func() {
		// The raw pipe end is closed, not the tls.Conn: a close_notify over
		// an unread net.Pipe waits out tls's 5-second close deadline.
		err := tls.Server(sc, &tls.Config{GetCertificate: getCert, MinVersion: tls.VersionTLS12}).Handshake()
		_ = sc.Close()
		srvErr <- err
	}()
	c := tls.Client(cc, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec // the test reads the leaf it was served
	cerr := c.Handshake()
	var leaf *x509.Certificate
	if cerr == nil {
		if pcs := c.ConnectionState().PeerCertificates; len(pcs) > 0 {
			leaf = pcs[0]
		}
	} else if len(c.ConnectionState().PeerCertificates) != 0 {
		t.Errorf("SNI %q: a refused handshake carried a certificate", sni)
	}
	_ = cc.Close()
	return leaf, cerr, <-srvErr
}

func isLeafFor(c *x509.Certificate, name string) bool {
	return c != nil && c.VerifyHostname(name) == nil
}

// TC-983-01 (cmd half): the door leaf, the nameserver record key and the
// projection's record key for the app door are all proto.SignInFQDN, and the
// home door's leaf is proto.SignInHomeFQDN.
func TestDoorWiring_NamesFromOneConstructor(t *testing.T) {
	r := newDoorRig(t, nil, nil)
	r.start()
	app, home := proto.SignInFQDN(rigCID), proto.SignInHomeFQDN(rigCID)
	for _, c := range []struct {
		door doorLeaf
		want string
	}{{r.leaves.app, app}, {r.leaves.home, home}} {
		door, want := c.door, c.want
		spec, err := door.consumer.Spec()
		if err != nil || spec.CommonName != want || !slices.Equal(spec.DNSNames, []string{want}) {
			t.Errorf("%s spec = %+v, %v; want %s", door.door.Name, spec, err, want)
		}
	}
	src := nameserver.NewDoorSource(r.table.App.Host, func() net.IP { return rigLAN }, r.appDoor.withheld)
	if _, ok := src.Records()[app+"."]; !ok {
		t.Errorf("DoorSource keys = %v, want %s.", src.Records(), app)
	}
	if err := r.mesh.ReconcileAppDNS(r.ctx); err != nil {
		t.Fatal(err)
	}
	if r.sup.got[app] != rigCPTail {
		t.Errorf("projection = %v, want %s → %s", r.sup.got, app, rigCPTail)
	}
}

// TC-983-02: with both door holders empty, a handshake for either door name,
// including a case-and-dot variant, is refused, the client receives no
// certificate, and the server's error names the door. Loaded, each door gets
// its own leaf, and every other SNI, and none, gets the api leaf.
func TestSNICertificate_DoorNamesAreNeverServedTheAPILeaf(t *testing.T) {
	r := newDoorRig(t, nil, nil)
	if err := r.api.load(rigLAN); err != nil {
		t.Fatal(err)
	}
	for sni, door := range map[string]string{
		"signin.bench.internal": "signin-app",
		"SIGNIN.Bench.Internal": "signin-app",
		"sso-bench.local":       "signin-home",
	} {
		leaf, cerr, serr := doorHandshake(t, r.sni(), sni)
		if cerr == nil || leaf != nil {
			t.Errorf("SNI %s with no door leaf: handshake succeeded with %v", sni, leaf)
		}
		if serr == nil || !strings.Contains(serr.Error(), door) {
			t.Errorf("SNI %s: server error %v does not name %s", sni, serr, door)
		}
	}
	// A trailing dot never reaches a Go server from a Go client, so the
	// selection is asked directly.
	if _, err := r.sni()(&tls.ClientHelloInfo{ServerName: "SIGNIN.Bench.Internal."}); err == nil || !strings.Contains(err.Error(), "signin-app") {
		t.Errorf("trailing-dot SNI: %v, want the app door's refusal", err)
	}

	r.leaves.load(r.ctx, r.log)
	for sni, want := range map[string]string{
		"signin.bench.internal": "signin.bench.internal",
		"sso-bench.local":       "sso-bench.local",
	} {
		leaf, cerr, _ := doorHandshake(t, r.sni(), sni)
		if cerr != nil || leaf == nil || !slices.Equal(leaf.DNSNames, []string{want}) {
			t.Errorf("SNI %s: leaf %v err %v, want the one-name leaf %s", sni, leaf, cerr, want)
		}
	}
	for _, sni := range []string{"bench.local", "unknown.example", ""} {
		leaf, cerr, _ := doorHandshake(t, r.sni(), sni)
		if cerr != nil || leaf == nil || !slices.Contains(leaf.DNSNames, "rasputin.local") {
			t.Errorf("SNI %q: leaf %v err %v, want the api leaf", sni, leaf, cerr)
		}
	}
}

// TC-983-05: each door leaf is one DNS SAN, no IP SAN, serverAuth only,
// chains to the controlplane CA, has ExactDNSNames on its spec, and shares no
// name with the api leaf.
func TestDoorLeaves_OneNameNoIPNoOverlapWithTheAPILeaf(t *testing.T) {
	r := newDoorRig(t, nil, nil)
	r.start()
	roots := x509.NewCertPool()
	roots.AddCert(r.ca.Cert)
	apiNames := apiLeafSpec(rigCID, rigLAN).DNSNames
	for _, door := range r.leaves.all() {
		spec, _ := door.consumer.Spec()
		if !spec.ExactDNSNames {
			t.Errorf("%s: ExactDNSNames off", door.door.Name)
		}
		c, err := door.holder.getCertificate(nil)
		if err != nil {
			t.Fatalf("%s: %v", door.door.Name, err)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(leaf.DNSNames, []string{door.door.Host}) || len(leaf.IPAddresses) != 0 {
			t.Errorf("%s: DNS %v IP %v", door.door.Name, leaf.DNSNames, leaf.IPAddresses)
		}
		if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
			t.Errorf("%s: EKU %v, want serverAuth only", door.door.Name, leaf.ExtKeyUsage)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: door.door.Host}); err != nil {
			t.Errorf("%s: does not chain to the CA: %v", door.door.Name, err)
		}
		for _, n := range leaf.DNSNames {
			if slices.Contains(apiNames, n) {
				t.Errorf("%s shares %s with the api leaf %v", door.door.Name, n, apiNames)
			}
		}
	}
}

// issue443Exceptions are the names the control plane is answered for that its
// api leaf does not carry, tabled by Bryce on 2026-09-15 under #443. They are
// listed, not hidden: a new uncovered name fails the invariant below.
var issue443Exceptions = map[string]string{
	"bench.internal":           "geekdojo/geekdojo-brain#443: the zone apex is not on the api leaf",
	"bench.lan.bench.internal": "geekdojo/geekdojo-brain#443: the control plane's .lan name is not on the api leaf",
}

// uncoveredNames returns every name, outside the #443 exceptions, whose leaf
// served by getCert for that SNI does not carry it.
func uncoveredNames(t *testing.T, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), names []string) []string {
	t.Helper()
	var bad []string
	for _, n := range names {
		if _, ok := issue443Exceptions[n]; ok {
			continue
		}
		leaf, err, _ := doorHandshake(t, getCert, n)
		if err != nil || !isLeafFor(leaf, n) {
			bad = append(bad, n)
		}
	}
	return bad
}

// TC-983-06: #443's invariant. Every name the nameserver's SelfSource, its
// ClusterSource (for the control plane's own node), the DoorSource and the
// mesh projection's door entry answer for the control plane passes
// VerifyHostname on the leaf sniCertificate serves for it, apart from the two
// names listed under #443; a name added without a SAN fails.
func TestDoorWiring_EveryNameAnsweredForTheControlPlaneIsOnItsLeaf(t *testing.T) {
	r := newDoorRig(t, nil, nil)
	r.start()
	lan := func() net.IP { return rigLAN }
	zone := proto.BaseDomain(rigCID)
	srcs := map[string]nameserver.Source{
		"ClusterSource": nameserver.NewClusterSource("lan."+zone,
			func() []nameserver.NodeAddr {
				return []nameserver.NodeAddr{{ID: rigCPNode, Hostname: rigCID, IP: rigLAN}}
			},
			func() []nameserver.AppRec { return nil }),
	}
	// main's own list, so a name main adds is checked here too (TC-997-10).
	for i, s := range controlPlaneSources(zone, rigCID+".local", r.table, true, lan, r.appDoor.withheld) {
		srcs[sourceName(i, s)] = s
	}
	var names []string
	for what, s := range srcs {
		recs := s.Records()
		if len(recs) == 0 {
			t.Fatalf("%s answers nothing", what)
		}
		for k := range recs {
			names = append(names, strings.TrimSuffix(k, "."))
		}
	}
	if err := r.mesh.ReconcileAppDNS(r.ctx); err != nil {
		t.Fatal(err)
	}
	for k, ip := range r.sup.got {
		if ip == rigCPTail {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	for _, n := range names {
		leaf, _, _ := doorHandshake(t, r.sni(), n)
		why := issue443Exceptions[n]
		t.Logf("%s → leaf %v %s", n, leaf.DNSNames, why)
	}
	if bad := uncoveredNames(t, r.sni(), names); len(bad) != 0 {
		t.Errorf("names answered for the control plane with no SAN on their leaf: %v", bad)
	}
	for n := range issue443Exceptions {
		if !slices.Contains(names, n) {
			t.Errorf("#443 exception %s is no longer answered; remove it from the list", n)
		}
	}
	if bad := uncoveredNames(t, r.sni(), append(names, "ghost.bench.internal")); !slices.Equal(bad, []string{"ghost.bench.internal"}) {
		t.Errorf("an added uncovered name was not caught: %v", bad)
	}
}

// assertWithheld is TC-983-09's state for a reserved app called name with id.
func assertWithheld(t *testing.T, r *doorRig, name string) {
	t.Helper()
	if m := r.query("signin.bench.internal"); m.Rcode != dns.RcodeNameError {
		t.Errorf("nameserver rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	if err := r.mesh.ReconcileAppDNS(r.ctx); err != nil {
		t.Fatal(err)
	}
	// No door entry: the only signin.bench.internal record is the app's own,
	// at its node's tailnet IP.
	if got := r.sup.got["signin.bench.internal"]; got == rigCPTail {
		t.Errorf("projection carries the door entry: %v", r.sup.got)
	}
	if _, err := r.leaves.app.consumer.Spec(); err == nil || (name != "" && !strings.Contains(err.Error(), name)) {
		t.Errorf("app door spec = %v, want an error naming %q", err, name)
	}
	if _, err := os.Stat(r.leafFile("signin-app")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a leaf was written under tls/signin-app: %v", err)
	}
	if leaf, cerr, _ := doorHandshake(t, r.sni(), "signin.bench.internal"); cerr == nil {
		t.Errorf("app door handshake served %v while withheld", leaf.DNSNames)
	}
	// The home door is unaffected.
	if _, err := os.Stat(r.leafFile("signin-home")); err != nil {
		t.Errorf("home leaf not minted: %v", err)
	}
	if leaf, cerr, _ := doorHandshake(t, r.sni(), "sso-bench.local"); cerr != nil || !isLeafFor(leaf, "sso-bench.local") {
		t.Errorf("home door handshake: %v %v", leaf, cerr)
	}
}

// TC-983-09: a pre-upgrade app named signin, or radius, withholds the app
// door at start: NXDOMAIN, no projection door entry (the app's own record
// stays), the spec errors naming it, no leaf file, a refused handshake, and
// one start-up WARN naming it; the home door is unaffected. The
// app-reserved-name alert is TestAppAlerts_ReservedName (api/internal/alerts).
func TestDoorWiring_ReservedAppWithholdsTheAppDoor(t *testing.T) {
	for _, name := range []string{"signin", "radius"} {
		t.Run(name, func(t *testing.T) {
			r := newDoorRig(t, nil, nil)
			r.addApp("a1", name)
			r.start()
			assertWithheld(t, r, name)
			if name == "signin" && r.sup.got["signin.bench.internal"] != rigAppTail {
				t.Errorf("the app's own record is gone: %v", r.sup.got)
			}
			var warns int
			for _, rec := range r.rec.Matching(slog.LevelWarn, "app sign-in address withheld") {
				if rec.Message == "app sign-in address withheld" {
					warns++
					if v, _ := logkittest.Attr(rec, "app"); v != name {
						t.Errorf("WARN app = %q, want %q", v, name)
					}
				}
			}
			if warns != 1 {
				t.Errorf("start-up WARNs = %d, want 1:\n%s", warns, r.rec.Text())
			}
		})
	}
}

// TC-983-10: an apps store whose List errors withholds the app door at every
// consumer through the one predicate: NXDOMAIN, the spec errors with no mint,
// no projection door entry, and a WARN carrying the error.
func TestDoorWiring_StoreErrorWithholds(t *testing.T) {
	r := newDoorRig(t, failingApps{}, nil)
	r.start()
	assertWithheld(t, r, "")
	if _, ok := r.sup.got["signin.bench.internal"]; ok {
		t.Errorf("projection carries the door on a store error: %v", r.sup.got)
	}
	recs := r.rec.Matching(slog.LevelWarn, "the apps list could not be read")
	if len(recs) == 0 {
		t.Fatalf("no WARN for the store error:\n%s", r.rec.Text())
	}
	if v, _ := logkittest.Attr(recs[0], "err"); v != "database is locked" {
		t.Errorf("WARN err = %q", v)
	}
}

// TC-983-11: deleting the reserved app publishes AppDeleted on the bus; the
// handler's refresh mints and loads the app-door leaf, and its projection adds
// the door entry, with no restart. The next query answers the LAN IP and the
// handshake serves the app-door leaf; the next sweep then has nothing to
// renew. Without the handler, the sweep alone mints the leaf and reloads the
// holder (the safety net). The alert clearing is TestAppAlerts_ReservedName.
func TestDoorWiring_AppDeletedRestoresTheAppDoor(t *testing.T) {
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)

	r := newDoorRig(t, nil, nil)
	r.addApp("a1", "signin")
	r.start()
	assertWithheld(t, r, "signin")

	done := make(chan struct{}, 1)
	reconcile := func(ctx context.Context) error {
		defer func() { done <- struct{}{} }()
		return r.mesh.ReconcileAppDNS(ctx)
	}
	sub, err := subscribeAppDeleted(nc, appDeletedHandler(r.ctx, r.log, r.leaves.app.holder, reconcile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}

	// The app.delete saga's last step: the row goes, then the event.
	if err := r.store.Delete(r.ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := nc.Publish(proto.AppChangeSubject("a1", proto.AppDeleted), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the AppDeleted handler never ran")
	}

	if m := r.query("signin.bench.internal"); m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 || !m.Answer[0].(*dns.A).A.Equal(rigLAN) {
		t.Errorf("nameserver after delete: %v", m)
	}
	if r.sup.got["signin.bench.internal"] != rigCPTail {
		t.Errorf("projection after delete = %v, want the door entry", r.sup.got)
	}
	if leaf, cerr, _ := doorHandshake(t, r.sni(), "signin.bench.internal"); cerr != nil || !isLeafFor(leaf, "signin.bench.internal") {
		t.Errorf("app door handshake after delete: %v %v", leaf, cerr)
	}
	if rep := r.sweeper.Sweep(r.ctx, nil); len(rep.Renewed) != 0 || len(rep.Failed) != 0 {
		t.Errorf("sweep after the handler = %+v, want nothing renewed", rep)
	}

	t.Run("sweep safety net", func(t *testing.T) {
		r := newDoorRig(t, nil, nil)
		r.addApp("a1", "signin")
		r.start()
		if err := r.store.Delete(r.ctx, "a1"); err != nil {
			t.Fatal(err)
		}
		rep := r.sweeper.Sweep(r.ctx, nil)
		if !slices.Contains(rep.Renewed, "signin-app") || !slices.Contains(rep.Reloaded, "signin-app") {
			t.Fatalf("sweep = %+v, want signin-app renewed and reloaded", rep)
		}
		if leaf, cerr, _ := doorHandshake(t, r.sni(), "signin.bench.internal"); cerr != nil || !isLeafFor(leaf, "signin.bench.internal") {
			t.Errorf("app door handshake after the sweep: %v %v", leaf, cerr)
		}
	})
}

// TC-983-15: the declared resolver fails closed on every shape of input. An
// absent or empty id is doors off with INFO; Bench, ben_ch, -bench and a
// 60-character id are doors off with an ERROR configfault naming the id; a
// 59-character id is accepted. With doors off, no door leaf consumer is
// required, so the api starts.
func TestDoorTableFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, value string
		unset       bool
		want        string // "" doors off, no cluster id; "refused"; "on"
	}{
		{name: "absent", unset: true},
		{name: "empty", value: ""},
		{name: "blank", value: "   "},
		{name: "uppercase", value: "Bench", want: "refused"},
		{name: "underscore", value: "ben_ch", want: "refused"},
		{name: "leading hyphen", value: "-bench", want: "refused"},
		{name: "60 characters", value: strings.Repeat("a", 60), want: "refused"},
		{name: "59 characters", value: strings.Repeat("a", 59), want: "on"},
		{name: "padded", value: " bench ", want: "on"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.unset {
				t.Setenv("RASPUTIN_CLUSTER_ID", "x")
				_ = os.Unsetenv("RASPUTIN_CLUSTER_ID")
			} else {
				t.Setenv("RASPUTIN_CLUSTER_ID", c.value)
			}
			log, rec := logkittest.New()
			table, err := doorTableFromEnv()
			on := wireDoorTable(ctx, log, table, err)
			switch c.want {
			case "":
				if on || table.App.Host != "" || len(rec.Matching(slog.LevelInfo, "sign-in doors off: no cluster id")) != 1 {
					t.Errorf("on=%v table=%+v logs:\n%s", on, table, rec.Text())
				}
			case "refused":
				recs := rec.Matching(slog.LevelError, "sign-in doors off: cluster id refused")
				if on || table.App.Host != "" || len(recs) != 1 {
					t.Fatalf("on=%v table=%+v logs:\n%s", on, table, rec.Text())
				}
				if v, _ := logkittest.Attr(recs[0], "configfault"); v != "true" {
					t.Errorf("configfault = %q", v)
				}
				if v, _ := logkittest.Attr(recs[0], "cluster_id"); v != c.value {
					t.Errorf("cluster_id = %q, want %q", v, c.value)
				}
			case "on":
				if !on || table.App.Host != proto.SignInFQDN(strings.TrimSpace(c.value)) {
					t.Errorf("on=%v table=%+v", on, table)
				}
			}
			if !on {
				for _, n := range requiredLeafConsumers(true, true, true, on) {
					if n == signInHomeLeafName || n == signInAppLeafName {
						t.Errorf("doors off still requires %s", n)
					}
				}
				// No AppDoorHost: the projection has no door entry.
				r := newDoorRig(t, nil, nil)
				svc := mesh.NewService(mesh.Config{ClusterID: rigCID, SelfNodeID: rigCPNode, AppDoorWithheld: func() bool { return false }},
					r.mesh.Store(), mesh.NewUnavailableClient("test"), r.sup)
				svc.SetAppLister(func() []mesh.AppDNS { return nil })
				if err := svc.ReconcileAppDNS(ctx); err != nil || len(r.sup.got) != 0 {
					t.Errorf("doors off projected %v, %v", r.sup.got, err)
				}
			}
		})
	}
}

// TC-983-16: the leaf lifecycle.
func TestDoorLeaves_Lifecycle(t *testing.T) {
	t.Run("behind the clock gate", func(t *testing.T) {
		release := make(chan struct{})
		deps := tlscatest.Deps()
		deps.LeafClock = func() bool { <-release; return true }
		r := newDoorRig(t, nil, &deps)
		loaded := make(chan struct{})
		go func() { r.leaves.load(r.ctx, r.log); close(loaded) }()
		// The gate has not returned, so no door leaf exists yet.
		for _, d := range []string{"signin-home", "signin-app"} {
			if _, err := os.Stat(r.leafFile(d)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s exists before the clock gate passed: %v", d, err)
			}
		}
		close(release)
		<-loaded
		for _, d := range []string{"signin-home", "signin-app"} {
			if _, err := os.Stat(r.leafFile(d)); err != nil {
				t.Errorf("%s not minted after the gate: %v", d, err)
			}
		}
	})

	t.Run("upgrade, restart and renewal", func(t *testing.T) {
		r := newDoorRig(t, nil, nil)
		// The previous release left only the api leaf.
		if err := r.api.load(rigLAN); err != nil {
			t.Fatal(err)
		}
		apiBefore, err := os.ReadFile(filepath.Join(r.dir, "tls", "api", "leaf.pem"))
		if err != nil {
			t.Fatal(err)
		}
		r.start()
		apiAfter, _ := os.ReadFile(filepath.Join(r.dir, "tls", "api", "leaf.pem"))
		if !bytes.Equal(apiBefore, apiAfter) {
			t.Error("the api leaf's bytes changed on upgrade")
		}
		serial := func(h *apiLeaf) string {
			c, err := h.getCertificate(nil)
			if err != nil {
				t.Fatal(err)
			}
			leaf, _ := x509.ParseCertificate(c.Certificate[0])
			return leaf.SerialNumber.String()
		}
		first := serial(r.leaves.home.holder)

		// Restart: a fresh holder over the same directory loads the leaf on
		// disk without a new serial.
		again := newDoorLeaves(r.ca, r.dir, r.table, r.appDoor)
		again.load(r.ctx, r.log)
		if got := serial(again.home.holder); got != first {
			t.Errorf("restart minted a new serial: %s → %s", first, got)
		}

		// Renewal: a leaf carrying an extra SAN is re-minted by the sweep,
		// and the holder serves the new serial on the next handshake.
		spec := r.table.Home.LeafSpec()
		spec.DNSNames = append(spec.DNSNames, "extra.example")
		spec.ExactDNSNames = false
		if err := os.RemoveAll(filepath.Join(r.dir, "tls", "signin-home")); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ca.MintLeafToDisk(filepath.Join(r.dir, "tls", "signin-home"), spec); err != nil {
			t.Fatal(err)
		}
		rep := r.sweeper.Sweep(r.ctx, nil)
		if !slices.Contains(rep.Renewed, "signin-home") || !slices.Contains(rep.Reloaded, "signin-home") {
			t.Fatalf("sweep = %+v", rep)
		}
		leaf, cerr, _ := doorHandshake(t, r.sni(), "sso-bench.local")
		if cerr != nil || leaf.SerialNumber.String() == first || !slices.Equal(leaf.DNSNames, []string{"sso-bench.local"}) {
			t.Errorf("after renewal: %v %v", leaf, cerr)
		}
	})

	t.Run("mint failure", func(t *testing.T) {
		r := newDoorRig(t, nil, nil)
		failed := newDoorLeaves(nil, r.dir, r.table, r.appDoor)
		failed.load(r.ctx, r.log)
		recs := r.rec.Matching(slog.LevelWarn, "sign-in leaf not loaded")
		var doorsSeen []string
		for _, rec := range recs {
			d, _ := logkittest.Attr(rec, "door")
			e, _ := logkittest.Attr(rec, "err")
			if e == "" {
				t.Errorf("WARN for %s carries no err", d)
			}
			doorsSeen = append(doorsSeen, d)
		}
		slices.Sort(doorsSeen)
		if !slices.Equal(doorsSeen, []string{"signin-app", "signin-home"}) {
			t.Errorf("WARNs for %v", doorsSeen)
		}
		if err := r.api.load(rigLAN); err != nil {
			t.Fatal(err)
		}
		if leaf, cerr, _ := doorHandshake(t, sniCertificate(r.api, failed.byHost()), "sso-bench.local"); cerr == nil {
			t.Errorf("handshake served %v after a failed mint", leaf.DNSNames)
		}
	})

	t.Run("consumers", func(t *testing.T) {
		for _, c := range []struct {
			https, doors bool
			want         bool
		}{{true, true, true}, {true, false, false}, {false, true, false}, {false, false, false}} {
			got := requiredLeafConsumers(c.https, false, false, c.doors)
			has := slices.Contains(got, signInHomeLeafName) && slices.Contains(got, signInAppLeafName)
			if has != c.want || (!c.want && (slices.Contains(got, signInHomeLeafName) || slices.Contains(got, signInAppLeafName))) {
				t.Errorf("https=%v doors=%v: %v", c.https, c.doors, got)
			}
		}
		// HTTPS and doors on: the registered door consumers satisfy the check.
		r := newDoorRig(t, nil, nil)
		if err := verifyLeafConsumers(append(r.sweeper.RegisteredNames(), "api-https"), requiredLeafConsumers(true, false, false, true)); err != nil {
			t.Errorf("registered doors fail the check: %v", err)
		}
		// A cluster id with HTTPS off: nothing is registered and nothing is
		// required, so the api starts.
		if err := verifyLeafConsumers(nil, requiredLeafConsumers(false, false, false, true)); err != nil {
			t.Errorf("HTTPS off with a cluster id stops the api: %v", err)
		}
	})
}

// The renamed-device hook only logs until the alerts service is wired, then
// raises through it, and logs a raise that fails.
func TestDeviceRenamedVia(t *testing.T) {
	log, rec := logkittest.New()
	holder := &atomic.Pointer[deviceRenamedFunc]{}
	hook := deviceRenamedVia(holder, log)
	hook(context.Background(), "12", "signin", "signin-12")
	if len(rec.Matching(slog.LevelWarn, "before alerts were wired")) != 1 {
		t.Errorf("unset hook logs:\n%s", rec.Text())
	}
	var raised []string
	f := deviceRenamedFunc(func(_ context.Context, hsID, from, to string) error {
		raised = append(raised, hsID+":"+from+":"+to)
		return errors.New("store down")
	})
	holder.Store(&f)
	hook(context.Background(), "12", "signin", "signin-12")
	if !slices.Equal(raised, []string{"12:signin:signin-12"}) || len(rec.Matching(slog.LevelWarn, "alert not raised")) != 1 {
		t.Errorf("raised %v logs:\n%s", raised, rec.Text())
	}
}
