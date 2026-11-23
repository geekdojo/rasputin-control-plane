package door

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// themeTargets are every theme path the fixture's allowlist serves, under
// version v.
func themeTargets(v string) []string {
	login, common := themePaths(v)
	return []string{login + "css/signin.css", common + "vendor/rfc4648/rfc4648.js"}
}

// relayedCSP is the script policy on a relayed answer at door k.
func (f *fixture) relayedCSP(k Kind) string {
	f.t.Helper()
	w := f.do(k, req{target: realmPrefix + ".well-known/openid-configuration"})
	if w.Code != http.StatusOK {
		f.t.Fatalf("%s discovery: %d", k, w.Code)
	}
	return w.Header().Get("Content-Security-Policy")
}

// wantClosed asserts the doors hold no version: every theme path, under
// each version given, is the 404 door page and reaches nothing, and the app
// door's policy names no /resources/ source.
func (f *fixture) wantClosed(what string, versions ...string) {
	f.t.Helper()
	for _, k := range []Kind{Home, App} {
		for _, v := range versions {
			for _, p := range themeTargets(v) {
				before := f.up.count()
				f.wantRefused(f.do(k, req{target: p}), http.StatusNotFound, before, what+": "+k.String()+" "+p)
			}
		}
		if csp := f.relayedCSP(k); strings.Contains(csp, "/resources/") {
			f.t.Errorf("%s: %s policy %q names a theme path with no version known", what, k, csp)
		}
	}
	if csp := f.relayedCSP(App); !strings.HasPrefix(csp, "script-src 'none';") {
		f.t.Errorf("%s: app policy %q, want script-src 'none' with no version known", what, csp)
	}
}

// wantServes asserts the doors serve the theme under v, and the app door's
// policy names v's two paths.
func (f *fixture) wantServes(what, v string) {
	f.t.Helper()
	for _, k := range []Kind{Home, App} {
		for _, p := range themeTargets(v) {
			if w := f.do(k, req{target: p}); w.Code != http.StatusOK {
				f.t.Errorf("%s: %s %s answered %d, want it relayed", what, k, p, w.Code)
			}
		}
	}
	login, common := themePaths(v)
	want := "script-src https://" + f.table.App.Host + login + " https://" + f.table.App.Host + common + ";"
	if csp := f.relayedCSP(App); !strings.HasPrefix(csp, want) {
		f.t.Errorf("%s: app policy %q, want it to start %q", what, csp, want)
	}
}

// TC-985-47: before the version is learned, and after a read fails, every
// /resources/ path is the 404 door page, nothing is forwarded, and no
// policy names a /resources/ source.
func TestDoor_ResourceVersionUnknown(t *testing.T) {
	f := newFixture(t)
	readsBefore := f.vsrc.reads
	log, rec := logkittest.New()
	var err error
	if f.version, err = NewResourceVersion(f.vsrc, log); err != nil {
		t.Fatal(err)
	}
	f.home, f.app = f.build(t)
	f.wantClosed("never learned", testVersion, "zzzzz")
	if n := f.vsrc.reads - readsBefore; n != 0 {
		t.Fatalf("%d reads with no fact to read on", n)
	}

	f.version.Learn(context.Background())
	f.wantServes("learned", testVersion)

	f.vsrc.set("", errors.New("the identity service is down"))
	f.version.Learn(context.Background())
	f.wantClosed("the last read failed", testVersion)
	if warns := rec.Matching(slog.LevelWarn, "resource version not read"); len(warns) != 1 {
		t.Fatalf("%d WARN records for the failed read, want 1", len(warns))
	}
}

// TC-985-48: when the identity service starts again with another version
// (an upgrade), the start fact makes the holder read it again: the theme is
// served under the new version only, and the app door's policy names it.
// Nothing reads it without the fact.
func TestDoor_ResourceVersionChanged(t *testing.T) {
	f := newFixture(t)
	f.wantServes("first start", testVersion)
	reads := make(chan string, 4)
	src := &signalSource{inner: f.vsrc, reads: reads}
	log, _ := logkittest.New()
	rv, err := NewResourceVersion(src, log)
	if err != nil {
		t.Fatal(err)
	}
	f.version = rv
	f.home, f.app = f.build(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rv.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	rv.Stale() // the identity service became ready
	<-reads
	f.vsrc.set("u9x2k", nil) // it started again, upgraded
	rv.Stale()
	<-reads // the second read has begun, so the first one's value is held
	rv.Stale()
	<-reads // and now the second one's
	f.wantServes("after the upgrade", "u9x2k")
	for _, k := range []Kind{Home, App} {
		for _, p := range themeTargets(testVersion) {
			before := f.up.count()
			f.wantRefused(f.do(k, req{target: p}), http.StatusNotFound, before, "the old version at "+k.String())
		}
	}
	if csp := f.relayedCSP(App); strings.Contains(csp, testVersion) {
		t.Errorf("app policy %q still names the old version", csp)
	}
	// Three facts, three reads: none of its own.
	select {
	case <-reads:
		t.Fatal("a read with no fact")
	default:
	}
}

// signalSource reports each read it begins.
type signalSource struct {
	inner VersionSource
	reads chan string
}

func (s *signalSource) ResourceVersion(ctx context.Context, file string) (string, error) {
	s.reads <- file
	return s.inner.ResourceVersion(ctx, file)
}

// TC-985-49: a version without the resource tag's shape is refused before
// it reaches a path match or a policy: the doors behave as with none known,
// and one WARN record names the refusal without the value.
func TestDoor_ResourceVersionMalformed(t *testing.T) {
	for _, v := range []string{"", "ab12", "ab12cd", "ab/1c", "ab.1c", "ab%1c", "ab 1c", `ab"1c`, "ab;1c", "AB12C", "ab12\n"} {
		f := newFixture(t)
		f.vsrc.set(v, nil)
		f.version.Learn(context.Background())
		if got, known := f.version.Current(); known {
			t.Errorf("%q: held as %q", v, got)
		}
		f.wantClosed("malformed "+v, testVersion)
		for _, k := range []Kind{Home, App} {
			if csp := f.relayedCSP(k); v != "" && strings.Contains(csp, v) {
				t.Errorf("%q: %s policy %q carries the value", v, k, csp)
			}
		}
		warns := f.vrec.Matching(slog.LevelWarn, "resource version refused")
		if len(warns) != 1 {
			t.Errorf("%q: %d WARN records, want 1", v, len(warns))
		}
		if v != "" && strings.Contains(f.vrec.Text(), v) {
			t.Errorf("%q: a record carries the value:\n%s", v, f.vrec.Text())
		}
	}
}

func TestNewResourceVersion_Refuses(t *testing.T) {
	log, _ := logkittest.New()
	if _, err := NewResourceVersion(nil, log); err == nil {
		t.Error("no source accepted")
	}
	if _, err := NewResourceVersion(&fakeVersionSource{}, nil); err == nil {
		t.Error("no logger accepted")
	}
}

// TC-985-48, the other fact: the identity service redirects a theme file
// only when it is asked under a version not its own, so a redirected theme
// file is never relayed. The door answers the 404 door page and reads the
// version again.
func TestDoor_ResourceVersionRedirectIsAFact(t *testing.T) {
	f := newFixture(t)
	reads := make(chan string, 4)
	log, _ := logkittest.New()
	rv, err := NewResourceVersion(&signalSource{inner: f.vsrc, reads: reads}, log)
	if err != nil {
		t.Fatal(err)
	}
	rv.Learn(context.Background())
	<-reads
	f.version = rv
	f.home, f.app = f.build(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rv.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	f.vsrc.set("u9x2k", nil) // the service restarted, upgraded, unobserved
	f.up.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", strings.Replace(r.URL.Path, testVersion, "u9x2k", 1))
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	for _, k := range []Kind{Home, App} {
		w := f.do(k, req{target: testLoginPath + "css/signin.css"})
		if w.Code != http.StatusNotFound || !isDoorPage(w) || w.Header().Get("Location") != "" {
			t.Fatalf("%s: a redirected theme file answered %d (door page %v, Location %q), want the 404 door page",
				k, w.Code, isDoorPage(w), w.Header().Get("Location"))
		}
	}
	<-reads // the redirect was the fact
	f.up.setHandler(nil)
	rv.Stale()
	<-reads // the first re-read has ended
	if v, _ := rv.Current(); v != "u9x2k" {
		t.Fatalf("after the redirect the door holds %q, want u9x2k", v)
	}
	f.wantServes("after the redirect", "u9x2k")
}
