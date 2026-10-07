package nodetrust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

// events records the order of reloads and re-registers.
type events struct {
	mu  sync.Mutex
	got []string
}

func (e *events) add(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.got = append(e.got, s)
}

func (e *events) take() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.got
	e.got = nil
	return out
}

// fakeReloader records its calls and fails while fail is set.
type fakeReloader struct {
	ev   *events
	fail error
}

func (r *fakeReloader) ReloadTrust(context.Context) error {
	r.ev.add("reload")
	return r.fail
}

// logRecords captures slog records.
type logRecords struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *logRecords) Enabled(context.Context, slog.Level) bool { return true }
func (h *logRecords) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r.Clone())
	return nil
}
func (h *logRecords) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logRecords) WithGroup(string) slog.Handler      { return h }

func (h *logRecords) errors() []map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []map[string]string
	for _, r := range h.recs {
		if r.Level != slog.LevelError {
			continue
		}
		m := map[string]string{"msg": r.Message}
		r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.String(); return true })
		out = append(out, m)
	}
	return out
}

type handlerFixture struct {
	h      *Handler
	store  *Store
	ev     *events
	reload *fakeReloader
	logs   *logRecords
}

func newHandlerFixture(t *testing.T, withReloader bool) *handlerFixture {
	t.Helper()
	f := &handlerFixture{store: NewStore(filepath.Join(t.TempDir(), "mesh", "tailscaled-ca.pem")), ev: &events{}, logs: &logRecords{}}
	var rs []Reloader
	if withReloader {
		f.reload = &fakeReloader{ev: f.ev}
		rs = append(rs, f.reload)
	}
	h, err := NewHandler(f.store, rs, func() { f.ev.add("reregister") }, slog.New(f.logs))
	if err != nil {
		t.Fatal(err)
	}
	f.h = h
	return f
}

func (f *handlerFixture) install(t *testing.T, bundle []byte) proto.TrustInstallAck {
	t.Helper()
	data, err := json.Marshal(proto.TrustInstallCmd{BundlePEM: bundle})
	if err != nil {
		t.Fatal(err)
	}
	ack := f.h.Handle(context.Background(), "n1", data)
	// The ack is computed after every side effect; record it in the order.
	f.ev.add("ack")
	return ack
}

func (f *handlerFixture) marker() string { return f.store.Path() + reloadPendingSuffix }

func eq(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

// TC-741-19: the trust.install handler.
func TestHandler_TrustInstall(t *testing.T) {
	a := tlstest.NewCA(t, "a").PEM

	t.Run("new bundle: install, reload, re-register once, then ack", func(t *testing.T) {
		f := newHandlerFixture(t, true)
		ack := f.install(t, a)
		if !ack.OK || !ack.Changed || ack.Fingerprint != proto.TrustFingerprint(a) || ack.NodeID != "n1" {
			t.Errorf("ack %+v", ack)
		}
		if got := f.ev.take(); !eq(got, []string{"reload", "reregister", "ack"}) {
			t.Errorf("order %v, want reload, reregister, ack", got)
		}
		if _, err := os.Stat(f.marker()); !os.IsNotExist(err) {
			t.Error("the marker is left after a successful reload")
		}
	})

	t.Run("identical bundle, no marker: nothing reloads or re-registers", func(t *testing.T) {
		f := newHandlerFixture(t, true)
		f.install(t, a)
		f.ev.take()
		ack := f.install(t, a)
		if !ack.OK || ack.Changed {
			t.Errorf("ack %+v", ack)
		}
		if got := f.ev.take(); !eq(got, []string{"ack"}) {
			t.Errorf("events %v, want none before the ack", got)
		}
	})

	t.Run("refused input leaves the bundle and makes no marker", func(t *testing.T) {
		f := newHandlerFixture(t, true)
		f.install(t, a)
		before, _ := os.ReadFile(f.store.Path())
		for name, in := range refusedBundles(t) {
			f.ev.take()
			ack := f.install(t, in)
			if ack.OK {
				t.Errorf("%s: OK", name)
			}
			if b, _ := os.ReadFile(f.store.Path()); !bytes.Equal(b, before) {
				t.Errorf("%s: bundle changed", name)
			}
			if _, err := os.Stat(f.marker()); !os.IsNotExist(err) {
				t.Errorf("%s: a marker was created", name)
			}
			if got := f.ev.take(); !eq(got, []string{"ack"}) {
				t.Errorf("%s: events %v", name, got)
			}
		}
		if ack := f.h.Handle(context.Background(), "n1", []byte("{not json")); ack.OK {
			t.Error("a malformed command was acked OK")
		}
	})

	t.Run("a write failure is OK=false", func(t *testing.T) {
		dir := t.TempDir()
		notADir := filepath.Join(dir, "file")
		if err := os.WriteFile(notADir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		h, err := NewHandler(NewStore(filepath.Join(notADir, "ca.pem")), nil, func() {}, slog.New(&logRecords{}))
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(proto.TrustInstallCmd{BundlePEM: a})
		if ack := h.Handle(context.Background(), "n1", data); ack.OK || ack.Detail == "" {
			t.Errorf("ack %+v, want a refusal with a reason", ack)
		}
	})

	t.Run("reload failure, then a retry that succeeds", func(t *testing.T) {
		f := newHandlerFixture(t, true)
		f.reload.fail = errors.New("systemctl exited 1")
		ack := f.install(t, a)
		if ack.OK || !ack.Changed || !strings.Contains(ack.Detail, "installed; reloading tailscaled failed") {
			t.Errorf("ack %+v", ack)
		}
		if ack.Fingerprint != proto.TrustFingerprintReloadPending || f.h.ReportedFingerprint() != proto.TrustFingerprintReloadPending {
			t.Errorf("reports %q / %q, want reload-pending", ack.Fingerprint, f.h.ReportedFingerprint())
		}
		if got := mode(t, f.marker()); got != 0o600 {
			t.Errorf("marker mode %o, want 600", got)
		}
		if got := f.ev.take(); !eq(got, []string{"reload", "reregister", "ack"}) {
			t.Errorf("order %v: re-register must still fire once", got)
		}
		errs := f.logs.errors()
		if len(errs) != 1 || errs[0]["err"] == "" || errs[0]["bundle"] != f.store.Path() {
			t.Errorf("ERROR records %v, want one with err and bundle", errs)
		}

		f.reload.fail = nil
		ack = f.install(t, a)
		if !ack.OK || ack.Changed || ack.Fingerprint != proto.TrustFingerprint(a) {
			t.Errorf("retry ack %+v", ack)
		}
		if got := f.ev.take(); !eq(got, []string{"reload", "reregister", "ack"}) {
			t.Errorf("retry order %v: an identical install while pending must reload", got)
		}
		if _, err := os.Stat(f.marker()); !os.IsNotExist(err) {
			t.Error("the marker survived a successful reload")
		}
	})

	t.Run("a marker present when the handler is built is honoured", func(t *testing.T) {
		f := newHandlerFixture(t, true)
		f.install(t, a)
		if err := os.WriteFile(f.marker(), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// A fresh handler over the same files: an agent restart.
		h, err := NewHandler(f.store, []Reloader{f.reload}, func() { f.ev.add("reregister") }, slog.New(f.logs))
		if err != nil {
			t.Fatal(err)
		}
		if h.ReportedFingerprint() != proto.TrustFingerprintReloadPending {
			t.Errorf("a fresh handler reports %q", h.ReportedFingerprint())
		}
		f.h = h
		f.ev.take()
		if ack := f.install(t, a); !ack.OK || ack.Changed {
			t.Errorf("ack %+v", ack)
		}
		if got := f.ev.take(); !eq(got, []string{"reload", "reregister", "ack"}) {
			t.Errorf("events %v, want the pending reload run", got)
		}
	})

	t.Run("no reloaders: a new bundle is OK and leaves no marker", func(t *testing.T) {
		f := newHandlerFixture(t, false)
		if ack := f.install(t, a); !ack.OK || !ack.Changed {
			t.Errorf("ack %+v", ack)
		}
		if _, err := os.Stat(f.marker()); !os.IsNotExist(err) {
			t.Error("a marker was left with nothing to reload")
		}
	})
}

// TC-741-31 (F-741-17, F-741-02): a reload-pending marker that cannot be
// written fails closed. The bundle is left as it was, the ack is OK=false
// naming the failure, nothing reloads, and the node never reports the new
// bundle's fingerprint, so the api reads it as stale and sends again. Once the
// marker can be written, the same bundle installs, reloads and reports.
func TestHandler_UnwritableMarkerFailsClosed(t *testing.T) {
	a := tlstest.NewCA(t, "a").PEM
	b := tlstest.NewCA(t, "b").PEM
	f := newHandlerFixture(t, true)
	if ack := f.install(t, a); !ack.OK {
		t.Fatalf("first install %+v", ack)
	}
	f.ev.take()
	before, err := os.ReadFile(f.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	// A directory where the marker belongs: WriteSecretFile cannot replace it.
	if err := os.MkdirAll(filepath.Join(f.marker(), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.reload.fail = errors.New("systemctl exited 1")

	ack := f.install(t, b)
	if ack.OK || ack.Changed || !strings.Contains(ack.Detail, "reload-pending marker could not be written") {
		t.Errorf("ack %+v, want OK=false naming the marker", ack)
	}
	newFP := proto.TrustFingerprint(b)
	if ack.Fingerprint == newFP || f.h.ReportedFingerprint() == newFP {
		t.Errorf("reports %q / %q: the new bundle's fingerprint before any reload", ack.Fingerprint, f.h.ReportedFingerprint())
	}
	if got, _ := os.ReadFile(f.store.Path()); !bytes.Equal(got, before) {
		t.Error("the bundle changed although its marker could not be written")
	}
	if got := f.ev.take(); !eq(got, []string{"ack"}) {
		t.Errorf("events %v, want no reload and no re-register", got)
	}
	errs := f.logs.errors()
	if len(errs) != 1 || errs[0]["bundle"] != f.store.Path() || errs[0]["err"] == "" {
		t.Errorf("ERROR records %v, want one naming the bundle and err", errs)
	}

	// The marker can be written again and tailscaled reloads.
	if err := os.RemoveAll(f.marker()); err != nil {
		t.Fatal(err)
	}
	f.reload.fail = nil
	ack = f.install(t, b)
	if !ack.OK || !ack.Changed || ack.Fingerprint != newFP || f.h.ReportedFingerprint() != newFP {
		t.Errorf("retry ack %+v, reports %q", ack, f.h.ReportedFingerprint())
	}
	if got := f.ev.take(); !eq(got, []string{"reload", "reregister", "ack"}) {
		t.Errorf("retry events %v", got)
	}
	if got, _ := os.ReadFile(f.store.Path()); !bytes.Equal(got, append(bytes.TrimSpace(b), '\n')) {
		t.Error("the retry did not install the bundle")
	}
}

// A bundle write that fails after its marker is written leaves the marker, so
// the node reports reload-pending and the api sends again.
func TestHandler_BundleWriteFailureAfterTheMarkerStaysPending(t *testing.T) {
	f := newHandlerFixture(t, true)
	// A directory where the bundle belongs: the marker beside it can be
	// written, the bundle cannot.
	if err := os.MkdirAll(filepath.Join(f.store.Path(), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	ack := f.install(t, tlstest.NewCA(t, "a").PEM)
	if ack.OK || ack.Changed || !strings.HasPrefix(ack.Detail, "trust bundle not installed: write ") {
		t.Errorf("ack %+v, want a refused write", ack)
	}
	if ack.Fingerprint != proto.TrustFingerprintReloadPending || f.h.ReportedFingerprint() != proto.TrustFingerprintReloadPending {
		t.Errorf("reports %q / %q, want reload-pending", ack.Fingerprint, f.h.ReportedFingerprint())
	}
	if got := f.ev.take(); !eq(got, []string{"ack"}) {
		t.Errorf("events %v, want no reload", got)
	}
}

func TestNewHandler_RefusesMissingCollaborators(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "ca.pem"))
	log := slog.New(&logRecords{})
	for name, build := range map[string]func() (*Handler, error){
		"no store":      func() (*Handler, error) { return NewHandler(nil, nil, func() {}, log) },
		"no reregister": func() (*Handler, error) { return NewHandler(s, nil, nil, log) },
		"no logger":     func() (*Handler, error) { return NewHandler(s, nil, func() {}, nil) },
	} {
		if h, err := build(); err == nil || h != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
