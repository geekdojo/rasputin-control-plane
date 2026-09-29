package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
)

// recordsHandler keeps every slog record.
type recordsHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *recordsHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordsHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r.Clone())
	return nil
}
func (h *recordsHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordsHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordsHandler) matching(level slog.Level, sub string) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.recs {
		if r.Level == level && strings.Contains(r.Message, sub) {
			out = append(out, r)
		}
	}
	return out
}

// TC-517-53: RASPUTIN_BUS_TLS is reported when set and changes nothing. It is
// set for any non-empty value, and the api writes exactly one WARN naming it,
// with value and fix; unset or empty writes none. The bus config comes from the
// key alone, so it requires TLS whatever the variable says. This is the table
// test the busTLSEnvWarning resolver row names.
func TestBusTLSEnvWarning(t *testing.T) {
	busDir := t.TempDir()
	for _, tc := range []struct {
		name      string
		env       map[string]string
		wantSet   bool
		wantValue string
	}{
		{"unset", map[string]string{}, false, ""},
		{"empty", map[string]string{envRetiredBusTLS: ""}, false, ""},
		{"blank", map[string]string{envRetiredBusTLS: " \t"}, false, ""},
		{"offer", map[string]string{envRetiredBusTLS: "offer"}, true, "offer"},
		{"require", map[string]string{envRetiredBusTLS: "require"}, true, "require"},
		{"banana", map[string]string{envRetiredBusTLS: "banana"}, true, "banana"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			value, set := busTLSEnvWarning(getenv)
			if set != tc.wantSet || value != tc.wantValue {
				t.Fatalf("busTLSEnvWarning = (%q, %v), want (%q, %v)", value, set, tc.wantValue, tc.wantSet)
			}

			h := &recordsHandler{}
			logger := slog.New(h)
			warnRetiredBusTLS(logger, getenv)
			warns := h.matching(slog.LevelWarn, envRetiredBusTLS)
			want := 0
			if tc.wantSet {
				want = 1
			}
			if len(warns) != want {
				t.Fatalf("%d WARN record(s) naming %s, want %d", len(warns), envRetiredBusTLS, want)
			}
			if want == 1 {
				got := map[string]string{}
				warns[0].Attrs(func(a slog.Attr) bool { got[a.Key] = a.Value.String(); return true })
				if got["value"] != tc.wantValue || got["fix"] == "" {
					t.Fatalf("WARN fields = %v, want value %q and a fix", got, tc.wantValue)
				}
			}

			// The bus config: derived from the key, never from the variable.
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, key, cert := loadBusTLS(logger, busDir)
			var cfg bus.Config
			applyBusTLS(&cfg, key, cert)
			if cfg.TLS == nil || cfg.NoListen {
				t.Fatalf("bus config TLS=%v NoListen=%v, want TLS required", cfg.TLS != nil, cfg.NoListen)
			}
		})
	}
}

// With no key, the bus serves no listener: never plaintext.
func TestApplyBusTLS_NoKeyServesNoListener(t *testing.T) {
	cfg := bus.Config{}
	applyBusTLS(&cfg, nil, tls.Certificate{})
	if cfg.TLS != nil || !cfg.NoListen {
		t.Fatalf("no key: TLS=%v NoListen=%v, want no listener", cfg.TLS != nil, cfg.NoListen)
	}
}

// loadBusTLS: an unusable key or certificate is an unavailable state naming the
// file, with one ERROR entry naming it; a fresh directory generates a key
// (WARN) and serves it; a restart loads it.
func TestLoadBusTLS(t *testing.T) {
	t.Run("fresh, then loaded", func(t *testing.T) {
		dir := t.TempDir()
		h := &recordsHandler{}
		st, key, cert := loadBusTLS(slog.New(h), dir)
		if pin, ok := st.Pin(); !ok || key == nil || pin != key.Pin() || len(cert.Certificate) == 0 {
			t.Fatalf("fresh dir: state %v key %v cert %d", ok, key != nil, len(cert.Certificate))
		}
		if len(h.matching(slog.LevelWarn, "bus key generated")) != 1 {
			t.Fatal("no WARN for a generated key")
		}
		on := h.matching(slog.LevelInfo, "bus TLS on")
		if len(on) != 1 || attrOf(on[0], "key_origin") != "generated" || attrOf(on[0], "pin") != key.Pin() {
			t.Fatalf("bus TLS on records = %v", on)
		}
		h2 := &recordsHandler{}
		_, key2, _ := loadBusTLS(slog.New(h2), dir)
		if key2 == nil || key2.Pin() != key.Pin() {
			t.Fatal("a restart did not load the same key")
		}
		if len(h2.matching(slog.LevelWarn, "bus key generated")) != 0 || attrOf(h2.matching(slog.LevelInfo, "bus TLS on")[0], "key_origin") != "loaded" {
			t.Fatal("a loaded key was reported as generated")
		}
	})
	t.Run("corrupt key", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, bustls.KeyFileName)
		if err := os.WriteFile(keyPath, []byte("not a key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		h := &recordsHandler{}
		st, key, _ := loadBusTLS(slog.New(h), dir)
		if key != nil {
			t.Fatal("a corrupt key loaded")
		}
		if file, err := st.Fault(); file != keyPath || err == nil {
			t.Fatalf("Fault = (%q, %v), want %s", file, err, keyPath)
		}
		errs := h.matching(slog.LevelError, "bus key did not load")
		if len(errs) != 1 || attrOf(errs[0], "file") != keyPath || attrOf(errs[0], "alert_id") != bustls.AlertID {
			t.Fatalf("ERROR records = %v", errs)
		}
	})
	t.Run("unreadable certificate", func(t *testing.T) {
		dir := t.TempDir()
		certPath := filepath.Join(dir, bustls.CertFileName)
		if err := os.MkdirAll(certPath, 0o700); err != nil {
			t.Fatal(err)
		}
		h := &recordsHandler{}
		st, key, _ := loadBusTLS(slog.New(h), dir)
		if key != nil {
			t.Fatal("a controlplane with no usable certificate reports its key available")
		}
		if file, err := st.Fault(); file != certPath || err == nil {
			t.Fatalf("Fault = (%q, %v), want %s", file, err, certPath)
		}
		errs := h.matching(slog.LevelError, "bus certificate unusable")
		if len(errs) != 1 || attrOf(errs[0], "file") != certPath {
			t.Fatalf("ERROR records = %v", errs)
		}
	})
}

func attrOf(r slog.Record, key string) string {
	var v string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			v = a.Value.String()
			return false
		}
		return true
	})
	return v
}
