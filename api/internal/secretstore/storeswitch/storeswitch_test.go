package storeswitch

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

var fixedNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// openSettings is a real settings table in rasputin.db under dir.
func openSettings(t *testing.T, dir string) *setup.Store {
	t.Helper()
	st, err := setup.OpenStore(context.Background(), filepath.Join(dir, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// countingSettings counts the writes to the settings it wraps, and fails Get
// or Set when told to.
type countingSettings struct {
	inner  Settings
	mu     sync.Mutex
	sets   int
	getErr error
	setErr error
}

func (c *countingSettings) Get(ctx context.Context, key string) (string, error) {
	if c.getErr != nil {
		return "", c.getErr
	}
	return c.inner.Get(ctx, key)
}

func (c *countingSettings) Set(ctx context.Context, key, value string) error {
	c.mu.Lock()
	c.sets++
	c.mu.Unlock()
	if c.setErr != nil {
		return c.setErr
	}
	return c.inner.Set(ctx, key, value)
}

func (c *countingSettings) writes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sets
}

func newMarker(t *testing.T, s Settings) (*Marker, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	m, err := New(Deps{Settings: s, Now: func() time.Time { return fixedNow }, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return m, rec
}

func switchedRecords(rec *logkittest.Recorder) []slog.Record {
	var out []slog.Record
	for _, r := range rec.Records() {
		if ev, _ := logkittest.Attr(r, "event"); ev == "secretstore.switched" {
			out = append(out, r)
		}
	}
	return out
}

// TC-604-03 (F-604-09, SC-CP 11; resolver row R42): Switched over every shape
// of the settings row. Absent and "" read not switched; every other present
// value, a malformed one included, reads switched; a read that fails is an
// error and never an answer.
func TestSwitched_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		why   string
		value *string // nil: no row
		want  bool
	}{
		{"absent", nil, false},
		{"empty", ptr(""), false},
		{"a timestamp", ptr("1793361600000"), true},
		{"malformed", ptr("not-a-time"), true},
		{"whitespace", ptr(" "), true},
		{"zero", ptr("0"), true},
	} {
		t.Run(c.why, func(t *testing.T) {
			st := openSettings(t, t.TempDir())
			t.Cleanup(func() { _ = st.Close() })
			if c.value != nil {
				if err := st.Set(ctx, KeySwitchedAt, *c.value); err != nil {
					t.Fatal(err)
				}
			}
			m, _ := newMarker(t, st)
			got, err := m.Switched(ctx)
			if err != nil || got != c.want {
				t.Fatalf("Switched() = %v, %v; want %v, nil", got, err, c.want)
			}
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		st := openSettings(t, t.TempDir())
		t.Cleanup(func() { _ = st.Close() })
		boom := errors.New("database is locked")
		m, _ := newMarker(t, &countingSettings{inner: st, getErr: boom})
		if got, err := m.Switched(ctx); !errors.Is(err, boom) || got {
			t.Fatalf("Switched() = %v, %v; want false and the read error", got, err)
		}
	})
	t.Run("closed database", func(t *testing.T) {
		st := openSettings(t, t.TempDir())
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		m, _ := newMarker(t, st)
		if got, err := m.Switched(ctx); err == nil || got {
			t.Fatalf("Switched() on a closed database = %v, %v; want an error", got, err)
		}
	})
}

// TC-604-03 (F-604-01): the first MarkSwitched writes the key once and logs
// one INFO; a second writes nothing and logs nothing; a read error is
// returned with no write; a write error is returned.
func TestMarkSwitched_WritesOnceAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	t.Run("first and second call", func(t *testing.T) {
		st := openSettings(t, t.TempDir())
		t.Cleanup(func() { _ = st.Close() })
		cs := &countingSettings{inner: st}
		m, rec := newMarker(t, cs)
		if err := m.MarkSwitched(ctx); err != nil {
			t.Fatal(err)
		}
		v, err := st.Get(ctx, KeySwitchedAt)
		if err != nil || v != "1793361600000" {
			t.Fatalf("the settings row = %q, %v; want the clock's time in milliseconds", v, err)
		}
		recs := switchedRecords(rec)
		if len(recs) != 1 || recs[0].Level != slog.LevelInfo || cs.writes() != 1 {
			t.Fatalf("%d secretstore.switched record(s) and %d write(s); want one INFO and one write", len(recs), cs.writes())
		}
		if err := m.MarkSwitched(ctx); err != nil {
			t.Fatal(err)
		}
		if cs.writes() != 1 || len(switchedRecords(rec)) != 1 {
			t.Fatalf("a second MarkSwitched made %d write(s) and %d record(s) in all; want 1 and 1", cs.writes(), len(switchedRecords(rec)))
		}
		if v2, _ := st.Get(ctx, KeySwitchedAt); v2 != v {
			t.Fatalf("a second MarkSwitched changed the row from %q to %q", v, v2)
		}
	})
	t.Run("a read error writes nothing", func(t *testing.T) {
		st := openSettings(t, t.TempDir())
		t.Cleanup(func() { _ = st.Close() })
		boom := errors.New("database is locked")
		cs := &countingSettings{inner: st, getErr: boom}
		m, rec := newMarker(t, cs)
		if err := m.MarkSwitched(ctx); !errors.Is(err, boom) {
			t.Fatalf("MarkSwitched() = %v, want the read error", err)
		}
		if cs.writes() != 0 || len(switchedRecords(rec)) != 0 {
			t.Fatalf("a failed read made %d write(s) and logged the switch", cs.writes())
		}
	})
	t.Run("a write error is returned", func(t *testing.T) {
		st := openSettings(t, t.TempDir())
		t.Cleanup(func() { _ = st.Close() })
		boom := errors.New("disk full")
		m, rec := newMarker(t, &countingSettings{inner: st, setErr: boom})
		if err := m.MarkSwitched(ctx); !errors.Is(err, boom) {
			t.Fatalf("MarkSwitched() = %v, want the write error", err)
		}
		if len(switchedRecords(rec)) != 0 {
			t.Fatal("a failed write logged the switch")
		}
		if v, _ := st.Get(ctx, KeySwitchedAt); v != "" {
			t.Fatalf("the row holds %q after a failed write", v)
		}
	})
}

// TC-604-03: the constructor refuses each nil dependency, and NoStore refuses
// every switch with ErrNoStore.
func TestNew_RefusesNilAndNoStoreRefuses(t *testing.T) {
	st := openSettings(t, t.TempDir())
	t.Cleanup(func() { _ = st.Close() })
	full := Deps{Settings: st, Now: time.Now, Log: slog.New(slog.DiscardHandler)}
	for name, clear := range map[string]func(*Deps){
		"Settings": func(d *Deps) { d.Settings = nil },
		"Now":      func(d *Deps) { d.Now = nil },
		"Log":      func(d *Deps) { d.Log = nil },
	} {
		d := full
		clear(&d)
		if m, err := New(d); err == nil || m != nil {
			t.Errorf("New with a nil %s = %v, %v; want an error", name, m, err)
		}
	}
	if err := (NoStore{}).MarkSwitched(context.Background()); !errors.Is(err, ErrNoStore) {
		t.Fatalf("NoStore.MarkSwitched() = %v, want ErrNoStore", err)
	}
}

// TC-604-04: the marker survives closing and reopening rasputin.db, read by a
// new Marker; and nothing the package exports can clear it.
func TestMarker_PersistsAndIsOneWay(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openSettings(t, dir)
	m, _ := newMarker(t, st)
	if err := m.MarkSwitched(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openSettings(t, dir)
	t.Cleanup(func() { _ = reopened.Close() })
	m2, _ := newMarker(t, reopened)
	if ok, err := m2.Switched(ctx); err != nil || !ok {
		t.Fatalf("after a reopen Switched() = %v, %v; want true", ok, err)
	}

	// The exported API: every exported method and function in the package's
	// non-test source. None of them may clear, reset or delete the key.
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var exported []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.IsExported() {
				exported = append(exported, fn.Name.Name)
			}
		}
	}
	want := map[string]bool{"New": true, "Switched": true, "MarkSwitched": true}
	for _, name := range exported {
		if !want[name] {
			t.Errorf("storeswitch exports %s; the marker is one-way and the package exports only New, Switched and MarkSwitched", name)
		}
	}
}

func ptr(s string) *string { return &s }
