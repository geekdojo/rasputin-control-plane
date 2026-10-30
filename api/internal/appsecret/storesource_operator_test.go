package appsecret

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// fakeDecls answers OperatorSecrets with decls, or with err, and counts calls.
type fakeDecls struct {
	mu    sync.Mutex
	decls []tileschema.OperatorSecret
	err   error
	calls int
}

func (f *fakeDecls) OperatorSecrets(context.Context, string) ([]tileschema.OperatorSecret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.decls, f.err
}

// operatorCompose uses a required operator name, an optional one and an
// ordinary derived one.
const operatorCompose = "services:\n  app:\n    environment:\n      FEED: ${secret:feed-key}\n      OPT: ${secret:opt-key}\n      PW: ${secret:db-password}\n"

func operatorDecls() []tileschema.OperatorSecret {
	no := false
	return []tileschema.OperatorSecret{
		{Name: "feed-key", Label: "Feed API key"},
		{Name: "opt-key", Label: "Optional key", Required: &no},
	}
}

func operatorHarness(t *testing.T, decls *fakeDecls, entries map[string]string) *harness {
	t.Helper()
	log, rec := logkittest.New()
	svc := newFakeSecrets(entries)
	nodes := &fakeNodes{nodes: map[string]string{appID: node}}
	refs := &fakeRefs{}
	seed := testSeed(t)
	src, err := NewStoreSource(StoreSourceDeps{Secrets: svc, Apps: nodes, Refs: refs, Seed: seed, Operator: decls, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{src: src, svc: svc, nodes: nodes, refs: refs, rec: rec, seed: seed}
}

func (h *harness) creates() int {
	n := 0
	for _, c := range h.svc.callLog() {
		if c.op == "create" {
			n++
		}
	}
	return n
}

func (h *harness) refNames() []string {
	h.refs.mu.Lock()
	defer h.refs.mu.Unlock()
	var out []string
	for _, r := range h.refs.refs {
		out = append(out, r.Name)
	}
	return out
}

// TC-604-09 (F-604-02): a declared name is never derived. An absent optional
// name resolves to "" with no create and no reference; an absent required
// name refuses; an absent undeclared name is derived, created and recorded as
// before; a declaration lookup that fails refuses and derives nothing.
func TestStoreSource_OperatorNamesAreNeverDerived(t *testing.T) {
	feed := mustRef(t, appID, "feed-key").String()
	opt := mustRef(t, appID, "opt-key").String()

	t.Run("absent optional resolves empty", func(t *testing.T) {
		h := operatorHarness(t, &fakeDecls{decls: operatorDecls()}, map[string]string{feed: sentinelStored})
		_, env, err := resolved(h.src.ResolveCompose(jobCtx(), appID, operatorCompose))
		if err != nil {
			t.Fatal(err)
		}
		v, ok := env["RASPUTIN_SECRET_OPT_KEY"]
		if !ok || v != "" {
			t.Fatalf("the optional key is %q (present %v), want present and empty", v, ok)
		}
		if env["RASPUTIN_SECRET_FEED_KEY"] != sentinelStored {
			t.Fatal("the required key does not carry the stored value")
		}
		if env["RASPUTIN_SECRET_DB_PASSWORD"] != derivedValue(t, h.seed, appID, "db-password") {
			t.Fatal("the undeclared key was not derived")
		}
		for _, c := range h.svc.callLog() {
			if c.op == "create" && c.ref.String() == opt {
				t.Fatal("the optional name was created in the store")
			}
		}
		if h.creates() != 1 {
			t.Fatalf("%d creates, want 1 (the undeclared name only)", h.creates())
		}
		for _, name := range h.refNames() {
			if name == "opt-key" {
				t.Fatal("a reference was recorded for the unset optional name")
			}
		}
		assertNoLeak(t, h.rec, nil, derivedValue(t, h.seed, appID, "opt-key"))
	})
	t.Run("absent required refuses", func(t *testing.T) {
		h := operatorHarness(t, &fakeDecls{decls: operatorDecls()}, nil)
		_, _, err := h.src.ResolveCompose(jobCtx(), appID, operatorCompose)
		if err == nil {
			t.Fatal("an absent required operator name resolved")
		}
		if h.creates() != 0 || len(h.refNames()) != 0 {
			t.Fatalf("%d creates and refs %v after the refusal; want none", h.creates(), h.refNames())
		}
		assertRefusedRecord(t, h.rec)
		assertNoLeak(t, h.rec, []error{err}, derivedValue(t, h.seed, appID, "feed-key"))
	})
	t.Run("absent undeclared is derived as before", func(t *testing.T) {
		d := &fakeDecls{decls: operatorDecls()}
		h := operatorHarness(t, d, nil)
		_, env, err := resolved(h.src.ResolveCompose(jobCtx(), appID, tokened))
		if err != nil {
			t.Fatal(err)
		}
		if env["RASPUTIN_SECRET_DB_PASSWORD"] != derivedValue(t, h.seed, appID, "db-password") || h.creates() != 1 {
			t.Fatal("the undeclared name was not derived and created")
		}
		if names := h.refNames(); len(names) != 1 || names[0] != "db-password" {
			t.Fatalf("refs %v, want db-password", names)
		}
		if d.calls != 1 {
			t.Fatalf("%d declaration lookups, want 1", d.calls)
		}
	})
	t.Run("a failed declaration lookup refuses", func(t *testing.T) {
		boom := errors.New("apps table unreadable")
		h := operatorHarness(t, &fakeDecls{err: boom}, nil)
		_, env, err := h.src.ResolveCompose(jobCtx(), appID, tokened)
		if !errors.Is(err, boom) || env != nil {
			t.Fatalf("ResolveCompose = %v (env %v), want a refusal wrapping the lookup error", err, env != nil)
		}
		if h.creates() != 0 || len(h.refNames()) != 0 {
			t.Fatalf("%d creates and refs %v after the lookup failed; want none", h.creates(), h.refNames())
		}
		assertRefusedRecord(t, h.rec)
		assertNoLeak(t, h.rec, []error{err}, derivedValue(t, h.seed, appID, "db-password"))
	})
	t.Run("a stored entry needs no lookup", func(t *testing.T) {
		d := &fakeDecls{err: errors.New("never asked")}
		h := operatorHarness(t, d, map[string]string{mustRef(t, appID, "db-password").String(): sentinelStored})
		if _, _, err := h.src.ResolveCompose(jobCtx(), appID, tokened); err != nil {
			t.Fatal(err)
		}
		if d.calls != 0 {
			t.Fatalf("%d declaration lookups for a stored entry, want 0", d.calls)
		}
	})
}

// assertRefusedRecord requires one WARN appsecret.resolve_refused record with
// outcome "failed": the existing refusal record, not a new one.
func assertRefusedRecord(t *testing.T, rec *logkittest.Recorder) {
	t.Helper()
	n := 0
	for _, r := range rec.AtLevel(slog.LevelWarn) {
		ev, _ := logkittest.Attr(r, "event")
		out, _ := logkittest.Attr(r, "outcome")
		if ev == "appsecret.resolve_refused" && out == "failed" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d WARN appsecret.resolve_refused records with outcome failed, want 1", n)
	}
}
