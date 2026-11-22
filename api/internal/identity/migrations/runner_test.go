package migrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fakeRealm is the Admin API over one realm's attribute map. Every call is
// logged; a call made while lock is not held is counted.
type fakeRealm struct {
	mu       sync.Mutex
	attrs    map[string]string
	calls    []string
	getErr   error
	putErr   error
	lock     *sync.Mutex
	unlocked int
}

func (f *fakeRealm) Admin(_ context.Context, method, path string, in, out any) (idclient.Response, error) {
	if f.lock != nil {
		if f.lock.TryLock() {
			f.lock.Unlock()
			f.mu.Lock()
			f.unlocked++
			f.mu.Unlock()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method+" "+path)
	if path != "/admin/realms/rasputin" {
		return idclient.Response{}, &idclient.Error{Op: "admin", Path: path, Kind: idclient.ErrNotFound}
	}
	switch method {
	case http.MethodGet:
		if f.getErr != nil {
			return idclient.Response{}, f.getErr
		}
		b, _ := json.Marshal(map[string]any{"realm": "rasputin", "attributes": f.attrs})
		return idclient.Response{Status: 200}, json.Unmarshal(b, out)
	case http.MethodPut:
		if f.putErr != nil {
			return idclient.Response{}, f.putErr
		}
		b, _ := json.Marshal(in)
		var body map[string]json.RawMessage
		_ = json.Unmarshal(b, &body)
		if len(body) != 1 || body["attributes"] == nil {
			return idclient.Response{}, fmt.Errorf("PUT carries %d fields, want attributes alone", len(body))
		}
		var attrs map[string]string
		if err := json.Unmarshal(body["attributes"], &attrs); err != nil {
			return idclient.Response{}, err
		}
		f.attrs = attrs
		return idclient.Response{Status: 204}, nil
	}
	return idclient.Response{}, errors.New("unexpected method")
}

func (f *fakeRealm) attr(k string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.attrs[k]
	return v, ok
}

// fixtures are n migrations that each log their ID into applied and set an
// attribute of their own through a; fail, when set, fails that ID.
func fixtures(n int, applied *[]int, fail int) []Migration {
	var out []Migration
	for i := 1; i <= n; i++ {
		out = append(out, Migration{ID: i, Name: fmt.Sprintf("fixture-%d", i), Apply: func(ctx context.Context, a Admin, realm string) error {
			if i == fail {
				return errors.New("fixture failure")
			}
			*applied = append(*applied, i)
			var rep realmAttrs
			if _, err := a.Admin(ctx, http.MethodGet, "/admin/realms/"+realm, nil, &rep); err != nil {
				return err
			}
			rep.Attributes[fmt.Sprintf("fixture.%d", i)] = json.RawMessage(`"set"`)
			_, err := a.Admin(ctx, http.MethodPut, "/admin/realms/"+realm, map[string]any{"attributes": rep.Attributes}, nil)
			return err
		}})
	}
	return out
}

func newRunner(t *testing.T, f *fakeRealm, all []Migration) (*Runner, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	if f.lock == nil {
		f.lock = &sync.Mutex{}
	}
	r, err := New(Deps{Admin: f, Realm: "rasputin", Lock: f.lock, All: all, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return r, rec
}

// TC-981-15: New refuses IDs that are not 1..n in order.
func TestNew_RefusesBadIDs(t *testing.T) {
	apply := func(context.Context, Admin, string) error { return nil }
	m := func(id int) Migration { return Migration{ID: id, Name: "x", Apply: apply} }
	log := slog.New(slog.DiscardHandler)
	for name, all := range map[string][]Migration{
		"gap":       {m(1), m(3)},
		"duplicate": {m(1), m(1)},
		"zero":      {m(0)},
		"unordered": {m(2), m(1)},
	} {
		if _, err := New(Deps{Admin: &fakeRealm{}, Realm: "rasputin", Lock: &sync.Mutex{}, All: all, Log: log}); err == nil {
			t.Errorf("%s: New accepted %v", name, all)
		}
	}
	if _, err := New(Deps{Admin: &fakeRealm{}, Realm: "rasputin", Lock: &sync.Mutex{}, All: []Migration{m(1), m(2)}, Log: log}); err != nil {
		t.Errorf("1..2: %v", err)
	}
	if _, err := New(Deps{Realm: "rasputin", Lock: &sync.Mutex{}, Log: log}); err == nil {
		t.Error("a nil Admin was accepted")
	}
}

// TC-981-15: Lagging reads an absent record as 0; a malformed one, or one
// above n, is an error.
func TestLagging(t *testing.T) {
	var applied []int
	for _, c := range []struct {
		attrs   map[string]string
		applied int
		wantErr bool
	}{
		{map[string]string{"other": "x"}, 0, false},
		{map[string]string{RecordAttr: "2"}, 2, false},
		{map[string]string{RecordAttr: "3"}, 3, false},
		{map[string]string{RecordAttr: "4"}, 0, true},
		{map[string]string{RecordAttr: "two"}, 0, true},
		{map[string]string{RecordAttr: "-1"}, 0, true},
		{map[string]string{RecordAttr: "02"}, 0, true},
		{map[string]string{RecordAttr: ""}, 0, true},
	} {
		r, _ := newRunner(t, &fakeRealm{attrs: c.attrs}, fixtures(3, &applied, 0))
		got, want, err := r.Lagging(t.Context())
		if (err != nil) != c.wantErr || got != c.applied || (err == nil && want != 3) {
			t.Errorf("%v: Lagging = %d, %d, %v; want %d, 3, error %t", c.attrs, got, want, err, c.applied, c.wantErr)
		}
	}
	r, _ := newRunner(t, &fakeRealm{getErr: &idclient.Error{Op: "admin", Kind: idclient.ErrUnreachable}}, nil)
	if _, _, err := r.Lagging(t.Context()); err == nil {
		t.Error("an unreadable realm read as not lagging")
	}
}

// TC-981-15: Run applies the pending migrations in order and records each
// one after it, keeping every other attribute.
func TestRun_AppliesInOrderAndRecordsEach(t *testing.T) {
	var applied []int
	f := &fakeRealm{attrs: map[string]string{RecordAttr: "1", "CreateDefaultClientScopes": "true", "frontendUrl": ""}}
	r, _ := newRunner(t, f, fixtures(3, &applied, 0))
	done, err := r.Run(t.Context())
	if err != nil || !slices.Equal(done, []int{2, 3}) || !slices.Equal(applied, []int{2, 3}) {
		t.Fatalf("Run = %v, %v; applied %v; want [2 3]", done, err, applied)
	}
	if v, _ := f.attr(RecordAttr); v != "3" {
		t.Errorf("record = %q, want 3", v)
	}
	for _, k := range []string{"CreateDefaultClientScopes", "frontendUrl", "fixture.2", "fixture.3"} {
		if _, ok := f.attr(k); !ok {
			t.Errorf("attribute %s lost", k)
		}
	}
	// The record is written after each migration: GET, the fixture's GET
	// and PUT, then the record's GET and PUT, for 2 and then 3.
	want := []string{"GET", "GET", "PUT", "GET", "PUT", "GET", "PUT", "GET", "PUT"}
	var methods []string
	for _, c := range f.calls {
		methods = append(methods, strings.Fields(c)[0])
	}
	if !slices.Equal(methods, want) {
		t.Errorf("calls = %v, want %v", f.calls, want)
	}
	// Nothing pending: no write.
	f.calls = nil
	if done, err := r.Run(t.Context()); err != nil || len(done) != 0 || len(f.calls) != 1 {
		t.Errorf("second Run = %v, %v with calls %v; want nothing applied, one read", done, err, f.calls)
	}
}

// TC-981-15: Run stops at the first failure with the record at the last
// success, logging ERROR with the migration's id and name.
func TestRun_StopsAtTheFirstFailure(t *testing.T) {
	var applied []int
	f := &fakeRealm{attrs: map[string]string{}}
	r, rec := newRunner(t, f, fixtures(3, &applied, 2))
	done, err := r.Run(t.Context())
	if !errors.Is(err, errApply) || !slices.Equal(done, []int{1}) || !slices.Equal(applied, []int{1}) {
		t.Fatalf("Run = %v, %v; applied %v; want [1] and errApply", done, err, applied)
	}
	if v, _ := f.attr(RecordAttr); v != "1" {
		t.Errorf("record = %q, want 1", v)
	}
	errs := rec.Matching(slog.LevelError, "A realm migration failed.")
	if len(errs) != 1 {
		t.Fatalf("records:\n%s\nwant one ERROR", rec.Text())
	}
	if id, _ := logkittest.Attr(errs[0], "migration_id"); id != "2" {
		t.Errorf("migration_id = %q", id)
	}
	if n, _ := logkittest.Attr(errs[0], "migration"); n != "fixture-2" {
		t.Errorf("migration = %q", n)
	}
	// A record above n, or malformed, applies nothing.
	f = &fakeRealm{attrs: map[string]string{RecordAttr: "9"}}
	r, _ = newRunner(t, f, fixtures(3, &applied, 0))
	if _, err := r.Run(t.Context()); !errors.Is(err, errRecord) || len(f.calls) != 1 {
		t.Errorf("newer realm: Run = %v with calls %v; want errRecord and no write", err, f.calls)
	}
	// A record write that fails stops the run.
	f = &fakeRealm{attrs: map[string]string{}, putErr: errors.New("refused")}
	applied = nil
	r, _ = newRunner(t, f, []Migration{{ID: 1, Name: "noop", Apply: func(context.Context, Admin, string) error { return nil }}})
	if done, err := r.Run(t.Context()); !errors.Is(err, errRecordWrite) || len(done) != 0 {
		t.Errorf("record write refused: Run = %v, %v", done, err)
	}
	// A failed first read writes nothing.
	f = &fakeRealm{getErr: errors.New("down")}
	r, _ = newRunner(t, f, fixtures(1, &applied, 0))
	if _, err := r.Run(t.Context()); !errors.Is(err, errRead) {
		t.Errorf("unreadable realm: Run = %v", err)
	}
}

// TC-981-15: Run holds the realm lock for every Admin API call it and its
// migrations make, so it never writes while converge, which holds the same
// lock, does.
func TestRun_HoldsTheSharedLock(t *testing.T) {
	var applied []int
	lock := &sync.Mutex{}
	f := &fakeRealm{attrs: map[string]string{}, lock: lock}
	r, _ := newRunner(t, f, fixtures(2, &applied, 0))
	if _, err := r.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.unlocked != 0 || len(f.calls) == 0 {
		t.Fatalf("%d of %d calls were made without the realm lock", f.unlocked, len(f.calls))
	}
}
