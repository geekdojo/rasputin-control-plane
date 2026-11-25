package move

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// world is the move's collaborators as recording fakes over one call log,
// with a failure for any call by name, and a real Store and auth.Store over
// one SQLite rasputin.db.
type world struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]error

	// realm is the identity service's persons by id; readName overrides
	// the read-back username, noApp drops the read-back app access.
	realm    map[string]accounts.Account
	readName string
	noApp    bool
	removed  map[string]bool
	// removedPass is how many removed-name reads pass before
	// fail["removed"] applies.
	removedPass int
	imports     []importBody

	old     *auth.Store
	store   *Store
	records Records
	dbPath  string
	rec     *logkittest.Recorder
	log     *slog.Logger
	mover   *Mover
}

func (w *world) call(name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, name)
	return w.fail[strings.SplitN(name, ":", 2)[0]]
}

func (w *world) log1() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.calls...)
}

type fAdmin struct{ w *world }

func (a fAdmin) Admin(_ context.Context, method, path string, in, _ any) (idclient.Response, error) {
	if err := a.w.call("import"); err != nil {
		return idclient.Response{}, err
	}
	if method != http.MethodPost || !strings.HasSuffix(path, "/partialImport") {
		return idclient.Response{}, fmt.Errorf("unexpected %s %s", method, path)
	}
	b, _ := json.Marshal(in)
	var body importBody
	_ = json.Unmarshal(b, &body)
	a.w.mu.Lock()
	defer a.w.mu.Unlock()
	a.w.imports = append(a.w.imports, body)
	// Keycloak 26.8.2 (K-PARTIALIMPORT): SKIP skips an existing id under
	// the same username, and answers 409 for the whole import, changing
	// nothing, when an existing id comes under another username.
	for _, u := range body.Users {
		if ex, ok := a.w.realm[u.ID]; ok && ex.Username != u.Username {
			return idclient.Response{}, &idclient.Error{Op: "admin", Status: 409, Kind: idclient.ErrConflict}
		}
	}
	for _, u := range body.Users {
		if _, ok := a.w.realm[u.ID]; ok && body.IfResourceExists == "SKIP" {
			continue
		}
		a.w.realm[u.ID] = accounts.Account{ID: u.ID, Username: u.Username, Enabled: u.Enabled, AppRole: accounts.AppLevel(u.Attributes[accounts.AttrAppRole][0])}
	}
	return idclient.Response{Status: 204}, nil
}

type fPersons struct{ w *world }

func (p fPersons) People(context.Context) ([]accounts.Account, error) {
	if err := p.w.call("people"); err != nil {
		return nil, err
	}
	p.w.mu.Lock()
	defer p.w.mu.Unlock()
	var out []accounts.Account
	for _, a := range p.w.realm {
		out = append(out, a)
	}
	return out, nil
}

func (p fPersons) Read(_ context.Context, sub string) (accounts.Person, error) {
	if err := p.w.call("read"); err != nil {
		return accounts.Person{}, err
	}
	p.w.mu.Lock()
	defer p.w.mu.Unlock()
	a, ok := p.w.realm[sub]
	if !ok {
		return accounts.Person{}, &idclient.Error{Op: "admin", Status: 404, Kind: idclient.ErrNotFound}
	}
	out := accounts.Person{Username: a.Username, Enabled: a.Enabled, AppRole: a.AppRole}
	if p.w.readName != "" {
		out.Username = p.w.readName
	}
	if p.w.noApp {
		out.AppRole = ""
	}
	return out, nil
}

type fDes struct{ w *world }

func (d fDes) DesignateMoved(context.Context, string) error { return d.w.call("designate") }

type fFacts struct{ w *world }

func (f fFacts) Record(context.Context, string) error { return f.w.call("fact") }

type fRemoved struct{ w *world }

func (r fRemoved) Removed(_ context.Context, name, _ string) (bool, error) {
	err := r.w.call("removed")
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	if r.w.removedPass > 0 {
		r.w.removedPass--
		err = nil
	}
	if err != nil {
		return false, err
	}
	return r.w.removed[name], nil
}

type fReady struct{ w *world }

func (r fReady) Ready(context.Context) error { return r.w.call("ready") }

// failingRecords is the Store with a failure by name ("recorded",
// "record", "rows") taken from the world.
type failingRecords struct {
	w     *world
	inner *Store
}

func (f failingRecords) Recorded(ctx context.Context) (bool, error) {
	if err := f.w.fail["recorded"]; err != nil {
		return false, err
	}
	return f.inner.Recorded(ctx)
}

func (f failingRecords) Rows(ctx context.Context) ([]Row, error) {
	if err := f.w.fail["rows"]; err != nil {
		return nil, err
	}
	return f.inner.Rows(ctx)
}

func (f failingRecords) Record(ctx context.Context, rows []Row) error {
	if err := f.w.call("record"); err != nil {
		return err
	}
	return f.inner.Record(ctx, rows)
}

// failingOld is the auth.Store with a failure by name ("count", "list").
type failingOld struct {
	w     *world
	inner *auth.Store
}

func (f failingOld) CountUsers(ctx context.Context) (int, error) {
	if err := f.w.fail["count"]; err != nil {
		return 0, err
	}
	return f.inner.CountUsers(ctx)
}

func (f failingOld) ListUsers(ctx context.Context) ([]*auth.User, error) {
	if err := f.w.fail["list"]; err != nil {
		return nil, err
	}
	return f.inner.ListUsers(ctx)
}

var errDown = errors.New("down")

// newWorld opens rasputin.db with the pre-update release's tables (through
// auth.Store) and the move's, and builds the Mover over the fakes.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{fail: map[string]error{}, realm: map[string]accounts.Account{}, removed: map[string]bool{}}
	w.dbPath = filepath.Join(t.TempDir(), "rasputin.db")
	var err error
	if w.old, err = auth.OpenStore(t.Context(), w.dbPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.old.Close() })
	if w.store, err = OpenStore(t.Context(), w.dbPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.store.Close() })
	w.records = failingRecords{w: w, inner: w.store}
	w.log, w.rec = logkittest.New()
	if w.mover, err = New(w.deps()); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) deps() Deps {
	return Deps{Admin: fAdmin{w}, OldUsers: failingOld{w: w, inner: w.old}, Persons: fPersons{w}, Designations: fDes{w},
		Facts: fFacts{w}, Removed: fRemoved{w}, Ready: fReady{w}, Records: w.records, Lock: &sync.Mutex{},
		Realm: "rasputin", Now: func() time.Time { return time.UnixMilli(5_000_000) }, Log: w.log, StepTimeout: time.Minute}
}

// state is a State over the same collaborators.
func (w *world) state(t *testing.T) *State {
	t.Helper()
	s, err := NewState(failingOld{w: w, inner: w.old}, w.records, fPersons{w}, fRemoved{w})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// addOld adds a pre-update operator with a one-byte-distinct handle.
func (w *world) addOld(t *testing.T, h byte, name string, created int64) []byte {
	t.Helper()
	handle := make([]byte, 16)
	handle[15] = h
	if err := w.old.CreateUser(t.Context(), &auth.User{ID: handle, Name: name, DisplayName: "Old " + name,
		CreatedAt: time.Unix(created, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	return handle
}

// run runs the workflow's steps in order as the runner does, stopping at
// the first failure, and returns each step's result and the error.
func (w *world) run(t *testing.T, spec Spec) (map[string]json.RawMessage, error) {
	t.Helper()
	raw, _ := json.Marshal(spec)
	prior := map[string]json.RawMessage{}
	for _, st := range w.mover.Workflow().Steps {
		b, err := st.Do(&jobs.StepCtx{Ctx: t.Context(), JobID: "j1", Spec: raw, PriorResults: prior, CreatedBy: "scheduler"})
		if err != nil {
			return prior, err
		}
		prior[st.Name] = b
	}
	return prior, nil
}

// rowCount is the identity_move rows.
func (w *world) rowCount(t *testing.T) int {
	t.Helper()
	rs, err := w.store.Rows(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return len(rs)
}
