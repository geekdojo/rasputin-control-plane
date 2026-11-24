package accounts

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/sessions"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// The identity service is faked at the Admin API seam only (the CI cases in
// identitytest run the real one). Users, sessions.Ender, RoleAccounts and
// authz.RoleGuard are the real ones over it; the stores are real sqlite; the
// job runs on the real jobs.Runner.

const (
	realm         = "rasputin"
	consoleClient = "rasputin-console"
	consoleUUID   = "console-uuid"
	appUUID       = "app-uuid"
)

// testKey is a low-entropy fixture key of the shortest accepted length.
var testKey = strings.Repeat("k", credmac.MinKeyLen)

// callLog is the one ordered record of every effect: the identity
// service's writes, the guard's decisions, and the api's own collaborators.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *callLog) add(c string) {
	l.mu.Lock()
	l.calls = append(l.calls, c)
	l.mu.Unlock()
}

func (l *callLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.calls)
}

// only is the log filtered to the calls in keep (by prefix).
func (l *callLog) only(keep ...string) []string {
	var out []string
	for _, c := range l.all() {
		if slices.ContainsFunc(keep, func(k string) bool { return strings.HasPrefix(c, k) }) {
			out = append(out, c)
		}
	}
	return out
}

type kcUser struct {
	rep     map[string]any
	console []string
	// directAdmin is holding admin as a direct mapping, which the role's
	// users read lists; a composite holding does not appear there.
	directAdmin bool
	realm       []string
	offline     map[string][]string
}

// request is one write's method, path (realm-relative) and body.
type request struct {
	method, path string
	body         []byte
}

// fakeKC is the identity service's Admin API, in memory.
type fakeKC struct {
	mu       sync.Mutex
	users    map[string]*kcUser
	log      *callLog
	reqs     []request
	fullPage bool
	// adminRows is how many rows the last administrators read answered.
	adminRows int
	// fail returns an error for a call, by method and realm-relative path.
	fail func(method, path string) error
}

func notFound(path string) error {
	return &idclient.Error{Op: "admin", Path: path, Status: http.StatusNotFound, Kind: idclient.ErrNotFound}
}

func answer(out, v any) {
	if out == nil {
		return
	}
	b, _ := json.Marshal(v)
	_ = json.Unmarshal(b, out)
}

func (k *fakeKC) Admin(_ context.Context, method, path string, in, out any) (idclient.Response, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	rel, ok := strings.CutPrefix(path, "/admin/realms/"+realm)
	if !ok {
		return idclient.Response{}, errors.New("fake: not the realm")
	}
	if k.fail != nil {
		if err := k.fail(method, rel); err != nil {
			return idclient.Response{}, err
		}
	}
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	if method != http.MethodGet {
		k.reqs = append(k.reqs, request{method: method, path: rel, body: body})
	}
	u, _ := url.Parse(rel)
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	switch {
	case parts[0] == "clients" && len(parts) == 1:
		if u.Query().Get("clientId") == consoleClient {
			answer(out, []map[string]string{{"id": consoleUUID}})
		} else {
			answer(out, []map[string]string{{"id": consoleUUID}, {"id": appUUID}})
		}
		return idclient.Response{Status: 200}, nil
	case parts[0] == "clients" && len(parts) == 5 && parts[4] == "users":
		var list []map[string]any
		if k.fullPage {
			for range adminPage {
				list = append(list, map[string]any{"enabled": true})
			}
		}
		for _, x := range k.users {
			if x.directAdmin {
				list = append(list, map[string]any{"enabled": x.rep["enabled"]})
			}
		}
		// Honour max= as the identity service does: never more rows than asked.
		if m, err := strconv.Atoi(u.Query().Get("max")); err == nil && len(list) > m {
			list = list[:m]
		}
		k.adminRows = len(list)
		answer(out, list)
		return idclient.Response{Status: 200}, nil
	case parts[0] == "roles":
		answer(out, map[string]any{"id": "offline-role-id", "name": offlineAccess})
		return idclient.Response{Status: 200}, nil
	case parts[0] == "sessions":
		k.log.add("offline-delete:" + parts[1])
		for _, x := range k.users {
			for c, ss := range x.offline {
				x.offline[c] = slices.DeleteFunc(ss, func(s string) bool { return s == parts[1] })
			}
		}
		return idclient.Response{Status: 204}, nil
	case parts[0] != "users":
		return idclient.Response{}, errors.New("fake: unknown path " + rel)
	}
	x := k.users[parts[1]]
	if x == nil {
		return idclient.Response{}, notFound(path)
	}
	tail := strings.Join(parts[2:], "/")
	switch {
	case tail == "" && method == http.MethodGet:
		answer(out, x.rep)
	case tail == "" && method == http.MethodPut:
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		if e, ok := b["enabled"].(bool); ok && !e && x.rep["enabled"] == true {
			k.log.add("disable")
			x.rep["enabled"] = false
		}
		before, after := roleOf(x.rep["attributes"]), roleOf(b["attributes"])
		switch {
		case before != "" && after == "":
			k.log.add("remove-attr")
		case after != before:
			k.log.add("set-attr:" + after)
		}
		x.rep["attributes"] = b["attributes"]
	case tail == "" && method == http.MethodDelete:
		k.log.add("delete-user")
		delete(k.users, parts[1])
	case tail == "logout":
		k.log.add("logout")
	case strings.HasPrefix(tail, "offline-sessions/"):
		var list []map[string]string
		for _, s := range x.offline[parts[3]] {
			list = append(list, map[string]string{"id": s})
		}
		answer(out, list)
	case tail == "role-mappings/clients/"+consoleUUID+"/composite":
		var list []map[string]string
		for _, r := range x.console {
			list = append(list, map[string]string{"name": r})
		}
		answer(out, list)
	case tail == "role-mappings/realm" && method == http.MethodGet:
		var list []map[string]string
		for _, r := range x.realm {
			list = append(list, map[string]string{"name": r})
		}
		answer(out, list)
	case tail == "role-mappings/realm" && method == http.MethodPost:
		k.log.add("add-offline")
		x.realm = append(x.realm, offlineAccess)
	case tail == "role-mappings/realm" && method == http.MethodDelete:
		k.log.add("remove-offline")
		x.realm = slices.DeleteFunc(x.realm, func(r string) bool { return r == offlineAccess })
	default:
		return idclient.Response{}, errors.New("fake: unknown path " + rel)
	}
	return idclient.Response{Status: 200}, nil
}

func roleOf(attrs any) string {
	m, _ := attrs.(map[string]any)
	vs, _ := m[AttrAppRole].([]any)
	if len(vs) == 0 {
		return ""
	}
	s, _ := vs[0].(string)
	return s
}

// person describes a seeded account.
type person struct {
	sub, name, email string
	enabled          bool
	console          []string
	directAdmin      bool
	appRole          string
	offlineRole      bool
	offline          map[string][]string
}

func (k *fakeKC) add(p person) {
	k.mu.Lock()
	defer k.mu.Unlock()
	attrs := map[string]any{"rasputin_second_step_any": []any{"true"}}
	if p.appRole != "" {
		attrs[AttrAppRole] = []any{p.appRole}
	}
	u := &kcUser{rep: map[string]any{"id": p.sub, "username": p.name, "email": p.email, "firstName": "Test",
		"enabled": p.enabled, "attributes": attrs, "requiredActions": []any{"CONFIGURE_TOTP"}},
		console: p.console, directAdmin: p.directAdmin, offline: map[string][]string{}}
	if p.offlineRole {
		u.realm = []string{offlineAccess}
	}
	for c, ss := range p.offline {
		u.offline[c] = slices.Clone(ss)
	}
	k.users[p.sub] = u
}

func (k *fakeKC) enabled(sub string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	u := k.users[sub]
	return u != nil && u.rep["enabled"] == true
}

func (k *fakeKC) exists(sub string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.users[sub] != nil
}

// ---- the recording collaborators -------------------------------------------

type recGuard struct {
	inner *authz.RoleGuard
	log   *callLog
}

func (g recGuard) Change(ctx context.Context, actor string, ch authz.RoleChange, apply func(context.Context, authz.Decision) error) (authz.Decision, error) {
	g.log.add("guard")
	return g.inner.Change(ctx, actor, ch, apply)
}

type recConsole struct {
	inner *auth.ConsoleSessions
	log   *callLog
}

func (c recConsole) EndBySub(ctx context.Context, sub string) (int64, error) {
	c.log.add("console")
	return c.inner.EndBySub(ctx, sub)
}

type recMoved struct {
	inner *auth.Store
	log   *callLog
}

func (m recMoved) RemoveMovedRows(ctx context.Context, sub string) (int64, int64, error) {
	m.log.add("moved")
	return m.inner.RemoveMovedRows(ctx, sub)
}

type recList struct {
	inner NameRecorder
	log   *callLog
	err   error
}

func (l *recList) Record(ctx context.Context, name, email string) error {
	l.log.add("list")
	if l.err != nil {
		return l.err
	}
	return l.inner.Record(ctx, name, email)
}

type recFacts struct {
	inner removednames.AccessFacts
	log   *callLog
	err   error
}

func (f *recFacts) Record(ctx context.Context, sub string) error {
	f.log.add("fact")
	if f.err != nil {
		return f.err
	}
	return f.inner.Record(ctx, sub)
}

func (f *recFacts) Held(ctx context.Context, sub string) (bool, error) { return f.inner.Held(ctx, sub) }

type recHook struct {
	name string
	log  *callLog
	out  Outcome
	err  error
}

func (h *recHook) Revoke(_ context.Context, _ string, _ RevokeKind) (Outcome, error) {
	h.log.add(h.name)
	return h.out, h.err
}

// ---- the harness -----------------------------------------------------------

type harness struct {
	kc       *fakeKC
	log      *callLog
	users    *Users
	rev      *Revoker
	access   *Access
	runner   *jobs.Runner
	jobs     *jobs.Store
	auth     *auth.Store
	console  *auth.ConsoleSessions
	removed  *removednames.Store
	list     *recList
	facts    *recFacts
	hooks    map[string]*recHook
	rec      *logkittest.Recorder
	sessions sessions.Ender
	mac      *credmac.Key
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{log: &callLog{}}
	h.kc = &fakeKC{users: map[string]*kcUser{}, log: h.log}
	dir := t.TempDir()
	var err error
	if h.jobs, err = jobs.OpenStore(t.Context(), filepath.Join(dir, "rasputin.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.jobs.Close() })
	if h.auth, err = auth.OpenStore(t.Context(), filepath.Join(dir, "rasputin.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.auth.Close() })
	if h.console, err = auth.NewConsoleSessions(h.auth, time.Now, rand.Reader); err != nil {
		t.Fatal(err)
	}
	if h.mac, err = credmac.New(secret.New([]byte(testKey))); err != nil {
		t.Fatal(err)
	}
	storeLog, _ := logkittest.New()
	if h.removed, err = removednames.OpenStore(t.Context(), filepath.Join(dir, "rasputin.db"), h.mac, storeLog); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.removed.Close() })
	if h.users, err = NewUsers(UsersDeps{Admin: h.kc, Realm: realm, ConsoleClient: consoleClient}); err != nil {
		t.Fatal(err)
	}
	ra, err := NewRoleAccounts(h.users)
	if err != nil {
		t.Fatal(err)
	}
	lock := &sync.Mutex{}
	guard, err := authz.NewRoleGuard(ra, lock)
	if err != nil {
		t.Fatal(err)
	}
	h.sessions = sessions.Ender{Admin: h.kc}
	h.list = &recList{inner: h.removed, log: h.log}
	h.facts = &recFacts{inner: h.removed.Facts(), log: h.log}
	h.hooks = map[string]*recHook{}
	for _, n := range []string{StepDevices, StepApps, StepNetwork} {
		h.hooks[n] = &recHook{name: n, log: h.log, out: Outcome{Outcome: "done"}}
	}
	var log *logkittest.Recorder
	slogger, log := logkittest.New()
	h.rec = log
	if h.rev, err = NewRevoker(RevokerDeps{
		Sessions: h.sessions, Users: h.users, Guard: recGuard{inner: guard, log: h.log}, Lock: lock,
		Console: recConsole{inner: h.console, log: h.log}, Moved: recMoved{inner: h.auth, log: h.log},
		Removed: h.list, Facts: h.facts, Devices: h.hooks[StepDevices], Apps: h.hooks[StepApps], Network: h.hooks[StepNetwork],
		Log: slogger, StepTimeout: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	if h.access, err = NewAccess(AccessDeps{Users: h.users, Sessions: h.sessions, Facts: h.facts, Lock: lock}); err != nil {
		t.Fatal(err)
	}
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	h.runner = jobs.NewRunner(h.jobs, nc)
	h.runner.Register(h.rev.Workflow())
	return h
}

// The seeded world: two enabled administrators, and a target with app
// access, offline_access and an offline session at each of two clients.
const (
	adminA = "admin-a"
	adminB = "admin-b"
	target = "target-sub"
)

func (h *harness) world() {
	h.kc.add(person{sub: adminA, name: "admina", email: "a@example.invalid", enabled: true, console: []string{"admin"}, directAdmin: true})
	h.kc.add(person{sub: adminB, name: "adminb", email: "b@example.invalid", enabled: true, console: []string{"admin"}, directAdmin: true})
	h.kc.add(person{sub: target, name: "targetname", email: "target@example.invalid", enabled: true, console: []string{"viewer"},
		appRole: "user", offlineRole: true, offline: map[string][]string{consoleUUID: {"s1"}, appUUID: {"s2"}}})
}

// result is one job's record.
type result struct {
	job   *jobs.Job
	steps []*jobs.JobStep
}

// outcome is a step's recorded outcome field.
func (r result) outcome(t *testing.T, step string) string {
	t.Helper()
	for _, s := range r.steps {
		if s.Name == step {
			var o struct {
				Outcome string `json:"outcome"`
			}
			_ = json.Unmarshal(s.Result, &o)
			return o.Outcome
		}
	}
	return ""
}

func (r result) step(name string) *jobs.JobStep {
	for _, s := range r.steps {
		if s.Name == name {
			return s
		}
	}
	return nil
}

func (h *harness) submit(t *testing.T, spec Spec, by string) string {
	t.Helper()
	j, err := h.runner.Submit(t.Context(), Kind, spec, by)
	if err != nil {
		t.Fatal(err)
	}
	return j.ID
}

func (h *harness) result(t *testing.T, id string) result {
	t.Helper()
	j, err := h.jobs.GetJob(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := h.jobs.ListSteps(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return result{job: j, steps: steps}
}

// run submits one identity.revoke and waits for it to finish.
func (h *harness) run(t *testing.T, spec Spec, by string) result {
	t.Helper()
	id := h.submit(t, spec, by)
	h.runner.Wait()
	return h.result(t, id)
}

// effects are the calls that change something, in order.
func (h *harness) effects() []string {
	return h.log.only("guard", "logout", "offline-delete", "disable", "delete-user", "set-attr", "remove-attr",
		"add-offline", "remove-offline", "console", "moved", "list", "fact", StepDevices, StepApps, StepNetwork)
}
