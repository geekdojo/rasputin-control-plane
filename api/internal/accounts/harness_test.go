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
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
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
	// roles are the console roles held directly besides admin (each
	// role's users read lists them); creds are the credential types.
	roles []string
	creds []string
	// credIDs are the credentials' ids, beside creds; labels their
	// userLabels by id; sessions the online sessions' ids; locked is held
	// by attack detection.
	credIDs  []string
	labels   map[string]string
	sessions []string
	locked   bool
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
	// gets are every GET's realm-relative path, query included.
	gets []string
	// noID leaves the id out of the user list.
	noID bool
	// keepNothing answers a user PUT and keeps no attribute it carried.
	keepNothing bool
	// observe, when set, sees every call before it is answered, outside
	// the fake's lock, so it may block.
	observe func(method, rel string)
	// rows models the identity service's attribute rows
	// (geekdojo/geekdojo-brain#994; Keycloak 26.8.2's UserAdapter): a user
	// PUT compares each attribute with the rows as they stood when the call
	// began (before observe), and only where they differ deletes those rows
	// and inserts the new values, so two overlapping writes of one
	// attribute store it twice. A PUT carrying an admin-only single-valued
	// attribute more than once is refused with a 400, counted in rejected.
	rows     bool
	rejected int
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
	obs := k.observe
	snap := k.snapshot(method, path)
	k.mu.Unlock()
	if obs != nil {
		obs(method, strings.TrimPrefix(path, "/admin/realms/"+realm))
	}
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
	if tb, ok := in.(idclient.TextBody); ok {
		body = append([]byte("text/plain:"), secret.Value(tb).Reveal()...)
	} else if in != nil {
		body, _ = json.Marshal(in)
	}
	if method != http.MethodGet {
		k.reqs = append(k.reqs, request{method: method, path: rel, body: body})
	} else {
		k.gets = append(k.gets, rel)
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
	case parts[0] == "clients" && len(parts) == 4 && parts[2] == "roles":
		answer(out, map[string]any{"id": "role-" + parts[3], "name": parts[3]})
		return idclient.Response{Status: 200}, nil
	case parts[0] == "clients" && len(parts) == 5 && parts[4] == "users":
		var list []map[string]any
		if k.fullPage {
			for range adminPage {
				list = append(list, map[string]any{"enabled": true})
			}
		}
		for _, x := range k.users {
			if (parts[3] == "admin" && x.directAdmin) || slices.Contains(x.roles, parts[3]) {
				list = append(list, map[string]any{"id": x.rep["id"], "username": x.rep["username"], "enabled": x.rep["enabled"]})
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
	case parts[0] == "attack-detection" && method == http.MethodDelete:
		k.log.add("unlock")
		if x := k.users[parts[len(parts)-1]]; x != nil {
			x.locked = false
		}
		return idclient.Response{Status: 204}, nil
	case parts[0] == "sessions" && u.Query().Get("isOffline") != "true":
		k.log.add("session-delete:" + parts[1])
		for _, x := range k.users {
			x.sessions = slices.DeleteFunc(x.sessions, func(s string) bool { return s == parts[1] })
		}
		return idclient.Response{Status: 204}, nil
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
	case len(parts) == 1:
		k.list(u.Query(), out)
		return idclient.Response{Status: 200}, nil
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
		if snap != nil {
			attrs, _ := b["attributes"].(map[string]any)
			for name, multi := range flows.AdminOnlyAttributes {
				if vs, _ := attrs[name].([]any); !multi && len(vs) > 1 {
					k.rejected++
					return idclient.Response{Status: http.StatusBadRequest}, &idclient.Error{Op: "admin", Path: path, Status: http.StatusBadRequest, Kind: idclient.ErrProtocol}
				}
			}
			b["attributes"] = mergeRows(x.rep["attributes"], snap, attrs)
		}
		if e, ok := b["email"].(string); ok && e != x.rep["email"] {
			for id, o := range k.users {
				if id != parts[1] && strings.EqualFold(o.rep["email"].(string), e) {
					return idclient.Response{}, &idclient.Error{Op: "admin", Path: path, Status: http.StatusConflict, Kind: idclient.ErrConflict}
				}
			}
			k.log.add("set-email")
			x.rep["email"] = strings.ToLower(e)
		}
		if e, ok := b["enabled"].(bool); ok && !e && x.rep["enabled"] == true {
			k.log.add("disable")
			x.rep["enabled"] = false
		}
		if e, ok := b["enabled"].(bool); ok && e && x.rep["enabled"] == false {
			k.log.add("enable")
			x.rep["enabled"] = true
		}
		if ra, ok := b["requiredActions"].([]any); ok {
			k.log.add("set-actions")
			x.rep["requiredActions"] = ra
		}
		if n, ok := b["firstName"].(string); ok && n != x.rep["firstName"] {
			k.log.add("set-name")
			x.rep["firstName"] = n
		}
		before, after := roleOf(x.rep["attributes"]), roleOf(b["attributes"])
		switch {
		case before != "" && after == "":
			k.log.add("remove-attr")
		case after != before:
			k.log.add("set-attr:" + after)
		}
		for _, a := range []string{AttrNetwork, "rasputin_email"} {
			if bv, av := attrOf(x.rep["attributes"], a), attrOf(b["attributes"], a); bv != av {
				k.log.add("set-" + a + ":" + av)
			}
		}
		if !k.keepNothing {
			x.rep["attributes"] = b["attributes"]
		}
	case tail == "" && method == http.MethodDelete:
		k.log.add("delete-user")
		delete(k.users, parts[1])
	case tail == "logout":
		k.log.add("logout")
	case tail == "reset-password" && method == http.MethodPut:
		k.log.add("reset-password")
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
	case tail == "credentials" && method == http.MethodGet:
		var list []map[string]string
		for i, c := range x.creds {
			list = append(list, map[string]string{"id": x.credIDs[i], "type": c})
		}
		answer(out, list)
	case strings.HasPrefix(tail, "credentials/") && len(parts) == 4 && method == http.MethodDelete:
		i := slices.Index(x.credIDs, parts[3])
		if i < 0 {
			return idclient.Response{}, notFound(path)
		}
		k.log.add("delete-credential:" + x.creds[i])
		x.creds, x.credIDs = slices.Delete(x.creds, i, i+1), slices.Delete(x.credIDs, i, i+1)
	case strings.HasPrefix(tail, "credentials/") && len(parts) == 5 && parts[4] == "userLabel":
		if !slices.Contains(x.credIDs, parts[3]) {
			return idclient.Response{}, notFound(path)
		}
		k.log.add("rename-credential")
		if x.labels == nil {
			x.labels = map[string]string{}
		}
		x.labels[parts[3]] = string(body)
	case tail == "sessions" && method == http.MethodGet:
		var list []map[string]string
		for _, s := range x.sessions {
			list = append(list, map[string]string{"id": s})
		}
		answer(out, list)
	case tail == "role-mappings/clients/"+consoleUUID && method == http.MethodGet:
		var list []map[string]string
		for _, r := range x.console {
			list = append(list, map[string]string{"name": r})
		}
		answer(out, list)
	case tail == "role-mappings/clients/"+consoleUUID && method == http.MethodDelete:
		var reps []map[string]any
		_ = json.Unmarshal(body, &reps)
		for _, r := range reps {
			name, _ := r["name"].(string)
			k.log.add("remove-console:" + name)
			x.console = slices.DeleteFunc(x.console, func(c string) bool { return c == name })
			x.roles = slices.DeleteFunc(x.roles, func(c string) bool { return c == name })
			if name == "admin" {
				x.directAdmin = false
			}
		}
	case tail == "role-mappings/clients/"+consoleUUID && method == http.MethodPost:
		var reps []map[string]any
		_ = json.Unmarshal(body, &reps)
		for _, r := range reps {
			name, _ := r["name"].(string)
			k.log.add("add-console:" + name)
			x.console = append(x.console, name)
			// The role's holders list it from now on, as the identity
			// service's does.
			x.roles = append(x.roles, name)
		}
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

// snapshot is, under rows, a user PUT's account attributes as they stand
// when the call begins: the rows its transaction loads. Otherwise nil.
func (k *fakeKC) snapshot(method, path string) map[string]any {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/admin/realms/"+realm), "/"), "/")
	if !k.rows || method != http.MethodPut || len(parts) != 2 || parts[0] != "users" || k.users[parts[1]] == nil {
		return nil
	}
	return cloneAttrs(k.users[parts[1]].rep["attributes"])
}

func cloneAttrs(attrs any) map[string]any {
	m, _ := attrs.(map[string]any)
	out := map[string]any{}
	for name, v := range m {
		vs, _ := v.([]any)
		out[name] = slices.Clone(vs)
	}
	return out
}

// mergeRows is what a user PUT leaves under rows: for each attribute whose
// new values differ from snap (the rows the call loaded), the rows snap
// held are deleted from cur and the new values inserted; an attribute
// whose values equal snap is left as cur holds it.
func mergeRows(cur any, snap, body map[string]any) map[string]any {
	out := cloneAttrs(cur)
	names := map[string]bool{}
	for n := range snap {
		names[n] = true
	}
	for n := range body {
		names[n] = true
	}
	for n := range names {
		old, _ := snap[n].([]any)
		nw, _ := body[n].([]any)
		if slices.Equal(old, nw) {
			continue
		}
		vs, _ := out[n].([]any)
		for _, o := range old {
			if i := slices.Index(vs, o); i >= 0 {
				vs = slices.Delete(vs, i, i+1)
			}
		}
		vs = append(vs, nw...)
		if len(vs) == 0 {
			delete(out, n)
			continue
		}
		out[n] = vs
	}
	return out
}

// list answers the users listing: by exact email, or every account in
// creation order with createdTimestamp, as the identity service does.
func (k *fakeKC) list(q url.Values, out any) {
	var list []map[string]any
	for _, x := range k.users {
		if e := q.Get("email"); q.Has("email") && !strings.EqualFold(e, x.rep["email"].(string)) {
			continue
		}
		rep := map[string]any{}
		for key, v := range x.rep {
			rep[key] = v
		}
		if k.noID {
			delete(rep, "id")
		}
		list = append(list, rep)
	}
	if m, err := strconv.Atoi(q.Get("max")); err == nil && len(list) > m {
		list = list[:m]
	}
	answer(out, list)
}

// attrOf is an attribute's values, joined by commas.
func attrOf(attrs any, name string) string {
	m, _ := attrs.(map[string]any)
	vs, _ := m[name].([]any)
	var out []string
	for _, v := range vs {
		s, _ := v.(string)
		out = append(out, s)
	}
	return strings.Join(out, ",")
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
	// roles are direct console roles besides admin; creds the credential
	// types; created the createdTimestamp; actions the required actions
	// (nil seeds CONFIGURE_TOTP).
	roles       []string
	creds       []string
	created     int64
	actions     []any
	appRole     string
	offlineRole bool
	offline     map[string][]string
	// network is the network grants; sessions the online sessions.
	network  []string
	sessions []string
}

func (k *fakeKC) add(p person) {
	k.mu.Lock()
	defer k.mu.Unlock()
	attrs := map[string]any{"rasputin_second_step_any": []any{"true"}}
	if p.appRole != "" {
		attrs[AttrAppRole] = []any{p.appRole}
	}
	if len(p.network) > 0 {
		var vs []any
		for _, g := range p.network {
			vs = append(vs, g)
		}
		attrs[AttrNetwork] = vs
	}
	actions := p.actions
	if actions == nil {
		actions = []any{"CONFIGURE_TOTP"}
	}
	u := &kcUser{rep: map[string]any{"id": p.sub, "username": p.name, "email": p.email, "firstName": "Test",
		"enabled": p.enabled, "attributes": attrs, "requiredActions": actions, "createdTimestamp": p.created},
		console: p.console, directAdmin: p.directAdmin, offline: map[string][]string{}, roles: p.roles, creds: slices.Clone(p.creds),
		sessions: slices.Clone(p.sessions)}
	for i, c := range p.creds {
		u.credIDs = append(u.credIDs, "id-"+c+"-"+strconv.Itoa(i))
	}
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

// countingLock is the one accounts lock, counting the callers waiting for
// it: the fact a lock test waits on.
type countingLock struct {
	mu      sync.Mutex
	waiting atomic.Int32
}

func (l *countingLock) Lock() {
	l.waiting.Add(1)
	l.mu.Lock()
	l.waiting.Add(-1)
}

func (l *countingLock) Unlock() { l.mu.Unlock() }

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

func (c recConsole) EndBySubExcept(ctx context.Context, sub, sid string) (int64, error) {
	c.log.add("console-except:" + sid)
	return c.inner.EndBySubExcept(ctx, sub, sid)
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
	kc           *fakeKC
	log          *callLog
	users        *Users
	rev          *Revoker
	access       *Access
	runner       *jobs.Runner
	jobs         *jobs.Store
	auth         *auth.Store
	console      *auth.ConsoleSessions
	designations *Designations
	removed      *removednames.Store
	list         *recList
	facts        *recFacts
	hooks        map[string]*recHook
	rec          *logkittest.Recorder
	sessions     sessions.Ender
	mac          *credmac.Key
	nc           *nats.Conn
	// lock is the one accounts lock; guard the real guard over it.
	lock  *countingLock
	guard *authz.RoleGuard
	ra    RoleAccounts
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
	if h.designations, err = OpenDesignations(t.Context(), filepath.Join(dir, "rasputin.db"), time.Now); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.designations.Close() })
	if h.console, err = auth.NewConsoleSessions(h.auth, time.Now, rand.Reader, h.designations); err != nil {
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
	h.ra = ra
	h.lock = &countingLock{}
	lock := h.lock
	h.guard, err = authz.NewRoleGuard(ra, lock)
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
		Sessions: h.sessions, Users: h.users, Guard: recGuard{inner: h.guard, log: h.log}, Lock: lock,
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
	h.nc = nc
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
