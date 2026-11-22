package converge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

const (
	testRealm  = "rasputin"
	realmPath  = "/admin/realms/rasputin"
	secretText = "s3cr3t-client-secret-value"
	redirectA  = "https://console.home.example/oidc/callback"
)

var testNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// call is one Admin API request the fake saw, its body as JSON.
type call struct {
	method, path string
	body         []byte
}

// fakeKC is the Admin API over one realm in memory. Writes are applied as
// Keycloak applies them: a realm PUT sets each field it carries and replaces
// the attributes map; a client PUT sets each field it carries.
type fakeKC struct {
	mu       sync.Mutex
	realm    map[string]any
	clients  []map[string]any
	keys     []map[string]any
	features []map[string]any
	calls    []call
	// fail maps "METHOD path" to the error that call answers; failOn,
	// when set, decides per call (n counts calls of that method and path).
	fail   map[string]error
	failOn func(method, path string, n int) error
	seen   map[string]int
	// ignoreWrites drops every write, so the read-back still differs.
	ignoreWrites bool
	// lock, when set, is the realm lock; calls made without it are counted.
	lock     *sync.Mutex
	unlocked int
}

// convergedRealm is a realm in the state converge wants, with install name
// "Test Home", as Keycloak answers GET for it.
func convergedRealm() map[string]any {
	return map[string]any{
		"id": "realm-uuid-1", "realm": testRealm, "displayName": "Test Home",
		"eventsEnabled": true, "eventsListeners": []any{}, "enabledEventTypes": toAny(AuditEventTypes),
		"eventsExpiration": 2592000, "adminEventsEnabled": true, "adminEventsDetailsEnabled": false,
		"smtpServer":                 map[string]any{},
		"attributes":                 map[string]any{"CreateDefaultClientScopes": "true", "cibaExpiresIn": "120", "adminEventsExpiration": "2592000"},
		"webAuthnPolicyRpEntityName": "keycloak", "webAuthnPolicyRpId": "", "webAuthnPolicyUserVerificationRequirement": "required",
		"webAuthnPolicyResidentKey": "Required", "webAuthnPolicySignatureAlgorithms": []any{"ES256", "RS256"}, "webAuthnPolicyCreateTimeout": 0,
		"webAuthnPolicyPasswordlessRpEntityName": "keycloak", "webAuthnPolicyPasswordlessRpId": "",
		"webAuthnPolicyPasswordlessUserVerificationRequirement": "required", "webAuthnPolicyPasswordlessResidentKey": "Required",
		"webAuthnPolicyPasswordlessPasskeysEnabled": true,
		"bruteForceProtected":                       true,
	}
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// convergedClients are the realm's clients in the wanted state, with the
// mesh client holding a secret.
func convergedClients() []map[string]any {
	var out []map[string]any
	for i, id := range DefaultClients {
		c := map[string]any{"id": fmt.Sprintf("c-default-%d", i), "clientId": id, "enabled": false}
		if id == "admin-cli" {
			c["directAccessGrantsEnabled"] = false
		}
		out = append(out, c)
	}
	for i, id := range RasputinClients {
		c := map[string]any{"id": fmt.Sprintf("c-rasputin-%d", i), "clientId": id, "enabled": true, "redirectUris": []any{}}
		if id == "rasputin-mesh" {
			c["secret"] = secretText
		}
		out = append(out, c)
	}
	return out
}

func convergedKeys() []map[string]any {
	var out []map[string]any
	for i, n := range KeyProviders {
		out = append(out, map[string]any{"id": fmt.Sprintf("k-%d", i), "name": n, "providerId": n})
	}
	return out
}

func newFakeKC() *fakeKC {
	return &fakeKC{realm: convergedRealm(), clients: convergedClients(), keys: convergedKeys(), fail: map[string]error{}, seen: map[string]int{}}
}

func roundTrip(v any, out any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func (f *fakeKC) Admin(_ context.Context, method, path string, in, out any) (idclient.Response, error) {
	if f.lock != nil && f.lock.TryLock() {
		f.lock.Unlock()
		f.mu.Lock()
		f.unlocked++
		f.mu.Unlock()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	f.calls = append(f.calls, call{method, path, body})
	key := method + " " + path
	f.seen[key]++
	if err := f.fail[key]; err != nil {
		return idclient.Response{}, err
	}
	if f.failOn != nil {
		if err := f.failOn(method, path, f.seen[key]); err != nil {
			return idclient.Response{}, err
		}
	}
	switch {
	case method == http.MethodGet && path == realmPath:
		return idclient.Response{Status: 200}, roundTrip(f.realm, out)
	case method == http.MethodGet && path == realmPath+"/clients":
		return idclient.Response{Status: 200}, roundTrip(f.clients, out)
	case method == http.MethodGet && strings.HasPrefix(path, realmPath+"/components?type="):
		return idclient.Response{Status: 200}, roundTrip(f.keys, out)
	case method == http.MethodGet && path == "/admin/serverinfo":
		return idclient.Response{Status: 200}, roundTrip(map[string]any{"features": f.features}, out)
	case method == http.MethodPut && path == realmPath:
		if f.ignoreWrites {
			return idclient.Response{Status: 204}, nil
		}
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		for k, v := range b {
			f.realm[k] = v
		}
		return idclient.Response{Status: 204}, nil
	case method == http.MethodPut && strings.HasPrefix(path, realmPath+"/clients/"):
		id := strings.TrimPrefix(path, realmPath+"/clients/")
		for _, c := range f.clients {
			if c["id"] == id {
				if !f.ignoreWrites {
					var b map[string]any
					_ = json.Unmarshal(body, &b)
					for k, v := range b {
						c[k] = v
					}
				}
				return idclient.Response{Status: 204}, nil
			}
		}
		return idclient.Response{}, &idclient.Error{Op: "admin", Path: path, Kind: idclient.ErrNotFound}
	case method == http.MethodDelete && strings.HasPrefix(path, realmPath+"/components/"):
		id := strings.TrimPrefix(path, realmPath+"/components/")
		if f.ignoreWrites {
			return idclient.Response{Status: 204}, nil
		}
		for i, k := range f.keys {
			if k["id"] == id {
				f.keys = append(f.keys[:i], f.keys[i+1:]...)
				return idclient.Response{Status: 204}, nil
			}
		}
		return idclient.Response{}, &idclient.Error{Op: "admin", Path: path, Kind: idclient.ErrNotFound}
	}
	return idclient.Response{}, errors.New("fakeKC: unexpected " + key)
}

// writes are the calls that change something.
func (f *fakeKC) writes() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.method != http.MethodGet {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeKC) client(id string) map[string]any {
	for _, c := range f.clients {
		if c["clientId"] == id {
			return c
		}
	}
	return nil
}

// memSettings is the settings store in memory.
type memSettings struct {
	mu     sync.Mutex
	m      map[string]string
	getErr error
	setErr error
}

func (s *memSettings) Get(_ context.Context, k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k], s.getErr
}

func (s *memSettings) Set(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setErr != nil {
		return s.setErr
	}
	s.m[k] = v
	return nil
}

// rig is a Converger over a fakeKC and memSettings.
type rig struct {
	kc       *fakeKC
	settings *memSettings
	inputs   Inputs
	c        *Converger
	rec      *logkittest.Recorder
	lock     *sync.Mutex
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{kc: newFakeKC(), settings: &memSettings{m: map[string]string{}}, inputs: Inputs{InstallName: "Test Home"}, lock: &sync.Mutex{}}
	r.kc.lock = r.lock
	log, rec := logkittest.New()
	r.rec = rec
	c, err := New(Deps{
		Admin: r.kc, Settings: r.settings, Realm: testRealm, Lock: r.lock,
		Inputs: func(context.Context) (Inputs, error) { return r.inputs, nil },
		Now:    func() time.Time { return testNow }, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
	return r
}

// stored is the hash the current inputs want, stored as though converge
// had reached it.
func (r *rig) storeHash() { r.settings.m[HashKey] = NewDesired(r.inputs).Hash() }
