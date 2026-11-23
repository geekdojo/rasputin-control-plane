package markers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

const userID = "4f1c7a2e-user"

// fakeAdmin is one account over the Admin API.
type fakeAdmin struct {
	mu    sync.Mutex
	user  map[string]any
	roles []string
	creds []string
	puts  []map[string]any
	fail  error
}

func (f *fakeAdmin) Admin(_ context.Context, method, path string, in, out any) (idclient.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return idclient.Response{}, f.fail
	}
	rt := func(v any) error {
		b, _ := json.Marshal(v)
		return json.Unmarshal(b, out)
	}
	base := "/admin/realms/rasputin"
	switch {
	case method == http.MethodGet && path == base+"/users/"+userID:
		return idclient.Response{Status: 200}, rt(f.user)
	case method == http.MethodPut && path == base+"/users/"+userID:
		var b map[string]any
		raw, _ := json.Marshal(in)
		_ = json.Unmarshal(raw, &b)
		f.puts = append(f.puts, b)
		f.user["attributes"] = b["attributes"]
		return idclient.Response{Status: 204}, nil
	case method == http.MethodGet && path == base+"/users/"+userID+"/credentials":
		var list []map[string]string
		for _, c := range f.creds {
			list = append(list, map[string]string{"type": c})
		}
		return idclient.Response{Status: 200}, rt(list)
	case method == http.MethodGet && strings.HasPrefix(path, base+"/clients?clientId="):
		return idclient.Response{Status: 200}, rt([]map[string]string{{"id": "console-uuid"}})
	case method == http.MethodGet && path == base+"/users/"+userID+"/role-mappings/clients/console-uuid/composite":
		var list []map[string]string
		for _, r := range f.roles {
			list = append(list, map[string]string{"name": r})
		}
		return idclient.Response{Status: 200}, rt(list)
	}
	return idclient.Response{}, errors.New("unexpected " + method + " " + path)
}

func newUser() map[string]any {
	return map[string]any{"id": userID, "username": "ana", "email": "ana@x.invalid", "firstName": "Ana",
		"requiredActions": []any{"CONFIGURE_RECOVERY_AUTHN_CODES"}, "attributes": map[string]any{"pet": []any{"cat"}}}
}

func newWriter(t *testing.T, f *fakeAdmin) (*Writer, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	w, err := New(Deps{Admin: f, Realm: "rasputin", Log: log, DoorOf: func(c string) (flows.Door, bool) {
		switch c {
		case "rasputin-console":
			return flows.DoorHome, true
		case "rasputin-account":
			return flows.DoorApp, true
		}
		return "", false
	}})
	if err != nil {
		t.Fatal(err)
	}
	return w, rec
}

func markersOf(f *fakeAdmin) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	attrs, _ := f.user["attributes"].(map[string]any)
	var out []string
	for _, m := range flows.Markers {
		if vs, _ := attrs[m].([]any); len(vs) == 1 && vs[0] == "true" {
			out = append(out, m)
		}
	}
	slices.Sort(out)
	return out
}

func sorted(s ...string) []string { slices.Sort(s); return s }

// TC-987-36: the markers each credential event sets, for privileged and
// unprivileged accounts; what sets nothing; the unknown-client and Admin
// failure WARNs; the attribute map preserved; and the corrections count.
func TestUserEvent_Markers(t *testing.T) {
	cases := []struct {
		name, typ, cred, client string
		roles                   []string
		attrs                   map[string]any
		want                    []string
	}{
		{"home passkey", "UPDATE_CREDENTIAL", "webauthn-passwordless", "rasputin-console", nil, nil,
			sorted(flows.MarkerWebAuthnHome, flows.MarkerSecondStepHome, flows.MarkerSecondStepAny)},
		{"app security key", "UPDATE_CREDENTIAL", "webauthn", "rasputin-account", nil, nil,
			sorted(flows.MarkerWebAuthnApp, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny)},
		{"authenticator app", "UPDATE_TOTP", "otp", "rasputin-account", nil, nil,
			sorted(flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny)},
		{"authenticator app by UPDATE_CREDENTIAL", "UPDATE_CREDENTIAL", "otp", "rasputin-console", nil, nil,
			sorted(flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny)},
		{"console admin's home passkey", "UPDATE_CREDENTIAL", "webauthn-passwordless", "rasputin-console", []string{"admin"}, nil,
			sorted(flows.MarkerWebAuthnHome, flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny)},
		{"operator's app passkey", "UPDATE_CREDENTIAL", "webauthn", "rasputin-account", []string{"operator"}, nil,
			sorted(flows.MarkerWebAuthnApp, flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny)},
		{"app admin's passkey", "UPDATE_CREDENTIAL", "webauthn", "rasputin-console", nil, map[string]any{"rasputin_app_role": []any{"admin"}},
			sorted(flows.MarkerWebAuthnHome, flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny)},
		{"gear-admin's passkey", "UPDATE_CREDENTIAL", "webauthn", "rasputin-console", nil, map[string]any{"rasputin_network": []any{"gear-read", "gear-admin"}},
			sorted(flows.MarkerWebAuthnHome, flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny)},
		{"recovery codes", "UPDATE_CREDENTIAL", "recovery-authn-codes", "rasputin-console", []string{"admin"}, nil, nil},
		{"a password", "UPDATE_PASSWORD", "password", "rasputin-console", nil, nil, nil},
		{"a sign-in", "LOGIN", "", "rasputin-console", nil, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeAdmin{user: newUser(), roles: c.roles}
			for k, v := range c.attrs {
				f.user["attributes"].(map[string]any)[k] = v
			}
			w, _ := newWriter(t, f)
			w.UserEvent(t.Context(), events.UserEvent{Type: c.typ, CredentialType: c.cred, ClientID: c.client, UserID: userID})
			if got := markersOf(f); !slices.Equal(got, c.want) {
				t.Errorf("markers %v, want %v", got, c.want)
			}
			wantPuts := 0
			if len(c.want) > 0 {
				wantPuts = 1
			}
			if len(f.puts) != wantPuts || w.Corrections() != uint64(wantPuts) {
				t.Fatalf("%d PUTs, %d corrections, want %d", len(f.puts), w.Corrections(), wantPuts)
			}
			if wantPuts == 1 {
				put := f.puts[0]
				if _, ok := put["requiredActions"]; ok {
					t.Error("the PUT carries the required actions")
				}
				if put["username"] != "ana" || put["email"] != "ana@x.invalid" || put["firstName"] != "Ana" {
					t.Errorf("the PUT lost a profile field: %v", put)
				}
				if a := put["attributes"].(map[string]any); a["pet"] == nil {
					t.Error("an attribute the writer does not own was dropped")
				}
			}
			// The same event again changes nothing and is not a correction.
			w.UserEvent(t.Context(), events.UserEvent{Type: c.typ, CredentialType: c.cred, ClientID: c.client, UserID: userID})
			if w.Corrections() != uint64(wantPuts) {
				t.Errorf("a repeat counted as a correction")
			}
		})
	}

	f := &fakeAdmin{user: newUser()}
	w, rec := newWriter(t, f)
	for _, client := range []string{"", "some-app"} {
		w.UserEvent(t.Context(), events.UserEvent{Type: "UPDATE_CREDENTIAL", CredentialType: "webauthn", ClientID: client, UserID: userID})
	}
	if len(f.puts) != 0 || len(rec.Matching(slog.LevelWarn, "A passkey was stored at a client no door serves, so no marker was set.")) != 2 {
		t.Errorf("an unknown client wrote %d times:\n%s", len(f.puts), rec.Text())
	}

	f = &fakeAdmin{user: newUser(), fail: &idclient.Error{Op: "admin", Path: "/admin/realms/rasputin/users/" + userID, Status: 503, Kind: idclient.ErrUnreachable}}
	w, rec = newWriter(t, f)
	for range 3 {
		w.UserEvent(t.Context(), events.UserEvent{Type: "UPDATE_TOTP", CredentialType: "otp", ClientID: "rasputin-console", UserID: userID})
	}
	warns := rec.Matching(slog.LevelWarn, "A sign-in marker could not be written; the next credential event writes it.")
	if len(warns) != 1 || strings.Contains(rec.Text(), userID) {
		t.Errorf("%d WARNs, want 1, with no user id:\n%s", len(warns), rec.Text())
	}
	f.fail = nil
	w.UserEvent(t.Context(), events.UserEvent{Type: "UPDATE_TOTP", CredentialType: "otp", ClientID: "rasputin-console", UserID: userID})
	f.fail = errors.New("down again")
	w.UserEvent(t.Context(), events.UserEvent{Type: "UPDATE_TOTP", CredentialType: "otp", ClientID: "rasputin-console", UserID: userID})
	if n := len(rec.Matching(slog.LevelWarn, "A sign-in marker could not be written; the next credential event writes it.")); n != 2 {
		t.Errorf("%d WARNs over two outages, want 2", n)
	}
}

// TC-987-37: BeforePrivilege writes both doors' second-step markers and
// _any for an account holding an authenticator app or a passkey, refuses
// one holding none with ErrNoSecondStep, and wraps a read error; neither
// refusal writes.
func TestBeforePrivilege(t *testing.T) {
	for _, creds := range [][]string{{"password", "otp"}, {"webauthn"}, {"webauthn-passwordless", "recovery-authn-codes"}} {
		f := &fakeAdmin{user: newUser(), creds: creds}
		w, _ := newWriter(t, f)
		if err := w.BeforePrivilege(t.Context(), userID); err != nil {
			t.Fatalf("%v: %v", creds, err)
		}
		if got := markersOf(f); !slices.Equal(got, sorted(flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny)) {
			t.Errorf("%v: markers %v", creds, got)
		}
	}
	f := &fakeAdmin{user: newUser(), creds: []string{"password", "recovery-authn-codes"}}
	w, _ := newWriter(t, f)
	if err := w.BeforePrivilege(t.Context(), userID); !errors.Is(err, ErrNoSecondStep) || len(f.puts) != 0 {
		t.Errorf("no second step: %v, %d writes", err, len(f.puts))
	}
	down := errors.New("down")
	f = &fakeAdmin{user: newUser(), fail: down}
	w, _ = newWriter(t, f)
	if err := w.BeforePrivilege(t.Context(), userID); !errors.Is(err, down) || errors.Is(err, ErrNoSecondStep) {
		t.Errorf("a read error: %v", err)
	}
}

func TestNew_Refuses(t *testing.T) {
	log, _ := logkittest.New()
	good := Deps{Admin: &fakeAdmin{}, Realm: "r", DoorOf: func(string) (flows.Door, bool) { return "", false }, Log: log}
	for name, mut := range map[string]func(*Deps){
		"Admin": func(d *Deps) { d.Admin = nil }, "Realm": func(d *Deps) { d.Realm = "" },
		"DoorOf": func(d *Deps) { d.DoorOf = nil }, "Log": func(d *Deps) { d.Log = nil },
	} {
		d := good
		mut(&d)
		if _, err := New(d); err == nil {
			t.Errorf("New with no %s succeeded", name)
		}
	}
}
