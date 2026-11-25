package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/sessions"
)

// recordingAdmin records each Admin API call the ender makes.
type recordingAdmin struct{ calls []string }

func (a *recordingAdmin) Admin(_ context.Context, method, path string, _, _ any) (idclient.Response, error) {
	a.calls = append(a.calls, method+" "+path)
	return idclient.Response{Status: http.StatusNoContent}, nil
}

type readyNow struct{}

func (readyNow) Ready(context.Context) error { return nil }

func consoleAuth(t *testing.T) (*auth.Service, *auth.ConsoleSessions) {
	t.Helper()
	store, err := auth.OpenStore(t.Context(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	sessions, err := auth.NewConsoleSessions(store, time.Now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := auth.NewService(store, auth.Config{RPID: "ci.local", RPOrigins: []string{"https://ci.local"}, Sessions: sessions})
	if err != nil {
		t.Fatal(err)
	}
	return svc, sessions
}

// TC-989-03: the sign-in is built only under keycloak with the doors on.
// In every other combination nothing is built, so /api/auth/signin is
// unavailable, status says ready:false and a gated route answers 401.
func TestConsoleSignInWiring_OnlyUnderKeycloakWithDoors(t *testing.T) {
	table, err := doors.New("ci")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{identityModeOff, identityModeMock, identityModeKeycloak} {
		for _, doorsOn := range []bool{false, true} {
			svc, sessions := consoleAuth(t)
			w, err := consoleSignInWiring(t.Context(), consoleSignInDeps{mode: mode, doorsOn: doorsOn, table: table, host: "ci.local",
				client: idclient.Disabled{Kind: idclient.ErrDisabled}, session: &recordingAdmin{}, ready: readyNow{},
				sessions: sessions, identity: sessionsEnder(), now: time.Now, log: slog.New(slog.DiscardHandler)})
			if err != nil {
				t.Fatalf("%s doors=%v: %v", mode, doorsOn, err)
			}
			built := mode == identityModeKeycloak && doorsOn
			if (w.signIn != nil) != built || (w.sink != nil) != built || (w.resetHome != nil) != built || (w.appResetDone() != nil) != built {
				t.Errorf("%s doors=%v: built sign-in %v sink %v resets %v %v, want %v", mode, doorsOn, w.signIn != nil, w.sink != nil,
					w.resetHome != nil, w.appResetDone() != nil, built)
			}
			w.install(svc)
			mux := http.NewServeMux()
			svc.RegisterRoutes(mux)
			mux.Handle("GET /api/nodes", svc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
			req := func(path string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodGet, "https://ci.local"+path, nil)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, r)
				return rec
			}
			var st map[string]any
			_ = json.Unmarshal(req("/api/auth/status").Body.Bytes(), &st)
			if st["ready"] != built {
				t.Errorf("%s doors=%v: status ready = %v", mode, doorsOn, st["ready"])
			}
			if !built {
				if loc := req("/api/auth/signin").Header().Get("Location"); loc != "/login?signin=unavailable" {
					t.Errorf("%s doors=%v: signin -> %s", mode, doorsOn, loc)
				}
			}
			// The console's reset return is installed with the sign-in: the
			// disabled client refuses the exchange, so a built one answers
			// reset-failed through ResetDone, and an unbuilt one the same
			// answer from the route itself.
			if loc := req("/api/auth/reset-done?code=c&iss=" + table.Home.Issuer).Header().Get("Location"); loc != "/login?signin=reset-failed" {
				t.Errorf("%s doors=%v: reset-done -> %s", mode, doorsOn, loc)
			}
			if code := req("/api/nodes").Code; code != http.StatusUnauthorized {
				t.Errorf("%s doors=%v: gated route %d", mode, doorsOn, code)
			}
			sinks := w.adminSinks(convergeSinks{admin: []events.AdminSink{nil}})
			if want := 1 + map[bool]int{true: 1, false: 0}[built]; len(sinks.admin) != want {
				t.Errorf("%s doors=%v: %d admin sinks, want %d", mode, doorsOn, len(sinks.admin), want)
			}
		}
	}
	if _, err := consoleSignInWiring(t.Context(), consoleSignInDeps{mode: identityModeKeycloak, doorsOn: true, table: table, host: "ci.local"}); err == nil {
		t.Error("a nil collaborator under keycloak with the doors on was accepted")
	}
}

// TC-989-28 (wiring part): converge is given the console's redirect URI and
// back-channel URL only while the doors are on. TC-992-12 (wiring part): the
// reset clients' redirect URIs and each door's reset start likewise.
func TestConsoleConvergeInputs(t *testing.T) {
	table, err := doors.New("ci")
	if err != nil {
		t.Fatal(err)
	}
	on := consoleConvergeInputs(true, "ci.local", table)
	if !slices.Equal(on.redirectURIs["rasputin-console"], []string{"https://ci.local/api/auth/callback"}) ||
		on.backchannel["rasputin-console"] != "https://127.0.0.1/api/identity/backchannel/rasputin-console" {
		t.Errorf("doors on: %+v", on)
	}
	appReturn := "https://" + table.App.Host + "/api/auth/reset-done"
	if !slices.Equal(on.redirectURIs["rasputin-reset-home"], []string{"https://ci.local/api/auth/reset-done"}) ||
		!slices.Equal(on.redirectURIs["rasputin-reset-app"], []string{appReturn}) ||
		on.resetHome != auth.ResetStartURL(table.Home, "rasputin-reset-home", "https://ci.local/api/auth/reset-done") ||
		on.resetApp != auth.ResetStartURL(table.App, "rasputin-reset-app", appReturn) {
		t.Errorf("doors on, resets: %+v", on)
	}
	for _, off := range []consoleInputs{consoleConvergeInputs(false, "ci.local", table), consoleConvergeInputs(true, "", table)} {
		if len(off.redirectURIs) != 0 || len(off.backchannel) != 0 || off.redirectURIs == nil || off.backchannel == nil ||
			off.resetHome != "" || off.resetApp != "" {
			t.Errorf("doors off: %+v, want empty maps", off)
		}
	}
}

// The ender ends an identity session through the Admin API by its id.
func TestSidEnder(t *testing.T) {
	a := &recordingAdmin{}
	if err := (sidEnder{session: a}).EndSession(t.Context(), "sid/1"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(a.calls, []string{"DELETE /admin/realms/rasputin/sessions/sid%2F1"}) {
		t.Errorf("calls %v", a.calls)
	}
	if err := (sidEnder{session: a}).EndSession(t.Context(), ""); err == nil {
		t.Error("an empty sid was sent")
	}
}

// sessionsEnder is #991's ender over an Admin API that records.
func sessionsEnder() sessions.Ender { return sessions.Ender{Admin: &recordingAdmin{}} }
