package recoveradmin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const jobID = "01JOBTEST"

// adminRoles are the baseline's eight realm-management roles.
var adminRoles = []string{"manage-users", "view-users", "query-users", "query-groups", "manage-clients", "view-realm", "manage-realm", "view-events"}

// readRepoBaseline is the shipped identity/realm-baseline.json.
func readRepoBaseline() ([]byte, error) {
	return os.ReadFile(filepath.Join("..", "..", "..", "..", "identity", "realm-baseline.json"))
}

// answer is one scripted Admin API answer.
type answer struct {
	resp idclient.Response
	body string
	err  error
}

// fakeWorld is the units, the recovery command and the identity API, all
// recording into one call log.
type fakeWorld struct {
	mu    sync.Mutex
	log   []string
	admin map[string]answer // "METHOD path" -> answer; missing is 404

	stopErr, startErr, bootErr error
	readyErr                   error
	tempLoginErr, proofErr     error

	bootArgs, bootEnv []string
	tempSecret        string
}

func (f *fakeWorld) add(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, s)
}

func (f *fakeWorld) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.log)
}

func (f *fakeWorld) Stop(context.Context) error  { f.add("stop"); return f.stopErr }
func (f *fakeWorld) Start(context.Context) error { f.add("start"); return f.startErr }
func (f *fakeWorld) Active(context.Context) (bool, error) {
	return true, nil
}
func (f *fakeWorld) Ready(context.Context) error { f.add("ready"); return f.readyErr }

func (f *fakeWorld) bootstrap(_ context.Context, args, env []string) error {
	f.add("bootstrap")
	f.bootArgs, f.bootEnv = slices.Clone(args), slices.Clone(env)
	return f.bootErr
}

func (f *fakeWorld) ClientCredentials(_ context.Context, realm, clientID string, s *secret.Value) (secret.Value, error) {
	if s != nil {
		f.add("login " + realm + "/" + clientID + " secret")
		f.tempSecret = string(s.Reveal())
		if f.tempLoginErr != nil {
			return secret.Value{}, f.tempLoginErr
		}
		return secret.New([]byte("temp-token")), nil
	}
	f.add("login " + realm + "/" + clientID + " x509")
	if f.proofErr != nil {
		return secret.Value{}, f.proofErr
	}
	return secret.New([]byte("admin-token")), nil
}

func (f *fakeWorld) Admin(_ context.Context, tok secret.Value, method, path string, in, out any) (idclient.Response, error) {
	key := method + " " + path
	f.add(key + " [" + string(tok.Reveal()) + "]")
	a, ok := f.admin[key]
	if !ok {
		return idclient.Response{}, &idclient.Error{Op: "admin", Path: path, Status: 404, Kind: idclient.ErrNotFound}
	}
	if a.err != nil {
		return idclient.Response{}, a.err
	}
	if out != nil && a.body != "" {
		if err := json.Unmarshal([]byte(a.body), out); err != nil {
			return idclient.Response{}, err
		}
	}
	return a.resp, nil
}

func rolesBody() string {
	var rs []map[string]any
	for i, n := range append([]string{"impersonation", "create-client"}, adminRoles...) {
		rs = append(rs, map[string]any{"id": fmt.Sprintf("r%d", i), "name": n, "clientRole": true})
	}
	b, _ := json.Marshal(rs)
	return string(b)
}

// healthyWorld answers every call the restore makes successfully.
func healthyWorld() *fakeWorld {
	ok := idclient.Response{Status: 200}
	return &fakeWorld{admin: map[string]answer{
		"GET /admin/realms/rasputin/clients?clientId=rasputin-admin":         {ok, `[{"id":"old1","clientId":"rasputin-admin"}]`, nil},
		"DELETE /admin/realms/rasputin/clients/old1":                         {idclient.Response{Status: 204}, "", nil},
		"POST /admin/realms/rasputin/clients":                                {idclient.Response{Status: 201, Location: "https://127.0.0.1:8543/admin/realms/rasputin/clients/new1"}, "", nil},
		"GET /admin/realms/rasputin/clients?clientId=realm-management":       {ok, `[{"id":"rm","clientId":"realm-management"}]`, nil},
		"GET /admin/realms/rasputin/clients/rm/roles":                        {ok, rolesBody(), nil},
		"GET /admin/realms/rasputin/clients/new1/service-account-user":       {ok, `{"id":"sa1"}`, nil},
		"POST /admin/realms/rasputin/users/sa1/role-mappings/clients/rm":     {idclient.Response{Status: 204}, "", nil},
		"POST /admin/realms/rasputin/clients/new1/scope-mappings/clients/rm": {idclient.Response{Status: 204}, "", nil},
		"GET /admin/realms/master/clients?clientId=rasputin-recover-&search=true": {ok,
			`[{"id":"own","clientId":"rasputin-recover-` + jobID + `"},{"id":"stale","clientId":"rasputin-recover-OLDJOB"},{"id":"x","clientId":"security-admin-console"}]`, nil},
		"DELETE /admin/realms/master/clients/stale": {idclient.Response{Status: 204}, "", nil},
		"DELETE /admin/realms/master/clients/own":   {idclient.Response{Status: 204}, "", nil},
		"GET /admin/realms/rasputin":                {ok, `{"realm":"rasputin"}`, nil},
	}}
}

// seededRand is a deterministic random source.
type seededRand byte

func (s seededRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(s) + byte(i)
	}
	return len(p), nil
}

type run struct {
	w      *fakeWorld
	rec    *logkittest.Recorder
	result json.RawMessage
	err    error
	steps  []string
}

func runRestore(t *testing.T, w *fakeWorld, rnd io.Reader, baseline func() ([]byte, error)) run {
	t.Helper()
	log, rec := logkittest.New()
	r, err := New(Deps{Identity: w, Units: w, Unit: "keycloak.service", Bootstrap: w.bootstrap, ReadBaseline: baseline,
		Rand: rnd, Log: log, StepTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var steps []string
	sc := &jobs.StepCtx{Ctx: t.Context(), JobID: jobID, Log: func(_, m string) { steps = append(steps, m) }}
	res, err := r.Workflow().Steps[0].Do(sc)
	return run{w: w, rec: rec, result: res, err: err, steps: steps}
}

// TC-978-21: argv is exactly the recovery command with the temporary client
// id and the secret's variable name; the secret is in env exactly once,
// printable base64url text carrying 32 bytes of Rand with no NUL, in no argv
// element, and the same text is what the temporary login sends; another Rand
// gives another secret.
func TestRestore_NoSecretOnTheCommandLine(t *testing.T) {
	r := runRestore(t, healthyWorld(), seededRand(1), readRepoBaseline)
	if r.err != nil {
		t.Fatalf("restore: %v", r.err)
	}
	want := []string{"bootstrap-admin", "service", "--optimized", "--no-prompt",
		"--client-id", "rasputin-recover-" + jobID, "--client-secret:env", "RASPUTIN_RECOVER_CLIENT_SECRET"}
	if !slices.Equal(r.w.bootArgs, want) {
		t.Errorf("argv = %q, want %q", r.w.bootArgs, want)
	}
	if len(r.w.bootEnv) != 1 || !strings.HasPrefix(r.w.bootEnv[0], "RASPUTIN_RECOVER_CLIENT_SECRET=") {
		t.Fatalf("env = %d entries, want exactly the secret's variable", len(r.w.bootEnv))
	}
	sec := strings.TrimPrefix(r.w.bootEnv[0], "RASPUTIN_RECOVER_CLIENT_SECRET=")
	if len(sec) != 43 || strings.ContainsFunc(sec, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_')
	}) {
		t.Errorf("the secret is %d characters, want 43 of unpadded base64url", len(sec))
	}
	raw := make([]byte, 32)
	_, _ = seededRand(1).Read(raw)
	if dec, err := base64.RawURLEncoding.DecodeString(sec); err != nil || !bytes.Equal(dec, raw) {
		t.Errorf("the secret decodes to %x (%v), want Rand's 32 bytes %x", dec, err, raw)
	}
	for _, a := range r.w.bootArgs {
		if strings.Contains(a, sec) {
			t.Errorf("argv element %q carries the secret", a)
		}
	}
	if r.w.tempSecret != sec {
		t.Error("the temporary login sent a different secret from the one in env")
	}
	if strings.Contains(r.rec.Text(), sec) || strings.Contains(strings.Join(r.steps, "\n"), sec) {
		t.Error("a record or step log line carries the secret")
	}
	other := runRestore(t, healthyWorld(), seededRand(9), readRepoBaseline)
	if other.w.tempSecret == sec {
		t.Error("a different Rand gave the same secret")
	}
}

// TC-978-22: the calls come in order, the result is {"restored":true} only
// after the proof, each phase writes one INFO record with job_id, unit and
// temp_client and never the secret, and the workflow is the one system step.
func TestRestore_SucceedsInOrderOnProofOnly(t *testing.T) {
	r := runRestore(t, healthyWorld(), seededRand(1), readRepoBaseline)
	if r.err != nil {
		t.Fatalf("restore: %v", r.err)
	}
	want := []string{
		"stop", "bootstrap", "start", "ready",
		"login master/rasputin-recover-" + jobID + " secret",
		"GET /admin/realms/rasputin/clients?clientId=rasputin-admin [temp-token]",
		"DELETE /admin/realms/rasputin/clients/old1 [temp-token]",
		"POST /admin/realms/rasputin/clients [temp-token]",
		"GET /admin/realms/rasputin/clients?clientId=realm-management [temp-token]",
		"GET /admin/realms/rasputin/clients/rm/roles [temp-token]",
		"GET /admin/realms/rasputin/clients/new1/service-account-user [temp-token]",
		"POST /admin/realms/rasputin/users/sa1/role-mappings/clients/rm [temp-token]",
		"POST /admin/realms/rasputin/clients/new1/scope-mappings/clients/rm [temp-token]",
		"GET /admin/realms/master/clients?clientId=rasputin-recover-&search=true [temp-token]",
		"DELETE /admin/realms/master/clients/stale [temp-token]",
		"DELETE /admin/realms/master/clients/own [temp-token]",
		"login rasputin/rasputin-admin x509",
		"GET /admin/realms/rasputin [admin-token]",
	}
	if got := r.w.calls(); !slices.Equal(got, want) {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if string(r.result) != `{"restored":true}` {
		t.Errorf("result = %s", r.result)
	}
	for _, phase := range []string{"stopped", "bootstrapped", "ready", "restored"} {
		recs := 0
		for _, rec := range r.rec.AtLevel(slog.LevelInfo) {
			attrs := map[string]string{}
			rec.Attrs(func(a slog.Attr) bool { attrs[a.Key] = a.Value.String(); return true })
			if attrs["event"] == "identity.recover_admin_"+phase {
				recs++
				if attrs["job_id"] != jobID || attrs["unit"] != "keycloak.service" || attrs["temp_client"] != "rasputin-recover-"+jobID {
					t.Errorf("%s record attrs = %v", phase, attrs)
				}
			}
		}
		if recs != 1 {
			t.Errorf("%d %s records, want 1", recs, phase)
		}
	}
	if strings.Contains(r.rec.Text(), r.w.tempSecret) {
		t.Error("a record carries the secret")
	}
	rr, _ := New(Deps{Identity: r.w, Units: r.w, Unit: "u", Bootstrap: r.w.bootstrap, ReadBaseline: readRepoBaseline,
		Rand: seededRand(1), Log: slog.New(slog.DiscardHandler), StepTimeout: 15 * time.Minute})
	wf := rr.Workflow()
	if wf.Kind != "identity.recover_admin" || !wf.System || len(wf.Steps) != 1 {
		t.Fatalf("workflow = %+v", wf)
	}
	if s := wf.Steps[0]; s.Name != "restore" || !s.Irreversible || s.Retries != 0 || s.Timeout != 15*time.Minute {
		t.Errorf("step = %+v, want restore, Irreversible, no retries, the step bound", s)
	}
	if err := jobs.ValidateWorkflow(wf); err != nil {
		t.Error(err)
	}
}

// TC-978-23: a baseline that cannot be read, is not JSON, or has no
// rasputin-admin client fails before anything is stopped or run.
func TestRestore_BadBaselineStopsNothing(t *testing.T) {
	good, err := readRepoBaseline()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(good, &doc); err != nil {
		t.Fatal(err)
	}
	clients := doc["clients"].([]any)
	doc["clients"] = slices.DeleteFunc(slices.Clone(clients), func(c any) bool {
		return c.(map[string]any)["clientId"] == "rasputin-admin"
	})
	noAdmin, _ := json.Marshal(doc)
	for name, read := range map[string]func() ([]byte, error){
		"unreadable": func() ([]byte, error) { return nil, os.ErrNotExist },
		"not json":   func() ([]byte, error) { return []byte("{"), nil },
		"no admin":   func() ([]byte, error) { return noAdmin, nil },
	} {
		t.Run(name, func(t *testing.T) {
			r := runRestore(t, healthyWorld(), seededRand(1), read)
			if r.err == nil || r.err.Error() != "The sign-in baseline could not be read, so the admin client was not restored." {
				t.Errorf("err = %v", r.err)
			}
			if c := r.w.calls(); len(c) != 0 {
				t.Errorf("calls = %v, want none", c)
			}
		})
	}
}

// TC-978-24: a failed stop ends the step with no recovery command; a failed
// recovery command still starts the unit and fails with its sentence.
func TestRestore_UnitControlFailsClosed(t *testing.T) {
	w := healthyWorld()
	w.stopErr = errors.New("systemctl stop: exit 1")
	r := runRestore(t, w, seededRand(1), readRepoBaseline)
	if r.err == nil || r.err.Error() != "The identity service could not be stopped, so the admin client was not restored." {
		t.Errorf("stop failure: err = %v", r.err)
	}
	if c := w.calls(); !slices.Equal(c, []string{"stop"}) {
		t.Errorf("stop failure: calls = %v, want only the stop", c)
	}

	w = healthyWorld()
	w.bootErr = errors.New("kc.sh: exit 1 (output: client exists)")
	r = runRestore(t, w, seededRand(1), readRepoBaseline)
	if r.err == nil || r.err.Error() != "The identity service's recovery command failed, so the admin client was not restored." {
		t.Errorf("command failure: err = %v", r.err)
	}
	if c := w.calls(); !slices.Equal(c, []string{"stop", "bootstrap", "start"}) {
		t.Errorf("command failure: calls = %v, want the unit started again", c)
	}

	w = healthyWorld()
	w.readyErr = errors.New("503")
	w.admin = nil
	wNotActive := &inactiveWorld{w}
	log := slog.New(slog.DiscardHandler)
	rr, _ := New(Deps{Identity: w, Units: wNotActive, Unit: "u", Bootstrap: w.bootstrap, ReadBaseline: readRepoBaseline,
		Rand: seededRand(1), Log: log, StepTimeout: time.Minute})
	_, err := rr.Workflow().Steps[0].Do(&jobs.StepCtx{Ctx: t.Context(), JobID: jobID})
	if err == nil || err.Error() != "The identity service did not become ready after the recovery, so the admin client was not restored." {
		t.Errorf("not ready: err = %v", err)
	}
}

// inactiveWorld's unit stops being active after its start.
type inactiveWorld struct{ *fakeWorld }

func (inactiveWorld) Active(context.Context) (bool, error) { return false, nil }

// TC-978-25: a failed re-creation still deletes the temporary clients and
// never reports restored; a failed cleanup after a good re-creation fails
// with its sentence; a failed proof never reports restored.
func TestRestore_CleanupAndProofFailures(t *testing.T) {
	cleanupRan := func(c []string) bool {
		return slices.Contains(c, "DELETE /admin/realms/master/clients/own [temp-token]")
	}
	for _, kind := range []error{idclient.ErrConflict, idclient.ErrUnreachable} {
		w := healthyWorld()
		w.admin["POST /admin/realms/rasputin/clients"] = answer{err: &idclient.Error{Op: "admin", Kind: kind}}
		r := runRestore(t, w, seededRand(1), readRepoBaseline)
		if r.err == nil || r.err.Error() != "The admin client could not be re-created." || r.result != nil {
			t.Errorf("create %v: err = %v result %s", kind, r.err, r.result)
		}
		if !cleanupRan(w.calls()) {
			t.Errorf("create %v: the temporary clients were not deleted", kind)
		}
	}

	w := healthyWorld()
	w.admin["DELETE /admin/realms/master/clients/stale"] = answer{err: &idclient.Error{Op: "admin", Kind: idclient.ErrUnreachable}}
	r := runRestore(t, w, seededRand(1), readRepoBaseline)
	if r.err == nil || r.err.Error() != "The admin client was restored, but the temporary recovery client could not be removed." || r.result != nil {
		t.Errorf("cleanup failure: err = %v result %s", r.err, r.result)
	}
	if !cleanupRan(w.calls()) {
		t.Error("cleanup failure: its own client was not deleted after the stale one failed")
	}

	w = healthyWorld()
	w.proofErr = &idclient.Error{Op: "token", Kind: idclient.ErrDenied}
	r = runRestore(t, w, seededRand(1), readRepoBaseline)
	if r.err == nil || r.result != nil {
		t.Errorf("x509 proof failure: err = %v result %s", r.err, r.result)
	}

	w = healthyWorld()
	w.admin["GET /admin/realms/rasputin"] = answer{err: &idclient.Error{Op: "admin", Kind: idclient.ErrForbidden}}
	r = runRestore(t, w, seededRand(1), readRepoBaseline)
	if r.err == nil || r.result != nil {
		t.Errorf("GET proof failure: err = %v result %s", r.err, r.result)
	}

	w = healthyWorld()
	w.tempLoginErr = &idclient.Error{Op: "token", Kind: idclient.ErrDenied}
	r = runRestore(t, w, seededRand(1), readRepoBaseline)
	if r.err == nil || r.err.Error() != "The admin client could not be re-created." {
		t.Errorf("temporary login failure: err = %v", r.err)
	}
}

// A random source that fails ends the step before anything is stopped.
func TestRestore_RandomFailureStopsNothing(t *testing.T) {
	w := healthyWorld()
	r := runRestore(t, w, failingRand{}, readRepoBaseline)
	if r.err == nil || r.err.Error() != "The temporary recovery secret could not be made, so the admin client was not restored." {
		t.Errorf("err = %v", r.err)
	}
	if c := w.calls(); len(c) != 0 {
		t.Errorf("calls = %v, want none", c)
	}
}

type failingRand struct{}

func (failingRand) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// New refuses an incomplete Deps.
func TestNew_RefusesIncompleteDeps(t *testing.T) {
	w := healthyWorld()
	full := Deps{Identity: w, Units: w, Unit: "u", Bootstrap: w.bootstrap, ReadBaseline: readRepoBaseline,
		Rand: seededRand(1), Log: slog.New(slog.DiscardHandler), StepTimeout: time.Minute}
	for name, m := range map[string]func(*Deps){
		"identity": func(d *Deps) { d.Identity = nil }, "unit": func(d *Deps) { d.Unit = "" },
		"timeout": func(d *Deps) { d.StepTimeout = 0 }, "rand": func(d *Deps) { d.Rand = nil },
	} {
		d := full
		m(&d)
		if _, err := New(d); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}
