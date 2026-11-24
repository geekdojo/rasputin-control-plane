package api

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"github.com/nats-io/nats.go"
)

// The kind table at the api (geekdojo/geekdojo-brain#1001): every route that
// submits a job, through the real RequireSession, the real runner and the
// real kind policy over the real tier reader.

// authenticateAs mints a console session for a person with sub, name and
// roles, and returns its cookie.
func (f *apiFixture) authenticateAs(t *testing.T, sub, name string, roles ...string) *http.Cookie {
	t.Helper()
	v, err := f.sessions.Create(f.ctx, auth.Principal{Sub: sub, Name: name, Roles: roles,
		Session: auth.SessionRef{SID: "sid-" + sub}})
	if err != nil {
		t.Fatalf("console session: %v", err)
	}
	t.Cleanup(v.Destroy)
	return &http.Cookie{Name: auth.SessionCookieName, Value: string(v.Reveal())}
}

// coded decodes a coded error body.
func coded(t *testing.T, w *httptest.ResponseRecorder) codedError {
	t.Helper()
	var e codedError
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode %d %s: %v", w.Code, w.Body.String(), err)
	}
	return e
}

// wantRefused asserts w is a 403 carrying code, a sentence and a correlation id.
func wantRefused(t *testing.T, what string, w *httptest.ResponseRecorder, code string) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Errorf("%s: %d %s, want 403 %s", what, w.Code, w.Body.String(), code)
		return
	}
	e := coded(t, w)
	if e.Code != code || e.CorrelationID == "" || !strings.HasSuffix(e.Error, ".") {
		t.Errorf("%s: body %+v, want code %s with a sentence and a correlation id", what, e, code)
	}
}

// rows is the job rows of kind.
func (f *apiFixture) rows(t *testing.T, kind string) []*jobs.Job {
	t.Helper()
	list, err := f.jobsStore.ListAllJobsByKind(f.ctx, kind)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// busRecorder records every node command and job event published on nc.
type busRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func recordBus(t *testing.T, nc *nats.Conn) *busRecorder {
	t.Helper()
	b := &busRecorder{}
	sub, err := nc.Subscribe(">", func(m *nats.Msg) {
		if strings.Contains(m.Subject, ".cmd.") || strings.HasPrefix(m.Subject, "rasputin.job.") {
			b.mu.Lock()
			b.msgs = append(b.msgs, m.Subject)
			b.mu.Unlock()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return b
}

func (b *busRecorder) seen(t *testing.T, nc *nats.Conn) []string {
	t.Helper()
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.msgs...)
}

func noop(kind string) jobs.Workflow { return jobs.Workflow{Kind: kind, Steps: noopSteps} }

// TC-1001-01: a kind the table does not know is 403 job_unknown_kind, and no
// row exists.
func TestJobsAuthz_TC1001_01_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"nope.kind"}`, f.authenticate(t))
	wantRefused(t, "nope.kind", w, "job_unknown_kind")
	if list, _ := f.jobsStore.ListJobs(f.ctx, 10); len(list) != 0 {
		t.Errorf("%d job rows, want none", len(list))
	}
}

// TC-1001-02: a viewer's power-cycle, by its route and by POST /api/jobs, is
// 403 job_not_permitted before anything exists; an administrator's runs and
// records the administrator's sub.
func TestJobsAuthz_TC1001_02_ViewerPowerCycle(t *testing.T) {
	f := newAPIFixture(t)
	f.runner.Register(noop("bmc.power"))
	viewer := f.authenticateAs(t, "sub-vic", "vic", "viewer")
	bus := recordBus(t, f.nc)
	wantRefused(t, "viewer power cycle", f.do(t, http.MethodPost, "/api/bmc/n1/power/cycle", "", viewer), "job_not_permitted")
	wantRefused(t, "viewer POST bmc.power", f.do(t, http.MethodPost, "/api/jobs",
		`{"kind":"bmc.power","spec":{"targetNodeId":"n1","verb":"cycle"}}`, viewer), "job_not_permitted")
	if got := f.rows(t, "bmc.power"); len(got) != 0 {
		t.Errorf("%d bmc.power rows after the viewer's calls, want none", len(got))
	}
	if got := bus.seen(t, f.nc); len(got) != 0 {
		t.Errorf("the viewer's calls published %v, want nothing", got)
	}
	w := f.do(t, http.MethodPost, "/api/bmc/n1/power/cycle", "", f.authenticate(t))
	if w.Code != http.StatusAccepted {
		t.Fatalf("admin power cycle: %d %s, want 202", w.Code, w.Body.String())
	}
	f.runner.Wait()
	if got := f.rows(t, "bmc.power"); len(got) != 1 || got[0].CreatedBy != "sub-alice" {
		t.Errorf("bmc.power rows = %v, want one created by sub-alice", got)
	}
}

// TC-1001-03: a self kind's target must be the submitter: another's is 403
// job_not_your_account; the viewer's own passes the policy and answers 400,
// because no workflow is registered for the kind yet.
func TestJobsAuthz_TC1001_03_SelfTarget(t *testing.T) {
	f := newAPIFixture(t)
	viewer := f.authenticateAs(t, "s-A", "amy", "viewer")
	wantRefused(t, "another's account", f.do(t, http.MethodPost, "/api/jobs",
		`{"kind":"accounts.rename_credential","spec":{"accountId":"s-B"}}`, viewer), "job_not_your_account")
	w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"accounts.rename_credential","spec":{"accountId":"s-A"}}`, viewer)
	if w.Code != http.StatusBadRequest {
		t.Errorf("own account: %d %s, want 400 (authorized, no workflow)", w.Code, w.Body.String())
	}
	if list, _ := f.jobsStore.ListJobs(f.ctx, 10); len(list) != 0 {
		t.Errorf("%d job rows, want none", len(list))
	}
}

// App ids for TC-1001-04, ULIDs as every app spec's strict decode wants.
const (
	tcCustomID   = "01J9ZK3Q0M8X7Y6W5V4T3S2C10"
	tcRoutineID  = "01J9ZK3Q0M8X7Y6W5V4T3S2R10"
	tcElevatedID = "01J9ZK3Q0M8X7Y6W5V4T3S2E10"
	tcHostID     = "01J9ZK3Q0M8X7Y6W5V4T3S2H10"
	tcUpgradeID  = "01J9ZK3Q0M8X7Y6W5V4T3S2U10"
	tcRevertID   = "01J9ZK3Q0M8X7Y6W5V4T3S2V10"
)

// TC-1001-04: an operator's custom compose and host-trusting tile are
// refused, by deploy, compose edit, stop, delete, an upgrade to a
// host-trusting tile and a revert to a host-trusting compose; routine and
// elevated tiles deploy; an administrator's custom deploy runs.
func TestJobsAuthz_TC1001_04_AppTiers(t *testing.T) {
	f, admin, _, _ := upgradeFixtureWith(t, hostTrustingBundleTile())
	f.runner.Register(noop("app.deploy"))
	operator := f.authenticateAs(t, "sub-otto", "otto", "operator")
	seedUpgradeApp(t, f, tcCustomID, "mine", "", customOld, 0)
	seedTieredApp(t, f, tcRoutineID, "vw", "vaultwarden", tileschema.TierRoutine)
	seedTieredApp(t, f, tcElevatedID, "jf", "jellyfin", tileschema.TierElevated)
	seedTieredApp(t, f, tcHostID, "ha", "homeassistant", tileschema.TierHostTrusting)
	// Installed routine; its tile in the catalog in effect is host-trusting.
	seedTieredApp(t, f, tcUpgradeID, "ha2", "homeassistant", tileschema.TierRoutine)
	// Installed host-trusting, then moved to a routine compose: its previous
	// tier, the one a revert re-applies, is host-trusting.
	rev := seedTieredApp(t, f, tcRevertID, "back", "homeassistant", tileschema.TierHostTrusting)
	if err := f.appsStore.UpgradeCompose(f.ctx, tcRevertID, rev.ComposeSHA256, apps.ComposeUpgrade{
		ComposeYAML: "services: {new: {}}\n", CatalogVersion: upgradeCatalogVersion, PrivilegeTier: tileschema.TierRoutine,
	}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	deploy := func(id string, c *http.Cookie) *httptest.ResponseRecorder {
		return f.do(t, http.MethodPost, "/api/apps/"+id+"/deploy", "", c)
	}
	wantRefused(t, "operator deploy custom", deploy(tcCustomID, operator), "job_not_permitted")
	wantRefused(t, "operator deploy host-trusting", deploy(tcHostID, operator), "job_not_permitted")
	for _, id := range []string{tcRoutineID, tcElevatedID} {
		if w := deploy(id, operator); w.Code != http.StatusAccepted {
			t.Errorf("operator deploy %s: %d %s, want 202", id, w.Code, w.Body.String())
		}
	}
	w := f.do(t, http.MethodPut, "/api/apps/"+tcCustomID+"/compose",
		composeYAMLBody(t, "services:\n  web:\n    image: me/web:2\n    ports: [\"127.0.0.1:1234:80\"]\n"), operator)
	wantRefused(t, "operator custom compose edit", w, "job_not_permitted")
	wantRefused(t, "operator stop custom", f.do(t, http.MethodPost, "/api/apps/"+tcCustomID+"/stop", "", operator), "job_not_permitted")
	wantRefused(t, "operator delete custom", f.do(t, http.MethodDelete, "/api/apps/"+tcCustomID, "", operator), "job_not_permitted")
	wantRefused(t, "operator upgrade to host-trusting", f.do(t, http.MethodPost, "/api/jobs",
		`{"kind":"app.upgrade","spec":{"appId":"`+tcUpgradeID+`"}}`, operator), "job_not_permitted")
	wantRefused(t, "operator revert to host-trusting", f.do(t, http.MethodPost, "/api/jobs",
		`{"kind":"app.revert","spec":{"appId":"`+tcRevertID+`","sha256":"ff"}}`, operator), "job_not_permitted")
	for _, k := range []string{"app.edit", "app.stop", "app.delete", "app.upgrade", "app.revert"} {
		if got := f.rows(t, k); len(got) != 0 {
			t.Errorf("%s: %d rows after the refusals, want none", k, len(got))
		}
	}
	if n := f.srv.composeStash.Len(); n != 0 {
		t.Errorf("the compose stash holds %d entries after the refused edit, want none", n)
	}
	if w := deploy(tcCustomID, admin); w.Code != http.StatusAccepted {
		t.Errorf("admin deploy custom: %d %s, want 202", w.Code, w.Body.String())
	}
	f.runner.Wait()
	if got := f.rows(t, "app.deploy"); len(got) != 3 {
		t.Errorf("app.deploy rows = %d, want 3 (routine, elevated, the admin's custom)", len(got))
	}
}

// TC-1001-05: accounts.grant_designated_role is never accepted through
// POST /api/jobs.
func TestJobsAuthz_TC1001_05_GrantDesignatedRole(t *testing.T) {
	f := newAPIFixture(t)
	wantRefused(t, "grant_designated_role", f.do(t, http.MethodPost, "/api/jobs",
		`{"kind":"accounts.grant_designated_role","spec":{"accountId":"s-x"}}`, f.authenticate(t)), "job_system_only")
	if got := f.rows(t, "accounts.grant_designated_role"); len(got) != 0 {
		t.Errorf("%d rows, want none", len(got))
	}
}

// TC-1001-07: the system-only identity kinds are refused through
// POST /api/jobs, even registered as ordinary workflows, and still run when
// the system submits them.
func TestJobsAuthz_TC1001_07_SystemOnlyKinds(t *testing.T) {
	f := newAPIFixture(t)
	admin := f.authenticate(t)
	kinds := []string{"identity.migrate", "identity.reference_check", "identity.recover", "identity.recover_admin"}
	for _, k := range kinds {
		f.runner.Register(noop(k))
		wantRefused(t, k, f.do(t, http.MethodPost, "/api/jobs", `{"kind":"`+k+`"}`, admin), "job_system_only")
		if got := f.rows(t, k); len(got) != 0 {
			t.Errorf("%s: %d rows after the refusal, want none", k, len(got))
		}
	}
	for _, k := range kinds {
		j, err := f.runner.Submit(f.ctx, k, nil, "identity-state")
		if err != nil || j == nil || j.Status != jobs.StatusQueued {
			t.Errorf("system submit of %s = %+v, %v; want a queued job", k, j, err)
		}
	}
	f.runner.Wait()
}

// TC-1001-08: identity.move through POST /api/jobs is refused.
func TestJobsAuthz_TC1001_08_IdentityMove(t *testing.T) {
	f := newAPIFixture(t)
	wantRefused(t, "identity.move", f.do(t, http.MethodPost, "/api/jobs", `{"kind":"identity.move"}`, f.authenticate(t)), "job_system_only")
	if got := f.rows(t, "identity.move"); len(got) != 0 {
		t.Errorf("%d rows, want none", len(got))
	}
}

// records is the captured records at level with message msg.
func (f *apiFixture) records(level slog.Level, msg string) []slog.Record {
	f.logs.mu.Lock()
	defer f.logs.mu.Unlock()
	var out []slog.Record
	for _, r := range f.logs.recs {
		if r.Level == level && r.Message == msg {
			out = append(out, r)
		}
	}
	return out
}

func attrs(r slog.Record) map[string]string {
	m := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.String()
		return true
	})
	return m
}

// TC-1001-11: an app store that cannot be read is 500 job_check_failed with
// one ERROR record; a missing app is 403 job_no_app; a spec without appId is
// job_no_target; an already-current upgrade is no 500 and no ERROR record.
func TestJobsAuthz_TC1001_11_AppReads(t *testing.T) {
	f, admin, cat, _ := upgradeFixture(t)
	seedUpgradeApp(t, f, sameID, "same", "vaultwarden", tileCompose(t, cat, "vaultwarden"), upgradeCatalogVersion)
	w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"app.upgrade","spec":{"appId":"`+sameID+`"}}`, admin)
	if w.Code == http.StatusInternalServerError || len(f.records(slog.LevelError, "api: job check failed")) != 0 {
		t.Errorf("already-current upgrade: %d %s, want no 500 and no ERROR record", w.Code, w.Body.String())
	}
	f.runner.Wait()
	wantRefused(t, "missing app", f.do(t, http.MethodPost, "/api/apps/"+downID+"/deploy", "", admin), "job_no_app")
	wantRefused(t, "no appId", f.do(t, http.MethodPost, "/api/jobs", `{"kind":"app.deploy","spec":{}}`, admin), "job_no_target")

	if err := f.appsStore.Close(); err != nil {
		t.Fatal(err)
	}
	w = f.do(t, http.MethodPost, "/api/apps/"+sameID+"/deploy", "", admin)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("store down: %d %s, want 500", w.Code, w.Body.String())
	}
	e := coded(t, w)
	if e.Code != "job_check_failed" || e.CorrelationID == "" || e.Error != "The job couldn't be checked, so it wasn't started." {
		t.Errorf("store down body = %+v", e)
	}
	recs := f.records(slog.LevelError, "api: job check failed")
	if len(recs) != 1 {
		t.Fatalf("%d ERROR records, want 1", len(recs))
	}
	a := attrs(recs[0])
	if a["correlation_id"] != e.CorrelationID || a["kind"] != "app.deploy" || a["err"] == "" {
		t.Errorf("ERROR record attrs = %v, want correlation_id, kind and err", a)
	}
	if got := f.rows(t, "app.deploy"); len(got) != 0 {
		t.Errorf("%d app.deploy rows, want none", len(got))
	}
}

// TC-1001-13 (api part): a runner that runs only the system's jobs answers a
// person's submission 500 job_check_failed.
func TestJobsAuthz_TC1001_13_NotSystem(t *testing.T) {
	f := newAPIFixture(t)
	r := httptest.NewRequest(http.MethodPost, "/api/obs/enable", nil)
	r.Pattern = "POST /api/obs/enable"
	w := httptest.NewRecorder()
	if !f.srv.refusedSubmit(w, r, "obs.enable", fmt.Errorf("%w: job kind %q", jobs.ErrNotSystem, "obs.enable")) {
		t.Fatal("ErrNotSystem was not answered")
	}
	if e := coded(t, w); w.Code != http.StatusInternalServerError || e.Code != "job_check_failed" {
		t.Errorf("ErrNotSystem: %d %+v, want 500 job_check_failed", w.Code, e)
	}
	if f.srv.refusedSubmit(httptest.NewRecorder(), r, "obs.enable", errors.New("unknown job kind")) {
		t.Error("an ordinary submit error was answered as a refusal")
	}
}

// TC-1001-14 (api part): app.delete through its route hands its step the
// sub, and the name appears nowhere in the job.
func TestJobsAuthz_TC1001_14_DeleteStepSeesTheSub(t *testing.T) {
	f, cookie, _ := volumesFixture(t)
	seedVolumesApp(t, f, volULIDLive, "immich")
	got := make(chan string, 1)
	f.runner.Register(jobs.Workflow{Kind: "app.delete", Steps: []jobs.WorkflowStep{{Name: "a", Timeout: time.Second,
		Do: func(sc *jobs.StepCtx) (json.RawMessage, error) { got <- sc.CreatedBy; return nil, nil }}}})
	w := f.do(t, http.MethodDelete, "/api/apps/"+volULIDLive, "", cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	f.runner.Wait()
	if who := <-got; who != "sub-alice" {
		t.Errorf("sc.CreatedBy = %q, want sub-alice", who)
	}
	if strings.Contains(w.Body.String(), `"alice"`) {
		t.Errorf("the job names the person: %s", w.Body.String())
	}
}

// TC-1001-19: an operator loses Ping, reboot, back up and the obs toggles,
// and keeps system and node updates; a viewer can no longer refresh BMC
// status from hardware.
func TestJobsAuthz_TC1001_19_OperatorAndViewer(t *testing.T) {
	f := newAPIFixture(t)
	for _, k := range []string{"diag.ping", "node.reboot", "obs.enable", "system.update", "node.update", "bmc.power"} {
		f.runner.Register(noop(k))
	}
	operator := f.authenticateAs(t, "sub-otto", "otto", "operator")
	wantRefused(t, "operator diag.ping", f.do(t, http.MethodPost, "/api/jobs", `{"kind":"diag.ping","spec":{"nodeId":"n1"}}`, operator), "job_not_permitted")
	wantRefused(t, "operator node.reboot", f.do(t, http.MethodPost, "/api/jobs", `{"kind":"node.reboot","spec":{"nodeId":"n1"}}`, operator), "job_not_permitted")
	wantRefused(t, "operator obs.enable", f.do(t, http.MethodPost, "/api/obs/enable", "", operator), "job_not_permitted")
	if w := f.do(t, http.MethodPost, "/api/updates/system", `{"version":"2026.08.4"}`, operator); w.Code != http.StatusAccepted {
		t.Errorf("operator system.update: %d %s, want 202", w.Code, w.Body.String())
	}
	if w := f.do(t, http.MethodPost, "/api/updates", `{"nodeId":"n1","bundleSha256":"ab"}`, operator); w.Code != http.StatusAccepted {
		t.Errorf("operator node.update: %d %s, want 202", w.Code, w.Body.String())
	}
	viewer := f.authenticateAs(t, "sub-vic", "vic", "viewer")
	wantRefused(t, "viewer BMC status refresh", f.do(t, http.MethodPost, "/api/bmc/n1/power/status", "", viewer), "job_not_permitted")
	f.runner.Wait()
	for k, want := range map[string]int{"diag.ping": 0, "node.reboot": 0, "obs.enable": 0, "bmc.power": 0, "system.update": 1, "node.update": 1} {
		if got := f.rows(t, k); len(got) != want {
			t.Errorf("%s: %d rows, want %d", k, len(got), want)
		}
	}

	// backup.run, by its route, on the backup routes' server.
	s, _ := runsTestServer(t)
	s.runner.Register(noop(storage.RunJobKind))
	req := httptest.NewRequest(http.MethodPost, "/api/backup/runs", strings.NewReader("{}"))
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Sub: "sub-otto", Name: "otto", Roles: []string{"operator"}}))
	rec := httptest.NewRecorder()
	s.handleStartBackupRun(rec, req)
	wantRefused(t, "operator backup.run", rec, "job_not_permitted")
	if list, _ := s.store.ListAllJobsByKind(t.Context(), storage.RunJobKind); len(list) != 0 {
		t.Errorf("backup.run: %d rows, want none", len(list))
	}
}

// TC-1001-20: storage.SubmitClaim is a person's submission: a viewer's claim
// is 403 with no row, no format command and no staged key; an
// administrator's runs and records the sub.
func TestJobsAuthz_TC1001_20_StorageClaim(t *testing.T) {
	s, store, nc := storageTestServer(t)
	formats := make(chan string, 4)
	sub, err := nc.Subscribe(">", func(m *nats.Msg) {
		if strings.HasSuffix(m.Subject, ".storage.claim") {
			formats <- m.Subject
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	body := `{"nodeId":"` + storageTestNode + `","devicePath":"/dev/sdb","fingerprint":"fp",` + claimKeyFields(t) + `}`
	viewer := auth.Principal{Sub: "sub-vic", Name: "vic", Roles: []string{"viewer"}}
	wantRefused(t, "viewer claim", postClaimAs(t, s, body, viewer), "job_not_permitted")
	if list, _ := s.store.ListAllJobsByKind(t.Context(), storage.ClaimJobKind); len(list) != 0 {
		t.Errorf("%d claim rows after the viewer's call, want none", len(list))
	}
	if staged, err := store.StagedClaimKeyJobs(t.Context()); err != nil || len(staged) != 0 {
		t.Errorf("staged keys after the refusal = %v, %v; want none", staged, err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	select {
	case subj := <-formats:
		t.Errorf("a format command was sent for the viewer: %s", subj)
	default:
	}
	rec := postClaim(t, s, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin claim: %d %s, want 201", rec.Code, rec.Body.String())
	}
	var j jobs.Job
	if err := json.Unmarshal(rec.Body.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	row, err := s.store.GetJob(t.Context(), j.ID)
	if err != nil || row.CreatedBy != storageAdmin.Sub {
		t.Errorf("admin claim row = %+v, %v; want created by %s", row, err, storageAdmin.Sub)
	}
}

// TC-1001-22: a refusal writes exactly one WARN "api: request refused" with
// the correlation id, the route pattern, the code and the kind, and neither
// the record nor the body holds the spec, the target, the sub or the name.
func TestJobsAuthz_TC1001_22_RefusalLogging(t *testing.T) {
	f := newAPIFixture(t)
	viewer := f.authenticateAs(t, "sub-amy-7f3a", "amy-name-9c1d", "viewer")
	before := len(f.records(slog.LevelWarn, "api: request refused"))
	w := f.do(t, http.MethodPost, "/api/jobs",
		`{"kind":"accounts.rename_credential","spec":{"accountId":"target-b-4e2f","label":"spec-label-5d6e"}}`, viewer)
	wantRefused(t, "another's account", w, "job_not_your_account")
	recs := f.records(slog.LevelWarn, "api: request refused")[before:]
	if len(recs) != 1 {
		t.Fatalf("%d refusal records, want 1", len(recs))
	}
	a := attrs(recs[0])
	if a["correlation_id"] != coded(t, w).CorrelationID || a["route"] != "POST /api/jobs" ||
		a["code"] != "job_not_your_account" || a["kind"] != "accounts.rename_credential" {
		t.Errorf("refusal record attrs = %v", a)
	}
	f.logs.mu.Lock()
	all := append([]slog.Record(nil), f.logs.recs...)
	f.logs.mu.Unlock()
	for _, secret := range []string{"target-b-4e2f", "spec-label-5d6e", "sub-amy-7f3a", "amy-name-9c1d"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Errorf("the response holds %q: %s", secret, w.Body.String())
		}
		for _, r := range all {
			text := r.Message + fmt.Sprint(attrs(r))
			if strings.Contains(text, secret) {
				t.Errorf("a log record holds %q: %s", secret, text)
			}
		}
	}
}

// claimKeyFields is a valid archive key for a claim body, as
// TestClaimBackupTarget_StagesTheArchiveKey builds it.
func claimKeyFields(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	pub := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	return `"archiveKey":{"keyId":"ak-1","alg":"x25519","publicKey":"` + pub +
		`","wrappedByPassphrase":"SENTINEL-WRAPPED-PP","wrappedByRecoveryCode":"SENTINEL-WRAPPED-RC"}`
}

// TC-1001-15: the decision follows the app the job will act on. A spec
// naming a routine app and, case-folded, a custom one is refused, and no
// row exists, so the policy never approves one app for a saga that decodes
// the other.
func TestJobsAuthz_TC1001_15_CaseFoldedTarget(t *testing.T) {
	f, _, _, _ := upgradeFixture(t)
	f.runner.Register(noop("app.deploy"))
	operator := f.authenticateAs(t, "sub-otto", "otto", "operator")
	seedTieredApp(t, f, tcRoutineID, "vw", "vaultwarden", tileschema.TierRoutine)
	seedUpgradeApp(t, f, tcCustomID, "mine", "", customOld, 0)
	for _, spec := range []string{
		`{"appId":"` + tcRoutineID + `","APPID":"` + tcCustomID + `"}`,
		`{"APPID":"` + tcCustomID + `","appId":"` + tcRoutineID + `"}`,
		`{"appId":"` + tcCustomID + `","appId":"` + tcRoutineID + `"}`,
	} {
		w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"app.deploy","spec":`+spec+`}`, operator)
		if w.Code != http.StatusForbidden {
			t.Errorf("spec %s: %d %s, want 403", spec, w.Code, w.Body.String())
		}
	}
	if got := f.rows(t, "app.deploy"); len(got) != 0 {
		t.Errorf("%d app.deploy rows, want none", len(got))
	}
}

// TC-1001-10 (api part): a request that reaches SubmitFor with no Principal
// submits the zero Submitter, which is refused, and nothing runs.
func TestJobsAuthz_TC1001_10_NoPrincipal(t *testing.T) {
	f := newAPIFixture(t)
	f.runner.Register(noop("obs.enable"))
	r := httptest.NewRequest(http.MethodPost, "/api/obs/enable", nil)
	r.Pattern = "POST /api/obs/enable"
	w := httptest.NewRecorder()
	f.srv.handleObsEnable(w, r)
	wantRefused(t, "no principal", w, "job_not_permitted")
	f.runner.Wait()
	if got := f.rows(t, "obs.enable"); len(got) != 0 {
		t.Errorf("%d obs.enable rows, want none", len(got))
	}
}
