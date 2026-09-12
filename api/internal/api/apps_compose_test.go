package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// PUT /api/apps/{id}/compose (geekdojo/geekdojo-brain#410) beyond the catalog
// upgrade, which apps_upgrade_test.go covers: the body's shape, the variant
// each app kind allows, a custom compose that never reaches a job's spec,
// steps, events or response and is not kept after its job, re-apply by hash,
// and the two POST routes this replaced being gone.

type revertRow struct {
	ID                    string `json:"id"`
	ComposeYAML           string `json:"composeYaml"`
	ComposeSHA256         string `json:"composeSha256"`
	PreviousComposeYAML   string `json:"previousComposeYaml"`
	PreviousComposeSHA256 string `json:"previousComposeSha256"`
	ComposeCatalogVersion int    `json:"composeCatalogVersion"`
	UpgradeAvailable      bool   `json:"upgradeAvailable"`
	RevertAvailable       bool   `json:"revertAvailable"`
}

// secretMarker stands for a secret a custom compose inlines.
const secretMarker = "hunter2-DO-NOT-LEAK-7f3a"

const customOld = "services:\n  web:\n    image: me/web:1\n    volumes: [data:/data]\nvolumes:\n  data: {}\n"

var customNew = "services:\n  web:\n    image: me/web:2\n    environment:\n      DB_PASSWORD: " + secretMarker + "\n    volumes: [data:/data]\nvolumes:\n  data: {}\n"

func composeYAMLBody(t *testing.T, compose string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"composeYaml": compose})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func shaBody(compose string) string {
	return `{"sha256":"` + apps.ComposeHash(compose) + `"}`
}

func getRow(t *testing.T, f *apiFixture, cookie *http.Cookie, id string) revertRow {
	t.Helper()
	w := f.do(t, http.MethodGet, "/api/apps/"+id, "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get %s: %d %s", id, w.Code, w.Body.String())
	}
	return decodeBody[revertRow](t, w.Body.String())
}

// assertNoComposeJob fails if any compose job exists or the agent was sent
// anything: the check behind every refusal and every no-op.
func assertNoComposeJob(t *testing.T, f *apiFixture, got <-chan proto.AppDeployCmd) {
	t.Helper()
	f.runner.Wait()
	for _, kind := range []string{"app.upgrade", "app.edit", "app.revert"} {
		if js, _ := f.jobsStore.ListJobsByKind(f.ctx, kind, 10); len(js) != 0 {
			t.Errorf("expected no job, found %d %s", len(js), kind)
		}
	}
	select {
	case cmd := <-got:
		t.Errorf("the agent was sent a deploy: %+v", cmd)
	default:
	}
}

// assertJobCarriesNoCompose reads a job back through every route the Tasks
// page renders it from, and fails if the submitted compose is in any of them.
func assertJobCarriesNoCompose(t *testing.T, f *apiFixture, cookie *http.Cookie, jobID string) {
	t.Helper()
	for _, path := range []string{"/api/jobs/" + jobID, "/api/jobs/" + jobID + "/steps", "/api/jobs/" + jobID + "/events", "/api/jobs"} {
		w := f.do(t, http.MethodGet, path, "", cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), secretMarker) || strings.Contains(w.Body.String(), "me/web:2") {
			t.Errorf("GET %s carries the submitted compose: %s", path, w.Body.String())
		}
	}
}

func TestAppsCompose_MalformedBodiesAre400(t *testing.T) {
	f, cookie, _, got := upgradeFixture(t)
	seedUpgradeApp(t, f, "cat", "vw", "vaultwarden", "services: {old: {}}\n", 3)
	seedUpgradeApp(t, f, "custom", "mine", "", customOld, 0)
	sha := apps.ComposeHash(customOld)

	for _, c := range []struct{ name, body string }{
		{"no body", ""},
		{"not json", "source=catalog"},
		{"empty object", `{}`},
		{"all null", `{"source":null,"composeYaml":null,"sha256":null}`},
		{"two keys", `{"source":"catalog","sha256":"` + sha + `"}`},
		{"three keys", `{"source":"catalog","composeYaml":"services: {}","sha256":"` + sha + `"}`},
		{"unknown field", `{"sha256":"` + sha + `","force":true}`},
		{"two values", `{"sha256":"` + sha + `"}{"source":"catalog"}`},
		{"unknown source", `{"source":"github"}`},
		{"empty compose", `{"composeYaml":"  \n"}`},
		{"short hash", `{"sha256":"abc123"}`},
		{"non-hex hash", `{"sha256":"` + strings.Repeat("z", 64) + `"}`},
		{"wrong type", `{"sha256":42}`},
	} {
		for _, id := range []string{"cat", "custom"} {
			if w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", c.body, cookie); w.Code != http.StatusBadRequest {
				t.Errorf("%s on %s: want 400, got %d (%s)", c.name, id, w.Code, w.Body.String())
			}
		}
	}
	big := composeYAMLBody(t, "services: {}\n# "+strings.Repeat("x", maxComposeBody))
	if w := f.do(t, http.MethodPut, "/api/apps/custom/compose", big, cookie); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: want 413, got %d", w.Code)
	}
	if w := f.do(t, http.MethodPut, "/api/apps/ghost/compose", `{}`, cookie); w.Code != http.StatusNotFound {
		t.Errorf("unknown app: want 404 before the body is judged, got %d", w.Code)
	}
	assertNoComposeJob(t, f, got)
}

// A catalog app's compose changes only to a signed tile's or back to one it
// already ran, and a custom app has no tile: the wrong variant for the kind is
// a 409, with no job and nothing written.
func TestAppsCompose_WrongVariantForTheAppKindIs409(t *testing.T) {
	f, cookie, _, got := upgradeFixture(t)
	seedUpgradeApp(t, f, "cat", "vw", "vaultwarden", "services: {old: {}}\n", 3)
	seedUpgradeApp(t, f, "custom", "mine", "", customOld, 0)

	w := f.do(t, http.MethodPut, "/api/apps/cat/compose", composeYAMLBody(t, customNew), cookie)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "installed from the catalog") {
		t.Errorf("composeYaml on a catalog app: want 409, got %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secretMarker) {
		t.Error("the refusal echoed the submitted compose")
	}
	if w := f.do(t, http.MethodPut, "/api/apps/custom/compose", catalogBody, cookie); w.Code != http.StatusConflict {
		t.Errorf("source catalog on a custom app: want 409, got %d (%s)", w.Code, w.Body.String())
	}
	// A compose identical to the catalog app's own is still the wrong kind,
	// not a no-op: what a catalog app may be sent does not depend on content.
	cat, _ := f.appsStore.Get(f.ctx, "cat")
	if w := f.do(t, http.MethodPut, "/api/apps/cat/compose", composeYAMLBody(t, cat.ComposeYAML), cookie); w.Code != http.StatusConflict {
		t.Errorf("a catalog app's own compose as composeYaml: want 409, got %d", w.Code)
	}
	assertNoComposeJob(t, f, got)
	if after, _ := f.appsStore.Get(f.ctx, "cat"); after.ComposeYAML != cat.ComposeYAML || after.PreviousComposeYAML != "" {
		t.Error("a refusal wrote the catalog app's row")
	}
}

// The done-means of #410 through the route: a custom app's compose is
// replaced, redeployed to the same ULID, and the compose is nowhere in the
// job — not the 202, its spec, its steps, its events or the job list — nor
// held once the job has ended. The same PUT again is a no-op.
func TestAppsCompose_CustomEditRedeploysInPlaceAndNeverRecordsTheCompose(t *testing.T) {
	f, cookie, _, got := upgradeFixture(t)
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	seedUpgradeApp(t, f, id, "mine", "", customOld, 0)

	w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", composeYAMLBody(t, customNew), cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("edit: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secretMarker) {
		t.Errorf("the 202 carries the submitted compose: %s", w.Body.String())
	}
	job := decodeBody[jobs.Job](t, w.Body.String())
	if job.Kind != "app.edit" || string(job.Spec) != `{"appId":"`+id+`"}` {
		t.Fatalf("job = %s %s, want app.edit keyed only by appId", job.Kind, job.Spec)
	}
	f.runner.Wait()
	if j, _ := f.jobsStore.GetJob(f.ctx, job.ID); j == nil || j.Status != jobs.StatusSucceeded {
		t.Fatalf("edit job did not succeed: %+v", j)
	}
	assertJobCarriesNoCompose(t, f, cookie, job.ID)
	if n := f.srv.composeStash.Len(); n != 0 {
		t.Errorf("%d composes still held after the job succeeded", n)
	}

	select {
	case cmd := <-got:
		if cmd.AppID != id || cmd.ComposeYAML != customNew {
			t.Errorf("agent was sent %s %q, want the submitted compose for the same app", cmd.AppID, cmd.ComposeYAML)
		}
		if proto.AppProjectName(cmd.AppID) != proto.AppProjectName(id) || proto.AppVolumeName(cmd.AppID, "data") != proto.AppVolumeName(id, "data") {
			t.Error("project/volume naming changed across the edit")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received the edit's deploy")
	}
	after, _ := f.appsStore.Get(f.ctx, id)
	if after.ID != id || after.Name != "mine" || after.TargetNode != "n1" || !after.ExposeLAN || after.PublishedPort != 1234 ||
		after.BackupAck == nil || after.BackupAck.By != "alice" {
		t.Errorf("identity or an owner choice changed: %+v", after)
	}
	r := getRow(t, f, cookie, id)
	if r.ComposeYAML != customNew || r.PreviousComposeYAML != customOld || !r.RevertAvailable ||
		r.PreviousComposeSHA256 != apps.ComposeHash(customOld) || r.UpgradeAvailable {
		t.Errorf("row after the edit = %+v", r)
	}

	w = f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", composeYAMLBody(t, customNew), cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("repeated edit: want 200 no-op, got %d (%s)", w.Code, w.Body.String())
	}
	if decodeBody[revertRow](t, w.Body.String()).ComposeSHA256 != apps.ComposeHash(customNew) {
		t.Errorf("the no-op did not answer with the app's current state: %s", w.Body.String())
	}
	f.runner.Wait()
	if js, _ := f.jobsStore.ListJobsByKind(f.ctx, "app.edit", 10); len(js) != 1 {
		t.Errorf("the repeated PUT started a job: %d app.edit jobs", len(js))
	}
}

// A failed edit discards the held compose too, and its failure — the job's
// error, its steps, its events — does not carry it.
func TestAppsCompose_AFailedEditDiscardsTheComposeAndDoesNotRecordIt(t *testing.T) {
	f, cookie, _, _ := upgradeFixture(t)
	now := time.Now().UTC()
	if err := f.inv.Insert(f.ctx, &proto.Node{ID: "n2", Role: proto.RoleCompute, Hostname: "n2.test", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	sub, err := f.nc.Subscribe(proto.AppPullSubject("n2"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppPullAck{OK: false, Detail: "docker compose pull: manifest unknown"})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	a := seedUpgradeApp(t, f, "a", "mine", "", customOld, 0)
	if _, err := f.appsStore.Get(f.ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	// seedUpgradeApp targets n1; this one needs the failing node.
	if err := f.appsStore.Delete(f.ctx, "a"); err != nil {
		t.Fatal(err)
	}
	a.TargetNode = "n2"
	if err := f.appsStore.Create(f.ctx, a); err != nil {
		t.Fatal(err)
	}

	w := f.do(t, http.MethodPut, "/api/apps/a/compose", composeYAMLBody(t, customNew), cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("edit: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	job := decodeBody[jobs.Job](t, w.Body.String())
	f.runner.Wait()
	j, _ := f.jobsStore.GetJob(f.ctx, job.ID)
	if j == nil || j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "manifest unknown") {
		t.Fatalf("job = %+v, want failed at the pull", j)
	}
	assertJobCarriesNoCompose(t, f, cookie, job.ID)
	if n := f.srv.composeStash.Len(); n != 0 {
		t.Errorf("%d composes still held after the job failed", n)
	}
	if after, _ := f.appsStore.Get(f.ctx, "a"); after.ComposeYAML != customOld || after.PreviousComposeYAML != "" {
		t.Errorf("a failed pull wrote the row: compose=%q previous=%q", after.ComposeYAML, after.PreviousComposeYAML)
	}
}

// Nothing is held for a request that never becomes a job.
func TestAppsCompose_ARefusedEditHoldsNothing(t *testing.T) {
	f, cookie, _, _ := upgradeFixture(t)
	seedUpgradeApp(t, f, "cat", "vw", "vaultwarden", "services: {old: {}}\n", 3)
	seedUpgradeApp(t, f, "custom", "mine", "", customOld, 0)
	f.do(t, http.MethodPut, "/api/apps/cat/compose", composeYAMLBody(t, customNew), cookie)
	f.do(t, http.MethodPut, "/api/apps/custom/compose", `{"composeYaml":"`+secretMarker+`","sha256":"x"}`, cookie)
	f.do(t, http.MethodPut, "/api/apps/custom/compose", composeYAMLBody(t, customOld), cookie) // no-op
	if n := f.srv.composeStash.Len(); n != 0 {
		t.Errorf("%d composes held for requests that started no job", n)
	}

	// And with no app.edit workflow registered, the submit fails after the
	// kind check and before anything is held.
	g := newAPIFixture(t)
	gc := g.authenticate(t)
	stash := apps.NewComposeStash()
	g.srv.SetComposeStash(stash)
	seedUpgradeApp(t, g, "custom", "mine", "", customOld, 0)
	if w := g.do(t, http.MethodPut, "/api/apps/custom/compose", composeYAMLBody(t, customNew), gc); w.Code != http.StatusBadRequest {
		t.Errorf("unregistered app.edit: want the runner's 400, got %d (%s)", w.Code, w.Body.String())
	}
	if stash.Len() != 0 {
		t.Error("a submit that failed left the compose held")
	}
}

func TestAppsCompose_ReapplyRefusals(t *testing.T) {
	f, cookie, _, got := upgradeFixture(t)
	seedUpgradeApp(t, f, "never", "vw", "vaultwarden", "services: {old: {}}\n", 3)
	seedUpgradeApp(t, f, "custom", "mine", "", customOld, 0)

	for _, id := range []string{"never", "custom"} {
		w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", shaBody("services: {something: {else}}\n"), cookie)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "no compose with that sha256") {
			t.Errorf("%s, unknown hash: want 409, got %d (%s)", id, w.Code, w.Body.String())
		}
	}
	// The installed hash is the no-op for both kinds, previous compose or not.
	w := f.do(t, http.MethodPut, "/api/apps/custom/compose", shaBody(customOld), cookie)
	if w.Code != http.StatusOK {
		t.Errorf("installed hash on a custom app: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	never, _ := f.appsStore.Get(f.ctx, "never")
	// Upper-case hex names the same hash.
	if w := f.do(t, http.MethodPut, "/api/apps/never/compose", `{"sha256":"`+strings.ToUpper(never.ComposeSHA256)+`"}`, cookie); w.Code != http.StatusOK {
		t.Errorf("installed hash on a catalog app: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	assertNoComposeJob(t, f, got)

	r := getRow(t, f, cookie, "never")
	if r.RevertAvailable || r.PreviousComposeSHA256 != "" {
		t.Errorf("never-changed app: revertAvailable=%v previousComposeSha256=%q", r.RevertAvailable, r.PreviousComposeSHA256)
	}
	if w := f.do(t, http.MethodGet, "/api/apps/never", "", cookie); !strings.Contains(w.Body.String(), `"revertAvailable":false`) {
		t.Errorf("revertAvailable:false not in %s", w.Body.String())
	}
}

// Upgrade, then re-apply by hash: the row goes back to the compose (and
// catalog version) it had, the agent is sent that compose for the same app,
// and the upgrade is on offer again. The same PUT again is a no-op — no
// bounce. Naming the other hash goes forward.
func TestAppsCompose_ReapplyByHashDoesNotBounce(t *testing.T) {
	f, cookie, cat, got := upgradeFixture(t)
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	const old = "services: {old: {}}\n"
	seedUpgradeApp(t, f, id, "vw", "vaultwarden", old, 3)
	tile := tileCompose(t, cat, "vaultwarden")

	if w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", catalogBody, cookie); w.Code != http.StatusAccepted {
		t.Fatalf("upgrade: %d %s", w.Code, w.Body.String())
	}
	f.runner.Wait()
	<-got

	r := getRow(t, f, cookie, id)
	if !r.RevertAvailable || r.UpgradeAvailable || r.PreviousComposeSHA256 != apps.ComposeHash(old) {
		t.Fatalf("after the upgrade: %+v", r)
	}

	w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", `{"sha256":"`+r.PreviousComposeSHA256+`"}`, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("re-apply: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	job := decodeBody[jobs.Job](t, w.Body.String())
	spec := decodeBody[apps.RevertSpec](t, string(job.Spec))
	if job.Kind != "app.revert" || spec.AppID != id || spec.ComposeSHA256 != apps.ComposeHash(old) {
		t.Fatalf("job = %s %s, want app.revert naming the old compose's hash", job.Kind, job.Spec)
	}
	f.runner.Wait()
	if j, _ := f.jobsStore.GetJob(f.ctx, job.ID); j == nil || j.Status != jobs.StatusSucceeded {
		t.Fatalf("re-apply job did not succeed: %+v", j)
	}
	select {
	case cmd := <-got:
		if cmd.AppID != id || cmd.ComposeYAML != old {
			t.Errorf("agent was sent app %q compose %q, want %q with the previous compose", cmd.AppID, cmd.ComposeYAML, id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received the re-apply's deploy")
	}
	r = getRow(t, f, cookie, id)
	if r.ComposeYAML != old || r.PreviousComposeYAML != tile || r.ComposeCatalogVersion != 3 {
		t.Errorf("row after re-apply: compose=%q previous=%q version=%d, want the old compose back from v3", r.ComposeYAML, r.PreviousComposeYAML, r.ComposeCatalogVersion)
	}
	if !r.UpgradeAvailable || !r.RevertAvailable {
		t.Errorf("after re-apply: upgradeAvailable=%v revertAvailable=%v, want both true", r.UpgradeAvailable, r.RevertAvailable)
	}

	// The same request again: already installed, so 200, no job, no deploy,
	// and the row stays on the old compose.
	w = f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", shaBody(old), cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("repeated re-apply: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	f.runner.Wait()
	if js, _ := f.jobsStore.ListJobsByKind(f.ctx, "app.revert", 10); len(js) != 1 {
		t.Errorf("the repeated PUT started a job: %d app.revert jobs", len(js))
	}
	select {
	case cmd := <-got:
		t.Fatalf("the repeated PUT reached the agent: %+v", cmd)
	default:
	}
	if r := getRow(t, f, cookie, id); r.ComposeYAML != old {
		t.Errorf("the repeated PUT bounced the compose to %q", r.ComposeYAML)
	}

	// Forward again is a request of its own, naming the tile compose's hash.
	if w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", shaBody(tile), cookie); w.Code != http.StatusAccepted {
		t.Fatalf("forward re-apply: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	f.runner.Wait()
	<-got
	if r := getRow(t, f, cookie, id); r.ComposeYAML != tile || r.UpgradeAvailable {
		t.Errorf("forward re-apply: compose=%q upgradeAvailable=%v", r.ComposeYAML, r.UpgradeAvailable)
	}
	if a, _ := f.appsStore.Get(f.ctx, id); a.LastStatus != proto.AppStatusRunning {
		t.Errorf("status = %s, want running", a.LastStatus)
	}
}

// A custom app goes back by hash too, after an edit, and its previous compose
// is re-applied from the row.
func TestAppsCompose_CustomAppReappliesByHash(t *testing.T) {
	f, cookie, _, got := upgradeFixture(t)
	seedUpgradeApp(t, f, "c", "mine", "", customOld, 0)
	if w := f.do(t, http.MethodPut, "/api/apps/c/compose", composeYAMLBody(t, customNew), cookie); w.Code != http.StatusAccepted {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}
	f.runner.Wait()
	<-got
	w := f.do(t, http.MethodPut, "/api/apps/c/compose", shaBody(customOld), cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("re-apply: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	job := decodeBody[jobs.Job](t, w.Body.String())
	f.runner.Wait()
	if cmd := <-got; cmd.AppID != "c" || cmd.ComposeYAML != customOld {
		t.Errorf("agent was sent %s %q, want the old compose", cmd.AppID, cmd.ComposeYAML)
	}
	assertJobCarriesNoCompose(t, f, cookie, job.ID)
	if r := getRow(t, f, cookie, "c"); r.ComposeYAML != customOld || r.PreviousComposeYAML != customNew {
		t.Errorf("row = %+v", r)
	}
}

// The verb routes this resource replaced are gone. No release carried them,
// so there is no alias: a client that calls them gets no job.
func TestAppsCompose_TheRemovedVerbRoutesAreGone(t *testing.T) {
	f, cookie, _, got := upgradeFixture(t)
	seedUpgradeApp(t, f, "a", "vw", "vaultwarden", "services: {old: {}}\n", 3)
	for _, path := range []string{"/api/apps/a/upgrade", "/api/apps/a/revert"} {
		w := f.do(t, http.MethodPost, path, catalogBody, cookie)
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: want 404 or 405, got %d (%s)", path, w.Code, w.Body.String())
		}
	}
	// And the resource takes PUT only.
	if w := f.do(t, http.MethodPost, "/api/apps/a/compose", catalogBody, cookie); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/apps/a/compose: want 404 or 405, got %d", w.Code)
	}
	assertNoComposeJob(t, f, got)
}
