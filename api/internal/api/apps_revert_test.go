package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Re-applying an app's previous compose through the route
// (geekdojo/geekdojo-brain#411): revertAvailable on both reads, the refusals,
// and a re-apply that takes the compose from the row whatever the body says.

type revertRow struct {
	ID                    string `json:"id"`
	ComposeYAML           string `json:"composeYaml"`
	PreviousComposeYAML   string `json:"previousComposeYaml"`
	ComposeCatalogVersion int    `json:"composeCatalogVersion"`
	UpgradeAvailable      bool   `json:"upgradeAvailable"`
	RevertAvailable       bool   `json:"revertAvailable"`
}

func TestAppsRevert_RefusalsAndAvailability(t *testing.T) {
	f, cookie, _, got := upgradeFixture(t)
	seedUpgradeApp(t, f, "never", "vw", "vaultwarden", "services: {old: {}}\n", 3)

	if w := f.do(t, http.MethodPost, "/api/apps/ghost/revert", "", cookie); w.Code != http.StatusNotFound {
		t.Errorf("unknown app: want 404, got %d (%s)", w.Code, w.Body.String())
	}
	w := f.do(t, http.MethodPost, "/api/apps/never/revert", "", cookie)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "no previous compose") {
		t.Errorf("never upgraded: want 409 naming the missing previous compose, got %d (%s)", w.Code, w.Body.String())
	}
	f.runner.Wait()
	if js, _ := f.jobsStore.ListJobsByKind(f.ctx, "app.revert", 10); len(js) != 0 {
		t.Errorf("a refusal must not create a job; found %d", len(js))
	}
	select {
	case cmd := <-got:
		t.Errorf("a refused re-apply reached the agent: %+v", cmd)
	default:
	}

	w = f.do(t, http.MethodGet, "/api/apps/never", "", cookie)
	if !strings.Contains(w.Body.String(), `"revertAvailable":false`) {
		t.Errorf("get never-upgraded app: revertAvailable:false not in %s", w.Body.String())
	}
}

// Upgrade, then re-apply: the row goes back to the compose (and catalog
// version) it had, the agent is sent that compose for the same app, the
// upgrade is on offer again, and the re-apply can itself be re-applied. A body
// naming another compose is not read.
func TestAppsRevert_ReappliesThePreviousComposeFromTheRow(t *testing.T) {
	f, cookie, cat, got := upgradeFixture(t)
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	const old = "services: {old: {}}\n"
	seedUpgradeApp(t, f, id, "vw", "vaultwarden", old, 3)
	tile := tileCompose(t, cat, "vaultwarden")

	if w := f.do(t, http.MethodPost, "/api/apps/"+id+"/upgrade", "", cookie); w.Code != http.StatusAccepted {
		t.Fatalf("upgrade: %d %s", w.Code, w.Body.String())
	}
	f.runner.Wait()
	<-got

	w := f.do(t, http.MethodGet, "/api/apps/"+id, "", cookie)
	var r revertRow
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if !r.RevertAvailable || r.UpgradeAvailable {
		t.Fatalf("after the upgrade: revertAvailable=%v upgradeAvailable=%v, want true/false", r.RevertAvailable, r.UpgradeAvailable)
	}

	body := `{"composeYaml":"services:\n  evil:\n    image: evil/evil:latest\n"}`
	w = f.do(t, http.MethodPost, "/api/apps/"+id+"/revert", body, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("revert: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	job := decodeBody[jobs.Job](t, w.Body.String())
	if job.Kind != "app.revert" || strings.Contains(string(job.Spec), "evil") {
		t.Fatalf("job = %s %s, want app.revert keyed only by appId", job.Kind, job.Spec)
	}
	f.runner.Wait()
	if j, _ := f.jobsStore.GetJob(f.ctx, job.ID); j == nil || j.Status != jobs.StatusSucceeded {
		t.Fatalf("revert job did not succeed: %+v", j)
	}
	select {
	case cmd := <-got:
		if cmd.AppID != id || cmd.ComposeYAML != old {
			t.Errorf("agent was sent app %q compose %q, want %q with the previous compose", cmd.AppID, cmd.ComposeYAML, id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received the re-apply's deploy")
	}

	w = f.do(t, http.MethodGet, "/api/apps/"+id, "", cookie)
	r = revertRow{}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.ComposeYAML != old || r.PreviousComposeYAML != tile || r.ComposeCatalogVersion != 3 {
		t.Errorf("row after re-apply: compose=%q previous=%q version=%d, want the old compose back from v3", r.ComposeYAML, r.PreviousComposeYAML, r.ComposeCatalogVersion)
	}
	if !r.UpgradeAvailable || !r.RevertAvailable {
		t.Errorf("after re-apply: upgradeAvailable=%v revertAvailable=%v, want both true", r.UpgradeAvailable, r.RevertAvailable)
	}
	if a, _ := f.appsStore.Get(f.ctx, id); a.LastStatus != proto.AppStatusRunning {
		t.Errorf("status = %s, want running", a.LastStatus)
	}
}
