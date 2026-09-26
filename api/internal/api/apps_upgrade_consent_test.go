package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Server-enforced consent on a catalog upgrade that raises the app's privilege
// tier (auth-methodology §9 dec 12, geekdojo/geekdojo-brain#522), through the
// real router: PUT /api/apps/{id}/compose {"source":"catalog"} refuses a raise
// with 409 unless the body carries "acceptPrivilegeTier", records the consent
// {at, by, what} when it does, and asks nothing of an upgrade that keeps or
// lowers the tier. Install is unchanged: it asks nothing.

// hostTrustingBundleTile is a live, installable tile that declares the top tier
// and passes the bundle's own safety gates: a privileged service, declared.
func hostTrustingBundleTile() tileschema.BundleTile {
	bt := oneTileBundle(upgradeCatalogVersion, "homeassistant").Tiles[0]
	image := "e/homeassistant:1@sha256:" + strings.Repeat("b", 64)
	bt.Tile.Name = "Home Assistant"
	bt.Tile.Status = ""
	bt.Tile.Requires = []string{tileschema.CapabilityPrivilegeTiers}
	bt.Tile.Privilege = &tileschema.Privilege{
		Tier:   tileschema.TierHostTrusting,
		Grants: []string{tileschema.GrantPrivileged},
		Why:    "discovers devices and talks to USB radios",
	}
	bt.Compose = "services:\n  ha:\n    image: " + image + "\n    privileged: true\n"
	bt.Tile.ComposeYAML = bt.Compose
	bt.Safety = tileschema.SafetyFacts{Images: []string{image}, Privileged: true}
	return bt
}

// App ids are ULIDs: every app job spec is decoded strictly.
const (
	haID   = "01J9ZK3Q0M8X7Y6W5V4T3S2HA0"
	downID = "01J9ZK3Q0M8X7Y6W5V4T3S2DN0"
	sameID = "01J9ZK3Q0M8X7Y6W5V4T3S2SM0"
	mineID = "01J9ZK3Q0M8X7Y6W5V4T3S2MN0"
)

// seedTieredApp is seedUpgradeApp with the privilege tier install recorded.
func seedTieredApp(t *testing.T, f *apiFixture, id, name, tile, tier string) *apps.App {
	t.Helper()
	now := time.Now().UTC()
	a := &apps.App{
		ID: id, Name: name, ComposeYAML: "services: {old: {}}\n", TargetNode: "n1", SourceTile: tile,
		ComposeCatalogVersion: 3, PrivilegeTier: tier,
		LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now,
	}
	if err := f.appsStore.Create(f.ctx, a); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
	return a
}

type privilegeRaiseBody struct {
	Error          string `json:"error"`
	PrivilegeRaise *struct {
		FromTier         string   `json:"fromTier"`
		FromTierRecorded bool     `json:"fromTierRecorded"`
		Tier             string   `json:"tier"`
		DockerSocket     bool     `json:"dockerSocket"`
		Grants           []string `json:"grants"`
		Why              string   `json:"why"`
		CatalogVersion   int      `json:"catalogVersion"`
	} `json:"privilegeRaise"`
}

type consentRow struct {
	ID                     string                `json:"id"`
	PrivilegeTier          string                `json:"privilegeTier"`
	PrivilegeAck           *apps.PrivilegeAck    `json:"privilegeAck"`
	UpgradeAvailable       bool                  `json:"upgradeAvailable"`
	UpgradeRaisesPrivilege bool                  `json:"upgradeRaisesPrivilege"`
	UpgradePrivilege       *tileschema.Privilege `json:"upgradePrivilege"`
}

// routine → host-trusting: refused without consent, and the refusal says
// plainly what is being raised and what consent is needed. Nothing is started,
// recorded or sent.
func TestAppsUpgradeConsent_RaiseWithoutConsentIsRefused(t *testing.T) {
	f, cookie, _, got := upgradeFixtureWith(t, hostTrustingBundleTile())
	seedTieredApp(t, f, haID, "ha", "homeassistant", tileschema.TierRoutine)

	for _, body := range []string{
		catalogBody,
		// Consent to a tier below the one the upgrade takes is not consent to it.
		`{"source":"catalog","acceptPrivilegeTier":"elevated"}`,
	} {
		w := f.do(t, http.MethodPut, "/api/apps/"+haID+"/compose", body, cookie)
		if w.Code != http.StatusConflict {
			t.Fatalf("%s: want 409, got %d (%s)", body, w.Code, w.Body.String())
		}
		r := decodeBody[privilegeRaiseBody](t, w.Body.String())
		if r.PrivilegeRaise == nil {
			t.Fatalf("%s: 409 carries no privilegeRaise: %s", body, w.Body.String())
		}
		pr := r.PrivilegeRaise
		if pr.FromTier != tileschema.TierRoutine || !pr.FromTierRecorded || pr.Tier != tileschema.TierHostTrusting ||
			len(pr.Grants) != 1 || pr.Grants[0] != tileschema.GrantPrivileged || pr.Why == "" ||
			pr.CatalogVersion != upgradeCatalogVersion {
			t.Errorf("%s: privilegeRaise = %+v", body, *pr)
		}
		for _, says := range []string{"ROUTINE", "HOST-TRUSTING", `"acceptPrivilegeTier"`, `"host-trusting"`} {
			if !strings.Contains(r.Error, says) {
				t.Errorf("%s: refusal %q does not say %s", body, r.Error, says)
			}
		}
	}
	assertNoComposeJob(t, f, got)
	if row, _ := f.appsStore.Get(f.ctx, haID); row.PrivilegeAck != nil || row.PrivilegeTier != tileschema.TierRoutine {
		t.Errorf("a refusal recorded something: tier=%q ack=%+v", row.PrivilegeTier, row.PrivilegeAck)
	}

	// The Apps page learns the same thing before it asks.
	w := f.do(t, http.MethodGet, "/api/apps/"+haID, "", cookie)
	r := decodeBody[consentRow](t, w.Body.String())
	if !r.UpgradeAvailable || !r.UpgradeRaisesPrivilege || r.UpgradePrivilege == nil ||
		r.UpgradePrivilege.Tier != tileschema.TierHostTrusting || r.PrivilegeTier != tileschema.TierRoutine {
		t.Errorf("GET /api/apps/ha = %+v, want the raise described", r)
	}
}

// With consent the upgrade is accepted, runs, and the row records who
// consented, when, and exactly what they accepted.
func TestAppsUpgradeConsent_RaiseWithConsentIsAcceptedAndRecorded(t *testing.T) {
	f, cookie, cat, got := upgradeFixtureWith(t, hostTrustingBundleTile())
	seedTieredApp(t, f, haID, "ha", "homeassistant", tileschema.TierRoutine)
	before := time.Now().UTC().Add(-time.Second)

	w := f.do(t, http.MethodPut, "/api/apps/"+haID+"/compose", `{"source":"catalog","acceptPrivilegeTier":"host-trusting"}`, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("consented upgrade: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	job := decodeBody[jobs.Job](t, w.Body.String())
	if string(job.Spec) != `{"appId":"`+haID+`"}` {
		t.Errorf("spec = %s: consent is recorded on the app, never carried in a spec", job.Spec)
	}
	waitForJobs(t, f.runner)
	if j, _ := f.jobsStore.GetJob(f.ctx, job.ID); j == nil || j.Status != jobs.StatusSucceeded {
		t.Fatalf("job did not succeed: %+v", j)
	}
	receiveWithin(t, got, "the consented upgrade never deployed")

	row, _ := f.appsStore.Get(f.ctx, haID)
	want := tileCompose(t, cat, "homeassistant")
	if row.ComposeYAML != want || row.PrivilegeTier != tileschema.TierHostTrusting || row.PreviousPrivilegeTier != tileschema.TierRoutine {
		t.Errorf("row after upgrade: tier=%q previous=%q", row.PrivilegeTier, row.PreviousPrivilegeTier)
	}
	ack := row.PrivilegeAck
	if ack == nil {
		t.Fatal("no consent recorded")
	}
	if ack.By != "alice" || ack.At.Before(before) || ack.At.After(time.Now().UTC().Add(time.Second)) {
		t.Errorf("ack by=%q at=%v", ack.By, ack.At)
	}
	if ack.What.FromTier != tileschema.TierRoutine || ack.What.Tier != tileschema.TierHostTrusting ||
		len(ack.What.Grants) != 1 || ack.What.Grants[0] != tileschema.GrantPrivileged ||
		ack.What.CatalogVersion != upgradeCatalogVersion || ack.What.ComposeSHA256 != apps.ComposeHash(want) {
		t.Errorf("ack.what = %+v", ack.What)
	}
	// And it is on the app as the API shows it.
	r := decodeBody[consentRow](t, f.do(t, http.MethodGet, "/api/apps/"+haID, "", cookie).Body.String())
	if r.PrivilegeAck == nil || r.PrivilegeAck.By != "alice" || r.PrivilegeTier != tileschema.TierHostTrusting {
		t.Errorf("GET after upgrade = %+v", r)
	}
}

// Keeping or lowering the tier needs no consent: host-trusting → routine, and
// host-trusting → host-trusting.
func TestAppsUpgradeConsent_EqualOrLowerTierNeedsNone(t *testing.T) {
	f, cookie, _, _ := upgradeFixtureWith(t, hostTrustingBundleTile())
	seedTieredApp(t, f, downID, "down", "jellyfin", tileschema.TierHostTrusting)
	seedTieredApp(t, f, sameID, "same", "homeassistant", tileschema.TierHostTrusting)

	for _, id := range []string{downID, sameID} {
		r := decodeBody[consentRow](t, f.do(t, http.MethodGet, "/api/apps/"+id, "", cookie).Body.String())
		if !r.UpgradeAvailable || r.UpgradeRaisesPrivilege {
			t.Errorf("%s: upgradeAvailable=%v upgradeRaisesPrivilege=%v", id, r.UpgradeAvailable, r.UpgradeRaisesPrivilege)
		}
		w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", catalogBody, cookie)
		if w.Code != http.StatusAccepted {
			t.Fatalf("%s: want 202, got %d (%s)", id, w.Code, w.Body.String())
		}
		waitForJobs(t, f.runner)
		job := decodeBody[jobs.Job](t, w.Body.String())
		if j, _ := f.jobsStore.GetJob(f.ctx, job.ID); j == nil || j.Status != jobs.StatusSucceeded {
			t.Fatalf("%s: job did not succeed: %+v", id, j)
		}
		row, _ := f.appsStore.Get(f.ctx, id)
		if row.PrivilegeAck != nil {
			t.Errorf("%s: an upgrade that needed no consent recorded one: %+v", id, row.PrivilegeAck)
		}
	}
	if row, _ := f.appsStore.Get(f.ctx, downID); row.PrivilegeTier != tileschema.TierRoutine {
		t.Errorf("down: tier after upgrade = %q, want routine", row.PrivilegeTier)
	}
}

// POST /api/jobs names any kind. An app.upgrade submitted there for a raise no
// request consented to fails in the saga, before the node is asked anything.
func TestAppsUpgradeConsent_ADirectJobCannotRaiseTheTier(t *testing.T) {
	f, cookie, _, got := upgradeFixtureWith(t, hostTrustingBundleTile())
	seedTieredApp(t, f, haID, "ha", "homeassistant", tileschema.TierRoutine)

	w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"app.upgrade","spec":{"appId":"`+haID+`"}}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	job := decodeBody[jobs.Job](t, w.Body.String())
	waitForJobs(t, f.runner)
	j, _ := f.jobsStore.GetJob(f.ctx, job.ID)
	if j == nil || j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "HOST-TRUSTING") {
		t.Fatalf("direct job = %+v, want it failed naming the tier", j)
	}
	select {
	case cmd := <-got:
		t.Fatalf("an unconsented raise reached the agent: %+v", cmd)
	default:
	}
	if row, _ := f.appsStore.Get(f.ctx, haID); row.ComposeYAML != "services: {old: {}}\n" || row.PrivilegeTier != tileschema.TierRoutine {
		t.Error("an unconsented direct job changed the row")
	}
}

// The consent field belongs to a catalog upgrade and names a tier this build
// knows; anything else is a malformed request, not a guess.
func TestAppsUpgradeConsent_MalformedConsentIs400(t *testing.T) {
	f, cookie, _, got := upgradeFixtureWith(t, hostTrustingBundleTile())
	seedTieredApp(t, f, haID, "ha", "homeassistant", tileschema.TierRoutine)
	seedTieredApp(t, f, mineID, "mine", "", "")

	for _, c := range []struct{ id, body string }{
		{haID, `{"source":"catalog","acceptPrivilegeTier":"HOST-TRUSTING"}`},
		{haID, `{"source":"catalog","acceptPrivilegeTier":""}`},
		{haID, `{"source":"catalog","acceptPrivilegeTier":"root"}`},
		{haID, `{"sha256":"` + strings.Repeat("a", 64) + `","acceptPrivilegeTier":"host-trusting"}`},
		{mineID, `{"composeYaml":"services: {}\n","acceptPrivilegeTier":"host-trusting"}`},
	} {
		if w := f.do(t, http.MethodPut, "/api/apps/"+c.id+"/compose", c.body, cookie); w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d (%s)", c.body, w.Code, w.Body.String())
		}
	}
	assertNoComposeJob(t, f, got)
}

// First install is unchanged (Bryce, 2026-09-12, reaffirmed by dec 12): a
// host-trusting tile installs with no consent in the body, and the tier it
// installed at is recorded for the next upgrade to compare against.
func TestAppsUpgradeConsent_InstallIsUnaffected(t *testing.T) {
	f, cookie, _, _ := upgradeFixtureWith(t, hostTrustingBundleTile())
	w := f.do(t, http.MethodPost, "/api/catalog/homeassistant/install", `{"targetNode":"n1"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("install: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	created := decodeBody[apps.App](t, w.Body.String())
	row, _ := f.appsStore.Get(f.ctx, created.ID)
	if row.PrivilegeTier != tileschema.TierHostTrusting || row.PrivilegeAck != nil {
		t.Errorf("installed tier=%q ack=%+v, want host-trusting and no consent record", row.PrivilegeTier, row.PrivilegeAck)
	}

	w = f.do(t, http.MethodPost, "/api/catalog/jellyfin/install", `{"targetNode":"n1"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("install jellyfin: %d %s", w.Code, w.Body.String())
	}
	created = decodeBody[apps.App](t, w.Body.String())
	if row, _ := f.appsStore.Get(f.ctx, created.ID); row.PrivilegeTier != tileschema.TierRoutine {
		t.Errorf("routine install recorded tier %q", row.PrivilegeTier)
	}
}

// Consent is recorded against a named user or not at all. The session
// middleware never lets a request through without one, so this calls the
// handler directly to prove the handler does not lean on that.
func TestAppsUpgradeConsent_NoUserRecordsNothing(t *testing.T) {
	f, _, _, got := upgradeFixtureWith(t, hostTrustingBundleTile())
	seedTieredApp(t, f, haID, "ha", "homeassistant", tileschema.TierRoutine)

	r := httptest.NewRequest(http.MethodPut, "/api/apps/"+haID+"/compose", strings.NewReader(`{"source":"catalog","acceptPrivilegeTier":"host-trusting"}`))
	r.SetPathValue("id", haID)
	w := httptest.NewRecorder()
	f.srv.handlePutAppCompose(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("no user: want 500, got %d (%s)", w.Code, w.Body.String())
	}
	assertNoComposeJob(t, f, got)
	if row, _ := f.appsStore.Get(f.ctx, haID); row.PrivilegeAck != nil {
		t.Errorf("a nameless consent was recorded: %+v", row.PrivilegeAck)
	}
}
