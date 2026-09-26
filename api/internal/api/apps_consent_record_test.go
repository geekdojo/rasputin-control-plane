package api

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// A stored privilege consent that cannot be read (#522 follow-up): the app
// and the apps list still load; only a tier-raising upgrade of that app is
// refused, saying which record is bad and how to replace it; and consenting
// again on the upgrade replaces it.

// corruptConsent writes an undecodable consent record straight into the apps
// database, as a bad disk or a hand edit would leave it.
func corruptConsent(t *testing.T, f *apiFixture, id string) {
	t.Helper()
	db, err := dbutil.Open(f.ctx, filepath.Join(f.dir, "apps.db"), "SELECT 1", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(f.ctx, `UPDATE apps SET privilege_ack_at = 1, privilege_ack_by = 'bryce', privilege_ack_what = '{not json' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
}

func TestAppsConsentRecord_UnreadableDoesNotBreakGetOrList(t *testing.T) {
	f, cookie, _, _ := upgradeFixtureWith(t, hostTrustingBundleTile())
	seedTieredApp(t, f, haID, "ha", "homeassistant", tileschema.TierRoutine)
	seedTieredApp(t, f, downID, "down", "jellyfin", tileschema.TierRoutine)
	corruptConsent(t, f, haID)

	w := f.do(t, http.MethodGet, "/api/apps/"+haID, "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("GET one: %d %s", w.Code, w.Body.String())
	}
	r := decodeBody[consentRow](t, w.Body.String())
	if r.PrivilegeAck == nil || !r.PrivilegeAck.Unreadable || !r.UpgradeRaisesPrivilege {
		t.Errorf("GET one = %+v, want the record flagged unreadable and the raise still on offer", r)
	}

	w = f.do(t, http.MethodGet, "/api/apps", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("GET list: %d %s", w.Code, w.Body.String())
	}
	if rows := decodeBody[[]consentRow](t, w.Body.String()); len(rows) != 2 {
		t.Errorf("GET list returned %d apps, want both", len(rows))
	}
}

func TestAppsConsentRecord_UnreadableRefusesARaiseUntilReConsented(t *testing.T) {
	f, cookie, cat, got := upgradeFixtureWith(t, hostTrustingBundleTile())
	seedTieredApp(t, f, haID, "ha", "homeassistant", tileschema.TierRoutine)
	corruptConsent(t, f, haID)

	// No consent in the request: refused, and the refusal names the record.
	w := f.do(t, http.MethodPut, "/api/apps/"+haID+"/compose", catalogBody, cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("raise with an unreadable record: want 409, got %d (%s)", w.Code, w.Body.String())
	}
	for _, says := range []string{"unreadable", "acceptPrivilegeTier", "replaces it"} {
		if !strings.Contains(w.Body.String(), says) {
			t.Errorf("409 %s does not say %q", w.Body.String(), says)
		}
	}
	assertNoComposeJob(t, f, got)

	// A job started directly is refused in the saga, over the same record.
	w = f.do(t, http.MethodPost, "/api/jobs", `{"kind":"app.upgrade","spec":{"appId":"`+haID+`"}}`, cookie)
	job := decodeBody[jobs.Job](t, w.Body.String())
	waitForJobs(t, f.runner)
	if j, _ := f.jobsStore.GetJob(f.ctx, job.ID); j == nil || j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "unreadable") {
		t.Fatalf("direct job = %+v, want it failed naming the unreadable record", j)
	}

	// Consenting again replaces the record, and the upgrade goes through.
	w = f.do(t, http.MethodPut, "/api/apps/"+haID+"/compose", `{"source":"catalog","acceptPrivilegeTier":"host-trusting"}`, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("re-consent: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	job = decodeBody[jobs.Job](t, w.Body.String())
	waitForJobs(t, f.runner)
	if j, _ := f.jobsStore.GetJob(f.ctx, job.ID); j == nil || j.Status != jobs.StatusSucceeded {
		t.Fatalf("re-consented job did not succeed: %+v", j)
	}
	receiveWithin(t, got, "the re-consented upgrade never deployed")
	row, err := f.appsStore.Get(f.ctx, haID)
	if err != nil {
		t.Fatal(err)
	}
	want := tileCompose(t, cat, "homeassistant")
	if row.PrivilegeAck == nil || row.PrivilegeAck.Unreadable || row.PrivilegeAck.By != "alice" ||
		row.PrivilegeAck.What.ComposeSHA256 != apps.ComposeHash(want) || row.PrivilegeTier != tileschema.TierHostTrusting {
		t.Errorf("after re-consent: tier=%q ack=%+v", row.PrivilegeTier, row.PrivilegeAck)
	}
}
