package alerts

import (
	"context"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-1127-12: the restored alert is one persisted row per job, firing, a
// warning under the security source with its exact labels, title and detail;
// a second raise for the same job adds no row and publishes nothing.
func TestRaiseIdentityAdminRestored(t *testing.T) {
	ctx := context.Background()
	svc, store := nodeKeyService(t)
	nc, changes := embeddedNATS(t)
	svc.nc = nc
	for _, id := range []string{"J1", "J1", "J2"} {
		if err := svc.RaiseIdentityAdminRestored(ctx, id); err != nil {
			t.Fatalf("raise %s: %v", id, err)
		}
	}
	rows, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2: %+v", len(rows), rows)
	}
	var jobs []string
	for _, r := range rows {
		want := map[string]string{"alertname": "IdentityAdminRestored", "severity": "warning", "source": "security", "jobId": r.Labels["jobId"]}
		if len(r.Labels) != len(want) {
			t.Errorf("labels = %v, want %v", r.Labels, want)
		}
		for k, v := range want {
			if r.Labels[k] != v {
				t.Errorf("label %s = %q, want %q", k, r.Labels[k], v)
			}
		}
		jobs = append(jobs, r.Labels["jobId"])
		if r.ID != "identity-admin-restored:"+fingerprintFromLabels(r.Labels) || r.Fingerprint != fingerprintFromLabels(r.Labels) {
			t.Errorf("id = %q, fingerprint %q", r.ID, r.Fingerprint)
		}
		if r.Status != "firing" || r.Severity != proto.AlertWarn {
			t.Errorf("status %q severity %q, want firing warn", r.Status, r.Severity)
		}
		if r.Title != "The control plane's admin client at the sign-in service was restored." {
			t.Errorf("title = %q", r.Title)
		}
		if r.Detail != "The control plane was refused as its sign-in service's administrator, so it re-created its admin client from the shipped baseline. Nothing in Rasputin removes that client; see Tasks for the run." {
			t.Errorf("detail = %q", r.Detail)
		}
		if a := toAlert(r); a.Source != proto.AlertSourceSecurity {
			t.Errorf("source = %q, want security", a.Source)
		}
	}
	slices.Sort(jobs)
	if !slices.Equal(jobs, []string{"J1", "J2"}) {
		t.Errorf("jobs = %v", jobs)
	}
	if c := changes.changes(t); !slices.Equal(c, []proto.AlertChangeType{proto.AlertFired, proto.AlertFired}) {
		t.Errorf("published %v, want two fired", c)
	}
}

// With no store (the aggregator-only configuration) raising is a no-op.
func TestRaiseIdentityAdminRestored_NoStore(t *testing.T) {
	if err := (&Service{}).RaiseIdentityAdminRestored(context.Background(), "J1"); err != nil {
		t.Fatal(err)
	}
}
