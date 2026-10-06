package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/console"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

var noopSteps = []jobs.WorkflowStep{{Name: "noop", Do: func(*jobs.StepCtx) (json.RawMessage, error) { return nil, nil }}}

// TC-825-18: every spec type a migrated caller now passes to the runner is
// stored as the bytes the previous release stored for the same input, which
// was json.Marshal of the same value (pinned here as literals), and nil is
// stored as {} where the previous release passed json.RawMessage("{}") or
// nothing. GET /api/jobs renders every one of them.
func TestTypedSpecs_StoredAsThePreviousReleaseStoredThem(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	cases := []struct {
		kind string
		spec any
		want string
	}{
		{"obs.enable", nil, `{}`},
		{"obs.disable", nil, `{}`},
		{"firewall.apply", nil, `{}`},
		{"mesh.reconcile", nil, `{}`},
		{"mesh.enroll_node", mesh.EnrollSpec{NodeID: "n1", AdvertiseRoutes: []string{"10.9.0.0/24"}}, `{"nodeId":"n1","advertiseRoutes":["10.9.0.0/24"]}`},
		{"bmc.configure", bmc.ConfigureSpec{Kind: "bitscope", HostNodeID: "h1", Config: json.RawMessage(`{"targets":[]}`), ConfigHash: "k1-ab"},
			`{"kind":"bitscope","hostNodeId":"h1","config":{"targets":[]},"configHash":"k1-ab"}`},
		{"bmc.power", bmc.Spec{TargetNodeID: "n1", Verb: "reset"}, `{"targetNodeId":"n1","verb":"reset"}`},
		{console.PushKind, console.PushSpec{NodeIDs: []string{"n1"}, Reason: "registration of n1"}, `{"nodeIds":["n1"],"reason":"registration of n1"}`},
		{"app.delete", apps.DeleteSpec{AppID: "a1", DeleteVolumes: []string{"rasp_a1_data"}}, `{"appId":"a1","deleteVolumes":["rasp_a1_data"]}`},
		{"app.deploy", map[string]string{"appId": "a1"}, `{"appId":"a1"}`},
		{"app.upgrade", apps.ComposeChangeSpec{AppID: "a1"}, `{"appId":"a1"}`},
		{"app.revert", apps.RevertSpec{AppID: "a1", ComposeSHA256: "ff"}, `{"appId":"a1","sha256":"ff"}`},
		{storage.RunJobKind, storage.RunSpec{Reason: storage.ReasonManual}, `{"reason":"manual"}`},
		{storage.RestoreAppJobKind, storage.RestoreAppSpec{AppID: "a1", PartUUID: "p", GenerationID: "g", KeyID: "k", SessionID: "s"},
			`{"appId":"a1","partUuid":"p","generationId":"g","keyId":"k","sessionId":"s"}`},
		{"firewall.set_active", firewall.SetActiveSpec{Active: true}, `{"active":true}`},
		{"system.update", proto.SystemUpdateSpec{Version: "2026.08.4"}, `{"version":"2026.08.4"}`},
		{"node.update", updater.UpdateSpec{NodeID: "n1", BundleSHA256: "ab"}, `{"nodeId":"n1","bundleSha256":"ab"}`},
		// system.update's child: a map, so its keys are stored sorted, as before.
		{"node.update.child", map[string]string{"nodeId": "n1", "bundleSha256": "ab"}, `{"bundleSha256":"ab","nodeId":"n1"}`},
		{obs.CollectorDeployKind, obs.CollectorNodeSpec{NodeID: "n1", CollectorKey: "ck", TrustFingerprint: "tf"},
			`{"nodeId":"n1","collectorKey":"ck","trustFingerprint":"tf"}`},
	}
	ids := map[string]string{}
	for _, tc := range cases {
		f.runner.Register(jobs.Workflow{Kind: tc.kind, Steps: noopSteps})
		want := tc.want
		if tc.spec != nil {
			marshalled, err := json.Marshal(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if want != string(marshalled) {
				t.Fatalf("%s: pinned bytes %s are not json.Marshal's %s", tc.kind, want, marshalled)
			}
		}
		j, err := f.runner.Submit(f.ctx, tc.kind, tc.spec, "test")
		if err != nil {
			t.Fatalf("%s: Submit: %v", tc.kind, err)
		}
		got, err := f.jobsStore.GetJob(f.ctx, j.ID)
		if err != nil {
			t.Fatal(err)
		}
		if string(got.Spec) != want {
			t.Errorf("%s: stored spec %s, want %s", tc.kind, got.Spec, want)
		}
		ids[j.ID] = want
	}
	f.runner.Wait()

	w := f.do(t, http.MethodGet, "/api/jobs?limit=100", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/jobs: %d %s", w.Code, w.Body.String())
	}
	var listed []*jobs.Job
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode /api/jobs: %v", err)
	}
	for _, j := range listed {
		if want, ok := ids[j.ID]; ok {
			if string(j.Spec) != want {
				t.Errorf("/api/jobs renders %s's spec as %s, want %s", j.Kind, j.Spec, want)
			}
			delete(ids, j.ID)
		}
	}
	if len(ids) != 0 {
		t.Errorf("/api/jobs omitted %d submitted jobs", len(ids))
	}
}

// TC-825-20: POST /api/jobs is raw JSON by nature and reaches the runner
// through SubmitRawSpec. A posted spec is stored byte for byte; no spec is
// stored as {}. Both answer 201.
func TestHandleCreateJob_StoresThePostedSpecThroughTheRawEntryPoint(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	f.runner.Register(jobs.Workflow{Kind: "diag.ping", Steps: noopSteps})
	for _, tc := range []struct {
		body, want string
	}{
		{`{"kind":"diag.ping","spec":{"nodeId":"n1"}}`, `{"nodeId":"n1"}`},
		{`{"kind":"diag.ping"}`, `{}`},
	} {
		w := f.do(t, http.MethodPost, "/api/jobs", tc.body, c)
		if w.Code != http.StatusCreated {
			t.Fatalf("POST %s: %d %s", tc.body, w.Code, w.Body.String())
		}
		var j jobs.Job
		if err := json.Unmarshal(w.Body.Bytes(), &j); err != nil {
			t.Fatal(err)
		}
		got, err := f.jobsStore.GetJob(f.ctx, j.ID)
		if err != nil {
			t.Fatal(err)
		}
		if string(got.Spec) != tc.want {
			t.Errorf("POST %s: stored spec %s, want %s", tc.body, got.Spec, tc.want)
		}
	}
	f.runner.Wait()
}
