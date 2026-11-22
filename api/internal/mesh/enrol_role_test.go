package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nodetrust"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const roleClusterLogin = "https://bench.local:18080"

// recordingTrust is a TrustDeliverer that records each node it delivered to.
type recordingTrust struct {
	mu    sync.Mutex
	nodes []string
}

func (r *recordingTrust) Deliver(_ context.Context, _ nodetrust.Requester, nodeID string) (proto.TrustInstallAck, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodes = append(r.nodes, nodeID)
	return proto.TrustInstallAck{OK: true, Fingerprint: "fp"}, nil
}

func (r *recordingTrust) delivered() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.nodes...)
}

// recordingSupervisor counts Start (the only path to writeConfig) and keeps
// every extra_records projection it is handed.
type recordingSupervisor struct {
	NoopSupervisor
	mu      sync.Mutex
	starts  int
	records []map[string]string
}

func (r *recordingSupervisor) Start(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts++
	return nil
}

func (r *recordingSupervisor) ReconcileAppRecords(m map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, m)
	return nil
}

// roleFixture enrols through the real mesh.enroll_node workflow on the real
// runner, with the cluster login server set, a recording trust deliverer and
// supervisor, the app door on for control plane cp1, and an agent on each
// node's enrol subject that captures the command and acks it.
type roleFixture struct {
	*convergeFixture
	trust  *recordingTrust
	sup    *recordingSupervisor
	jst    *jobs.Store
	runner *jobs.Runner
	mu     sync.Mutex
	cmds   map[string][]proto.MeshEnrollCmd
}

func newRoleFixture(t *testing.T, wrap func(jobs.Workflow) jobs.Workflow) *roleFixture {
	t.Helper()
	cf := newConvergeFixture(t)
	f := &roleFixture{convergeFixture: cf, trust: &recordingTrust{}, sup: &recordingSupervisor{}, cmds: map[string][]proto.MeshEnrollCmd{}}
	cf.svc = NewService(Config{
		LoginServer:     roleClusterLogin,
		Trust:           f.trust,
		ClusterID:       "bench",
		AppDoorHost:     proto.SignInFQDN("bench"),
		SelfNodeID:      "cp1",
		AppDoorWithheld: func() bool { return false },
	}, cf.store, cf.client, f.sup)
	cf.svc.SetAppLister(func() []AppDNS { return nil })
	jst, err := jobs.OpenStore(cf.ctx, filepath.Join(t.TempDir(), "role-jobs.db"))
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = jst.Close() })
	f.jst = jst
	f.runner = jobs.NewRunner(jst, cf.nc)
	wf := EnrollNodeWorkflow(cf.svc, cf.inv, cf.nc)
	if wrap != nil {
		wf = wrap(wf)
	}
	f.runner.Register(wf)
	return f
}

// node registers id with role and answers its enrol subject.
func (f *roleFixture) node(t *testing.T, id string, role proto.NodeRole, ip string) {
	t.Helper()
	f.addNode(t, id, role, time.Now().UTC())
	sub, err := f.nc.Subscribe(proto.MeshEnrollSubject(id), func(m *nats.Msg) {
		var cmd proto.MeshEnrollCmd
		_ = json.Unmarshal(m.Data, &cmd)
		f.mu.Lock()
		f.cmds[id] = append(f.cmds[id], cmd)
		f.mu.Unlock()
		body, _ := json.Marshal(proto.MeshEnrollAck{OK: true, Backend: "test", TailnetID: "hs-" + id, TailnetIP: ip})
		_ = m.Respond(body)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := f.nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

func (f *roleFixture) received(id string) []proto.MeshEnrollCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]proto.MeshEnrollCmd(nil), f.cmds[id]...)
}

// enrol submits mesh.enroll_node for id, waits for it, and returns the job
// and the info lines it logged.
func (f *roleFixture) enrol(t *testing.T, id string) (*jobs.Job, []string) {
	t.Helper()
	j, err := f.runner.Submit(f.ctx, "mesh.enroll_node", EnrollSpec{NodeID: id}, "auto-enroll")
	if err != nil {
		t.Fatalf("Submit(%s): %v", id, err)
	}
	f.runner.Wait()
	got, err := f.jst.GetJob(f.ctx, j.ID)
	if err != nil || got == nil {
		t.Fatalf("GetJob: %v", err)
	}
	evs, err := f.jst.ListEvents(f.ctx, j.ID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var lines []string
	for _, e := range evs {
		if e.Type != string(proto.JobLog) {
			continue
		}
		var d proto.LogEventData
		if json.Unmarshal(e.Data, &d) == nil && d.Level == "info" {
			lines = append(lines, d.Message)
		}
	}
	return got, lines
}

// TC-984-04: the real dispatch sends each role its exact command. The control
// plane gets both settings off and the loopback login server; compute,
// storage and firewall get both on and the cluster login server, and every
// other field is today's.
// TC-984-06: the job's step log names the node, its role and both settings.
// TC-984-08: the control-plane enrolment through dispatch and record never
// starts the supervisor (the only path to writeConfig), and its only write is
// one ReconcileAppRecords carrying the door's record.
func TestEnrollDispatch_CommandPerRole(t *testing.T) {
	for _, tc := range []struct {
		id    string
		role  proto.NodeRole
		login string
		on    bool
	}{
		{"cp1", proto.RoleControlPlane, "https://127.0.0.1:18080", false},
		{"c01", proto.RoleCompute, roleClusterLogin, true},
		{"stor1", proto.RoleStorage, roleClusterLogin, true},
		{"fw", proto.RoleFirewall, roleClusterLogin, true},
	} {
		t.Run(string(tc.role), func(t *testing.T) {
			f := newRoleFixture(t, nil)
			f.node(t, tc.id, tc.role, "100.64.0.5")
			j, lines := f.enrol(t, tc.id)
			if j.Status != jobs.StatusSucceeded {
				t.Fatalf("enrol %s: %s (%s)", tc.id, j.Status, j.Error)
			}
			cmds := f.received(tc.id)
			if len(cmds) != 1 {
				t.Fatalf("enrol commands for %s = %d, want 1", tc.id, len(cmds))
			}
			cmd := cmds[0]
			values, _ := f.client.minted()
			if len(values) != 1 {
				t.Fatalf("minted %d keys, want 1", len(values))
			}
			want := proto.MeshEnrollCmd{
				LoginServer: tc.login, AuthKey: values[0], Hostname: tc.id,
				AcceptDNS: tc.on, AcceptRoutes: tc.on,
			}
			if cmd.LoginServer != want.LoginServer || cmd.AuthKey != want.AuthKey || cmd.Hostname != want.Hostname ||
				cmd.AcceptDNS != want.AcceptDNS || cmd.AcceptRoutes != want.AcceptRoutes ||
				len(cmd.AdvertiseRoutes) != 0 || len(cmd.LegacyTrustBundlePEM) != 0 {
				t.Errorf("command = %+v\nwant      %+v", cmd, want)
			}

			// TC-984-06
			wantLine := fmt.Sprintf("%s (%s) enrols with accept-routes=%t accept-dns=%t", tc.id, tc.role, tc.on, tc.on)
			n := 0
			for _, l := range lines {
				if strings.Contains(l, "enrols with") {
					n++
					if l != wantLine {
						t.Errorf("settings line = %q, want %q", l, wantLine)
					}
				}
			}
			if n != 1 {
				t.Errorf("settings lines = %d, want 1: %q", n, lines)
			}

			// TC-984-08
			if tc.role != proto.RoleControlPlane {
				return
			}
			f.sup.mu.Lock()
			defer f.sup.mu.Unlock()
			if f.sup.starts != 0 {
				t.Errorf("supervisor Start called %d times by an enrolment, want 0", f.sup.starts)
			}
			if len(f.sup.records) != 1 {
				t.Fatalf("ReconcileAppRecords calls = %d, want 1", len(f.sup.records))
			}
			if got := f.sup.records[0]; len(got) != 1 || got[proto.SignInFQDN("bench")] != "100.64.0.5" {
				t.Errorf("projection = %v, want only the door record to 100.64.0.5", got)
			}
		})
	}
}

// TC-984-05: when the role cannot be read (the node left the registry after
// validate) or has no settings (a role nothing enrols), dispatch fails before
// trust is delivered or a key minted, nothing is sent, and the job fails.
func TestEnrollDispatch_FailsClosedWithoutARole(t *testing.T) {
	for _, tc := range []struct {
		name    string
		role    proto.NodeRole
		remove  bool
		wantErr string
	}{
		{name: "gone from the registry", role: proto.RoleCompute, remove: true, wantErr: "node n1 is not registered"},
		{name: "role with no settings", role: proto.NodeRole("router"), wantErr: `node n1: no enrolment settings for role "router"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var inv *inventory.Store
			wrap := func(wf jobs.Workflow) jobs.Workflow {
				if !tc.remove {
					return wf
				}
				validate := wf.Steps[0].Do
				wf.Steps[0].Do = func(sc *jobs.StepCtx) (json.RawMessage, error) {
					res, err := validate(sc)
					if err == nil {
						err = inv.Delete(sc.Ctx, "n1")
					}
					return res, err
				}
				return wf
			}
			f := newRoleFixture(t, wrap)
			inv = f.inv
			f.node(t, "n1", tc.role, "100.64.0.9")
			j, _ := f.enrol(t, "n1")
			if j.Status != jobs.StatusFailed {
				t.Fatalf("job status = %s, want failed", j.Status)
			}
			steps, err := f.jst.ListSteps(f.ctx, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			var dispatchErr string
			for _, st := range steps {
				if st.Name == "dispatch" {
					dispatchErr = st.Error
				}
			}
			if !strings.Contains(dispatchErr, tc.wantErr) {
				t.Errorf("dispatch error = %q, want it to contain %q", dispatchErr, tc.wantErr)
			}
			if d := f.trust.delivered(); len(d) != 0 {
				t.Errorf("trust delivered to %v, want none", d)
			}
			if keys, _ := f.svc.Client().ListPreAuthKeys(f.ctx, f.svc.cfg.DefaultUser); len(keys) != 0 {
				t.Errorf("%d pre-auth key(s) minted, want 0", len(keys))
			}
			if err := f.nc.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := f.received("n1"); len(got) != 0 {
				t.Errorf("enrol subject received %d message(s), want 0", len(got))
			}
		})
	}
}
