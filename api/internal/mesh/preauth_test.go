package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

func TestResolvePreAuthKey_NodeProfile(t *testing.T) {
	now := time.Now()
	in, err := ResolvePreAuthKey(PreAuthNode, "op", PreAuthKeyRequest{}, now)
	if err != nil {
		t.Fatalf("node profile: %v", err)
	}
	if in.User != "op" || in.Reusable || in.Ephemeral || !slices.Equal(in.Tags, []string{meshNodeTag}) {
		t.Errorf("node key = %+v; want single-use, non-ephemeral, [%s]", in, meshNodeTag)
	}
	if !in.Expiry.Equal(now.Add(nodeEnrolKeyExpiry)) {
		t.Errorf("node key expiry %s, want now+%s", in.Expiry.Sub(now), nodeEnrolKeyExpiry)
	}
	// The node profile's fields are fixed; a caller setting any is refused.
	for name, req := range map[string]PreAuthKeyRequest{
		"reusable":  {Reusable: true},
		"ephemeral": {Ephemeral: true},
		"expiry":    {ExpiresIn: time.Hour},
		"tags":      {Tags: []string{meshNodeTag}},
	} {
		if _, err := ResolvePreAuthKey(PreAuthNode, "op", req, now); !errors.Is(err, ErrPreAuthRequest) {
			t.Errorf("node profile with %s set: err=%v, want ErrPreAuthRequest", name, err)
		}
	}
}

func TestResolvePreAuthKey_UserDeviceProfile(t *testing.T) {
	now := time.Now()
	ok := map[string]struct {
		req        PreAuthKeyRequest
		wantExpiry time.Duration
	}{
		"defaults":            {PreAuthKeyRequest{}, UserDeviceKeyDefaultExpiry},
		"own tag":             {PreAuthKeyRequest{Tags: []string{UserDeviceTag}}, UserDeviceKeyDefaultExpiry},
		"own tag twice":       {PreAuthKeyRequest{Tags: []string{UserDeviceTag, UserDeviceTag}}, UserDeviceKeyDefaultExpiry},
		"at the cap":          {PreAuthKeyRequest{ExpiresIn: UserDeviceKeyMaxExpiry}, UserDeviceKeyMaxExpiry},
		"short":               {PreAuthKeyRequest{ExpiresIn: time.Hour}, time.Hour},
		"reusable, ephemeral": {PreAuthKeyRequest{Reusable: true, Ephemeral: true}, UserDeviceKeyDefaultExpiry},
	}
	for name, tc := range ok {
		in, err := ResolvePreAuthKey(PreAuthUserDevice, "op", tc.req, now)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !slices.Equal(in.Tags, []string{UserDeviceTag}) {
			t.Errorf("%s: tags %v, want exactly [%s]", name, in.Tags, UserDeviceTag)
		}
		if !in.Expiry.Equal(now.Add(tc.wantExpiry)) {
			t.Errorf("%s: expiry now+%s, want now+%s", name, in.Expiry.Sub(now), tc.wantExpiry)
		}
		if in.Reusable != tc.req.Reusable || in.Ephemeral != tc.req.Ephemeral {
			t.Errorf("%s: reuse flags not carried: %+v", name, in)
		}
	}
	refused := map[string]PreAuthKeyRequest{
		"node tag":          {Tags: []string{meshNodeTag}},
		"any reserved tag":  {Tags: []string{"tag:rasputin-controlplane"}},
		"reserved + own":    {Tags: []string{UserDeviceTag, meshNodeTag}},
		"foreign tag":       {Tags: []string{"tag:server"}},
		"empty tag":         {Tags: []string{""}},
		"over the cap":      {ExpiresIn: UserDeviceKeyMaxExpiry + time.Second},
		"ten years":         {ExpiresIn: 87600 * time.Hour},
		"negative duration": {ExpiresIn: -time.Hour},
	}
	for name, req := range refused {
		if _, err := ResolvePreAuthKey(PreAuthUserDevice, "op", req, now); !errors.Is(err, ErrPreAuthRequest) {
			t.Errorf("%s: err=%v, want ErrPreAuthRequest", name, err)
		}
	}
	_, err := ResolvePreAuthKey(PreAuthUserDevice, "op", PreAuthKeyRequest{Tags: []string{"tag:rasputin-node"}}, now)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("a reserved tag should be named as reserved: %v", err)
	}
}

func TestResolvePreAuthKey_RefusesUnknownProfileAndNoUser(t *testing.T) {
	if _, err := ResolvePreAuthKey(PreAuthProfile(99), "op", PreAuthKeyRequest{}, time.Now()); err == nil {
		t.Error("unknown profile accepted")
	}
	if _, err := ResolvePreAuthKey(PreAuthUserDevice, "", PreAuthKeyRequest{}, time.Now()); err == nil {
		t.Error("empty user accepted")
	}
}

func TestParseUserDeviceKeyExpiry(t *testing.T) {
	if d, err := ParseUserDeviceKeyExpiry(""); err != nil || d != 0 {
		t.Errorf(`"" = %s, %v; want 0 (profile default)`, d, err)
	}
	if d, err := ParseUserDeviceKeyExpiry("168h"); err != nil || d != 168*time.Hour {
		t.Errorf("168h = %s, %v", d, err)
	}
	for _, bad := range []string{"forever", "7d", "-1h", "0s"} {
		if _, err := ParseUserDeviceKeyExpiry(bad); !errors.Is(err, ErrPreAuthRequest) {
			t.Errorf("%q: err=%v, want ErrPreAuthRequest", bad, err)
		}
	}
}

// MintPreAuthKey sends Headscale exactly the resolved input, and refuses a
// request outside the profile without calling Headscale at all.
func TestMintPreAuthKey_OneFunctionTwoProfiles(t *testing.T) {
	f := newMeshFixture(t)
	k, err := f.svc.MintPreAuthKey(f.ctx, PreAuthNode, PreAuthKeyRequest{})
	if err != nil {
		t.Fatalf("node mint: %v", err)
	}
	if k.ID == "" || k.Value == "" || !slices.Equal(k.Tags, []string{meshNodeTag}) || k.User != f.svc.cfg.DefaultUser {
		t.Errorf("node key = %+v", k)
	}
	if _, err := f.svc.MintPreAuthKey(f.ctx, PreAuthUserDevice, PreAuthKeyRequest{Tags: []string{meshNodeTag}}); !errors.Is(err, ErrPreAuthRequest) {
		t.Fatalf("user key with the node tag: err=%v", err)
	}
	if f.client.createCalls != 1 {
		t.Errorf("createCalls = %d; a refused request must not reach Headscale", f.client.createCalls)
	}
	u, err := f.svc.MintPreAuthKey(f.ctx, PreAuthUserDevice, PreAuthKeyRequest{Reusable: true})
	if err != nil {
		t.Fatalf("user mint: %v", err)
	}
	in := f.client.createInputs[1]
	if !in.Reusable || !slices.Equal(in.Tags, []string{UserDeviceTag}) || !slices.Equal(u.Tags, in.Tags) {
		t.Errorf("user key sent %+v, returned %+v", in, u)
	}
}

// mesh.apply mints nothing: user keys are minted by the Keys endpoint, node
// keys inside the enrol dispatch step.
func TestApplyWorkflow_MintsNoKeys(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := f.store.CreateIntent(f.ctx, &Intent{
		ID: "k1", Kind: string(proto.IntentPreAuthKey), Name: "never minted",
		Enabled: true, Spec: mustMarshal(t, proto.PreAuthKeySpec{User: "u1", ExpiresIn: "24h"}),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateIntent: %v", err)
	}
	wf := ApplyWorkflow(f.svc, nil, f.nc)
	prior := map[string]json.RawMessage{}
	for _, st := range wf.Steps {
		if st.Name == "push_keys" {
			t.Fatal("mesh.apply still has a push_keys step")
		}
		res, err := st.Do(&jobs.StepCtx{Ctx: f.ctx, JobID: "j", Spec: []byte("{}"), NATS: f.nc, PriorResults: prior, Log: func(string, string) {}})
		if err != nil {
			t.Fatalf("step %s: %v", st.Name, err)
		}
		prior[st.Name] = res
	}
	if f.client.createCalls != 0 {
		t.Errorf("mesh.apply minted %d key(s)", f.client.createCalls)
	}
	if got, _ := f.store.GetIntent(f.ctx, "k1"); got.HSID != "" {
		t.Errorf("mesh.apply wrote a key onto the intent: %+v", got)
	}
}

// runWholeEnroll runs every enroll step as the runner would and returns the
// step results and the first error.
func runWholeEnroll(t *testing.T, f *convergeFixture, nodeID string, ctx context.Context) (map[string]json.RawMessage, error) {
	t.Helper()
	wf := EnrollNodeWorkflow(f.svc, f.inv, f.nc)
	spec, _ := json.Marshal(EnrollSpec{NodeID: nodeID})
	prior := map[string]json.RawMessage{}
	for _, st := range wf.Steps {
		sc := &jobs.StepCtx{Ctx: ctx, JobID: "test-job", Spec: spec, NATS: f.nc, PriorResults: prior, Log: func(string, string) {}}
		res, err := st.Do(sc)
		if err != nil {
			return prior, err
		}
		if res != nil {
			prior[st.Name] = res
		}
	}
	return prior, nil
}

func TestEnrollWorkflow_HasNoSeparateMintStep(t *testing.T) {
	f := newMeshFixture(t)
	wf := EnrollNodeWorkflow(f.svc, nil, f.nc)
	var names []string
	for _, st := range wf.Steps {
		names = append(names, st.Name)
	}
	if !slices.Equal(names, []string{"validate", "dispatch", "record"}) {
		t.Errorf("enroll steps = %v, want [validate dispatch record]", names)
	}
}

// The enrolment key is expired when the dispatch step ends — on success,
// on a rejection, on no responder and on a timeout — and it is never
// written into any step result.
func TestEnrollWorkflow_KeyIsExpiredWhenDispatchEnds(t *testing.T) {
	type outcome struct {
		name    string
		agent   func(t *testing.T, f *convergeFixture)
		timeout time.Duration
		wantErr bool
	}
	cases := []outcome{
		{name: "success", agent: func(t *testing.T, f *convergeFixture) {
			fakeAgent(t, f.nc, "node-1", proto.MeshEnrollAck{OK: true, TailnetID: "hs-7", TailnetIP: "100.64.0.7", Backend: "test"})
		}},
		{name: "rejected", wantErr: true, agent: func(t *testing.T, f *convergeFixture) {
			fakeAgent(t, f.nc, "node-1", proto.MeshEnrollAck{OK: false, Backend: "test", Detail: "nope"})
		}},
		{name: "no responder", wantErr: true, agent: func(*testing.T, *convergeFixture) {}},
		{name: "timeout", wantErr: true, timeout: 300 * time.Millisecond, agent: func(t *testing.T, f *convergeFixture) {
			sub, err := f.nc.Subscribe(proto.MeshEnrollSubject("node-1"), func(*nats.Msg) {})
			if err != nil {
				t.Fatalf("subscribe: %v", err)
			}
			t.Cleanup(func() { _ = sub.Unsubscribe() })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newConvergeFixture(t)
			f.addNode(t, "node-1", proto.RoleCompute, time.Now().UTC())
			tc.agent(t, f)
			ctx := f.ctx
			if tc.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(f.ctx, tc.timeout)
				defer cancel()
			}
			prior, err := runWholeEnroll(t, f, "node-1", ctx)
			if (err != nil) != tc.wantErr {
				t.Fatalf("enroll err=%v, wantErr=%v", err, tc.wantErr)
			}
			values, expired := f.client.minted()
			if len(values) != 1 {
				t.Fatalf("minted %d keys, want 1", len(values))
			}
			f.client.mu.Lock()
			keyID := ""
			for id := range f.client.keys {
				keyID = id
			}
			f.client.mu.Unlock()
			if !slices.Equal(expired, []string{keyID}) {
				t.Errorf("expired %v, want exactly the minted key %s", expired, keyID)
			}
			for step, res := range prior {
				if strings.Contains(string(res), values[0]) {
					t.Errorf("step %s result carries the key value: %s", step, res)
				}
			}
			if err != nil && strings.Contains(err.Error(), values[0]) {
				t.Errorf("step error carries the key value: %v", err)
			}
		})
	}
}

// A failed expire is logged, never turned into the enrol's outcome: the
// short safety-net expiry covers exactly that miss.
func TestEnrollWorkflow_ExpireFailureDoesNotFailTheEnrol(t *testing.T) {
	f := newConvergeFixture(t)
	f.addNode(t, "node-1", proto.RoleCompute, time.Now().UTC())
	fakeAgent(t, f.nc, "node-1", proto.MeshEnrollAck{OK: true, TailnetID: "hs-8", TailnetIP: "100.64.0.8", Backend: "test"})
	f.client.expireKeyErr = errors.New("headscale down")
	var logs []string
	wf := EnrollNodeWorkflow(f.svc, f.inv, f.nc)
	spec, _ := json.Marshal(EnrollSpec{NodeID: "node-1"})
	prior := map[string]json.RawMessage{}
	for _, st := range wf.Steps {
		sc := &jobs.StepCtx{Ctx: f.ctx, JobID: "j", Spec: spec, NATS: f.nc, PriorResults: prior,
			Log: func(_, m string) { logs = append(logs, m) }}
		res, err := st.Do(sc)
		if err != nil {
			t.Fatalf("step %s: %v", st.Name, err)
		}
		prior[st.Name] = res
	}
	if !slices.ContainsFunc(logs, func(m string) bool { return strings.Contains(m, "could not expire enrollment key") }) {
		t.Errorf("a failed expire should be logged; logs: %v", logs)
	}
}

// Reconcile binds a device to a node only through the Headscale id recorded
// at enrol — never through its hostname or its tag.
func TestReconcileFetch_BindsByRecordedHeadscaleID(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC()
	// hs-1 was enrolled as node-a; it has since renamed itself.
	if err := f.store.UpsertDevice(f.ctx, &Device{HSID: "hs-1", Hostname: "node-a", RasputinNodeID: "node-a", Kind: "rasputin", Tags: []string{meshNodeTag}, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	f.client.mu.Lock()
	f.client.nodes["hs-1"] = HSNode{ID: "hs-1", Hostname: "renamed", Tags: []string{meshNodeTag}, IPv4: "100.64.0.1", LastSeen: now, RegisteredAt: now}
	// hs-2 carries the node tag and a node's hostname, but no enrol recorded it.
	f.client.nodes["hs-2"] = HSNode{ID: "hs-2", Hostname: "node-b", Tags: []string{meshNodeTag}, IPv4: "100.64.0.2", LastSeen: now, RegisteredAt: now}
	// hs-3 is an untagged device named like a node.
	f.client.nodes["hs-3"] = HSNode{ID: "hs-3", Hostname: "node-c", IPv4: "100.64.0.3", LastSeen: now, RegisteredAt: now}
	f.client.mu.Unlock()

	if _, err := reconcileFetch(f.svc, f.nc)(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("reconcileFetch: %v", err)
	}
	devices, _ := f.store.ListDevices(f.ctx)
	got := map[string]*Device{}
	for _, d := range devices {
		got[d.HSID] = d
	}
	if d := got["hs-1"]; d == nil || d.RasputinNodeID != "node-a" || d.Kind != "rasputin" || d.Hostname != "renamed" {
		t.Errorf("hs-1 should stay bound to node-a by id: %+v", d)
	}
	if d := got["hs-2"]; d == nil || d.RasputinNodeID != "" || d.Kind != "rasputin" {
		t.Errorf("hs-2 has no recorded enrol and must be bound to no node: %+v", d)
	}
	if d := got["hs-3"]; d == nil || d.RasputinNodeID != "" || d.Kind != "user" {
		t.Errorf("hs-3 is a user device: %+v", d)
	}
	if d, _ := f.store.GetDeviceByRasputinNodeID(f.ctx, "node-b"); d != nil {
		t.Errorf("node-b resolved to %+v through a hostname", d)
	}
}

// Through the real runner and job store, for an enrol that succeeds and one
// that the agent rejects: the enrolment key appears in no job spec, step
// result, step error, job event or process log line — the job-ledger rule
// (geekdojo/geekdojo-brain#479) holds on the mesh.enroll_node path.
func TestEnrollJob_KeyNeverReachesTheLedger(t *testing.T) {
	var logBuf strings.Builder
	var logMu sync.Mutex
	prev := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logBuf.Write(p)
	}))
	t.Cleanup(func() { log.SetOutput(prev) })

	f := newConvergeFixture(t)
	f.addNode(t, "good", proto.RoleCompute, time.Now().UTC())
	f.addNode(t, "bad", proto.RoleCompute, time.Now().UTC())
	fakeAgent(t, f.nc, "good", proto.MeshEnrollAck{OK: true, TailnetID: "hs-9", TailnetIP: "100.64.0.9", Backend: "test"})
	fakeAgent(t, f.nc, "bad", proto.MeshEnrollAck{OK: false, Backend: "test", Detail: "refused"})

	jst, err := jobs.OpenStore(f.ctx, filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = jst.Close() })
	runner := jobs.NewRunner(jst, f.nc)
	runner.Register(EnrollNodeWorkflow(f.svc, f.inv, f.nc))
	var ids []string
	for _, node := range []string{"good", "bad"} {
		spec, _ := json.Marshal(EnrollSpec{NodeID: node})
		j, err := runner.Submit(f.ctx, "mesh.enroll_node", spec, "test")
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		ids = append(ids, j.ID)
	}
	runner.Wait()

	values, _ := f.client.minted()
	if len(values) != 2 {
		t.Fatalf("minted %d keys, want 2", len(values))
	}
	check := func(where, got string) {
		for _, v := range values {
			if strings.Contains(got, v) {
				t.Errorf("%s carries an enrolment key: %s", where, got)
			}
		}
	}
	for i, id := range ids {
		j, err := jst.GetJob(f.ctx, id)
		if err != nil || j == nil {
			t.Fatalf("GetJob: %v", err)
		}
		if want := []jobs.Status{jobs.StatusSucceeded, jobs.StatusFailed}[i]; j.Status != want {
			t.Errorf("job %d finished %s, want %s", i, j.Status, want)
		}
		raw, _ := json.Marshal(j)
		check("job "+id, string(raw))
		steps, _ := jst.ListSteps(f.ctx, id)
		for _, st := range steps {
			raw, _ := json.Marshal(st)
			check("step "+st.Name, string(raw))
		}
		events, _ := jst.ListEvents(f.ctx, id)
		for _, ev := range events {
			raw, _ := json.Marshal(ev)
			check("event", string(raw))
		}
	}
	logMu.Lock()
	check("process log", logBuf.String())
	logMu.Unlock()
}

type writerFunc func([]byte) (int, error)

func (w writerFunc) Write(p []byte) (int, error) { return w(p) }
