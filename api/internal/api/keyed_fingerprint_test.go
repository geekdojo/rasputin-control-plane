package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac/credmactest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/ledgertest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// recordingState is a firewallState that counts its calls and can fail them.
type recordingState struct {
	inner                   firewallState
	desiredErr, nodeErr     error
	desiredCalls, nodeCalls atomic.Int32
}

func (r *recordingState) DesiredHash(ctx context.Context) (string, error) {
	r.desiredCalls.Add(1)
	if r.desiredErr != nil {
		return "", r.desiredErr
	}
	return r.inner.DesiredHash(ctx)
}

func (r *recordingState) NodeState(ctx context.Context, nodeID string) (*firewall.NodeState, error) {
	r.nodeCalls.Add(1)
	if r.nodeErr != nil {
		return nil, r.nodeErr
	}
	return r.inner.NodeState(ctx, nodeID)
}

func (r *recordingState) EmptyHash() string { return r.inner.EmptyHash() }

func insertFirewallNode(t *testing.T, f *apiFixture) {
	t.Helper()
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-fw", Role: proto.RoleFirewall, Hostname: "fw",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

// TC-827-08 (api): NewServer refuses a nil firewall state service.
func TestNewServer_RefusesANilFirewallState(t *testing.T) {
	f := newAPIFixture(t)
	srv, err := NewServer(f.jobsStore, f.runner, f.inv, inventory.NewService(f.inv, f.nc, slog.New(slog.DiscardHandler)),
		f.fw, nil, f.appsStore, f.metricsStore, f.updStore, f.verifier, f.bundleDir, f.srv.trustDir,
		f.mesh, f.bmcSvc, f.setupSvc, f.authSvc, nil, f.srv.busTokens, f.nc,
		f.srv.bus, f.srv.log, f.srv.newCorrelationID)
	if err == nil || srv != nil {
		t.Fatalf("NewServer with a nil firewall state = (%v, %v), want (nil, an error)", srv, err)
	}
}

// TC-827-13 (carries TC-825-30): with the PPPoE state applied, so the stored
// intent hash is its keyed fingerprint, the state route reads not pending;
// after only the PPPoE secret changes it reads pending. Its values come from
// the firewall service (DesiredHash and NodeState), not a compile of its own.
// The empty row is TestHandleGetFirewallState_PendingFalseWhenFreshAndEmpty.
func TestHandleGetFirewallState_PendingThroughTheService(t *testing.T) {
	// The keyed fingerprint of exactly these two intents with the password
	// SENTINEL-PPPOE-PASSWORD under credmactest's key, computed outside Go;
	// the firewall package pins the same vector against the apply command.
	const appliedPPPoEKeyed = "k1-53c93b534ef46563336939f776a1d2c6652ea445e24653353a32482a62f188de"
	f := newAPIFixture(t)
	insertFirewallNode(t, f)
	rec := &recordingState{inner: f.fwSvc}
	f.srv.fwState = rec
	c := f.authenticate(t)
	for _, body := range []string{
		`{"kind":"port_forward","name":"web","enabled":true,"spec":{"wanPort":8080,"lanHost":"192.168.1.10","lanPort":80,"protocol":"tcp"}}`,
		`{"kind":"wan_config","name":"isp","enabled":true,"spec":{"proto":"pppoe","username":"user@isp","secret":"SENTINEL-PPPOE-PASSWORD","service":"internet"}}`,
	} {
		if w := f.do(t, http.MethodPost, "/api/firewall/intents", body, c); w.Code != http.StatusCreated {
			t.Fatalf("create intent: %d %s", w.Code, w.Body.String())
		}
	}
	if err := f.fw.UpdateAfterApply(f.ctx, "node-fw", appliedPPPoEKeyed, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateAfterApply: %v", err)
	}

	pending := func() bool {
		t.Helper()
		w := f.do(t, http.MethodGet, "/api/firewall/state", "", c)
		if w.Code != http.StatusOK {
			t.Fatalf("get state: %d %s", w.Code, w.Body.String())
		}
		var out []firewall.NodeState
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out) != 1 {
			t.Fatalf("decode state: %v (%s)", err, w.Body.String())
		}
		return out[0].Pending
	}
	if pending() {
		t.Error("the applied PPPoE state reads as pending")
	}

	intents, err := f.fw.ListIntents(f.ctx)
	if err != nil {
		t.Fatalf("ListIntents: %v", err)
	}
	var wanID string
	for _, in := range intents {
		if in.Kind == string(proto.IntentWANConfig) {
			wanID = in.ID
		}
	}
	upd := `{"spec":{"proto":"pppoe","username":"user@isp","secret":"SENTINEL-ROTATED","service":"internet"}}`
	if w := f.do(t, http.MethodPatch, "/api/firewall/intents/"+wanID, upd, c); w.Code != http.StatusOK {
		t.Fatalf("update intent: %d %s", w.Code, w.Body.String())
	}
	if !pending() {
		t.Error("after only the PPPoE secret changed, the firewall is not pending")
	}
	if rec.desiredCalls.Load() != 2 || rec.nodeCalls.Load() != 2 {
		t.Errorf("the handler called DesiredHash %d and NodeState %d time(s), want 2 each",
			rec.desiredCalls.Load(), rec.nodeCalls.Load())
	}
}

// TC-827-25: a failed desired or node-state read answers 500
// firewall_state_unavailable with a safe message and a correlation id; the
// store's error stays out of the body and is logged at WARN under that id.
func TestHandleGetFirewallState_CodedErrorOnAFailedRead(t *testing.T) {
	const marker = "SENTINEL-SQL-DETAIL no such table"
	for name, rec := range map[string]*recordingState{
		"DesiredHash": {desiredErr: errors.New(marker)},
		"NodeState":   {nodeErr: errors.New(marker)},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAPIFixture(t)
			insertFirewallNode(t, f)
			rec.inner = f.fwSvc
			f.srv.fwState = rec
			c := f.authenticate(t)
			w := f.do(t, http.MethodGet, "/api/firewall/state", "", c)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status %d, want 500: %s", w.Code, w.Body.String())
			}
			e := decodeCoded(t, w.Body.Bytes())
			if e.Code != codeFirewallStateUnavailable || e.CorrelationID == "" || e.Error == "" {
				t.Fatalf("body = %+v, want code %s, a message and a correlation id", e, codeFirewallStateUnavailable)
			}
			if strings.Contains(w.Body.String(), "SENTINEL-SQL-DETAIL") {
				t.Errorf("the store's error reached the client: %s", w.Body.String())
			}
			recs := f.logs.withAttr("correlation_id", e.CorrelationID)
			if len(recs) != 1 || recs[0].Level != slog.LevelWarn {
				t.Fatalf("want one WARN record under the correlation id, got %d", len(recs))
			}
			var cause string
			recs[0].Attrs(func(a slog.Attr) bool {
				if a.Key == "err" {
					cause = a.Value.String()
				}
				return true
			})
			if !strings.Contains(cause, marker) {
				t.Errorf("the WARN record's err = %q, want the store error", cause)
			}
		})
	}
}

// TC-827-10: bmc.configure, submitted once through the configure handler and
// once by the registration reconcile, each on the real Runner with a stub
// host agent. The bus command carries the credential; the spec configHash,
// the step logs and the step results hold only the keyed fingerprint; and no
// ledger surface holds the plaintext credential or the previous release's
// unkeyed hash for those inputs.
func TestConfigureLedger_OnlyKeyedValues(t *testing.T) {
	const (
		unlock = "SENTINEL-BMC-UNLOCK"
		// The config as the handler stores it, and the previous release's
		// and the keyed fingerprint for it with this unlock, computed
		// outside Go.
		storedConfig = `{"targets":[{"node_id":"node-1","pos":"A-0"}]}`
		legacyHash   = "d9a203d2fd31e3da"
		keyedHash    = "k1-2df0a233aa7430134b9972c05144329dbeab552f9d441658bfe1a55ec8b4c644"
	)
	f := newAPIFixture(t)
	logs := ledgertest.CaptureLog(t)
	for _, id := range []string{"self-node", "node-1"} {
		if err := f.inv.Insert(f.ctx, &proto.Node{ID: id, Role: proto.RoleCompute, Hostname: id,
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	st := f.setupSvc.Store()
	f.runner.Register(bmc.ConfigureWorkflow(f.bmcSvc, f.inv, st, f.srv.BMCSessions(), nil))

	pushed := make(chan proto.BMCConfigureCmd, 4)
	sub, err := f.nc.Subscribe(proto.BMCConfigureSubject("self-node"), func(m *nats.Msg) {
		var cmd proto.BMCConfigureCmd
		_ = json.Unmarshal(m.Data, &cmd)
		pushed <- cmd
		ack, _ := json.Marshal(proto.BMCConfigureAck{OK: true, ConfigHash: cmd.ConfigHash})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	check := func(t *testing.T, how string, jobID string, cmd proto.BMCConfigureCmd) {
		t.Helper()
		var cfg map[string]any
		if err := json.Unmarshal(cmd.Config, &cfg); err != nil || cfg["unlock"] != unlock {
			t.Fatalf("%s: the configure command's unlock = %v (err %v), want the stored credential", how, cfg["unlock"], err)
		}
		done, err := f.jobsStore.GetJob(f.ctx, jobID)
		if err != nil || done == nil || done.Status != jobs.StatusSucceeded {
			t.Fatalf("%s: job %+v (err %v), want succeeded", how, done, err)
		}
		var spec bmc.ConfigureSpec
		if err := json.Unmarshal(done.Spec, &spec); err != nil {
			t.Fatal(err)
		}
		if string(spec.Config) != storedConfig || spec.ConfigHash != keyedHash || !credmac.IsKeyed(spec.ConfigHash) {
			t.Fatalf("%s: spec config %s hash %s, want %s and %s", how, spec.Config, spec.ConfigHash, storedConfig, keyedHash)
		}
		ledger := &ledgertest.Surfaces{Spec: string(done.Spec) + done.Error, Log: logs.String()}
		steps, err := f.jobsStore.ListSteps(f.ctx, jobID)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range steps {
			ledger.Steps += string(s.Result) + s.Error
		}
		events, err := f.jobsStore.ListEvents(f.ctx, jobID)
		if err != nil {
			t.Fatal(err)
		}
		sawKeyedLog := false
		for _, ev := range events {
			ledger.Events += string(ev.Data)
			if ev.Type == string(proto.JobLog) && strings.Contains(string(ev.Data), keyedHash) {
				sawKeyedLog = true
			}
		}
		if !sawKeyedLog {
			t.Errorf("%s: no step log carries the keyed fingerprint", how)
		}
		if !strings.Contains(ledger.Steps, keyedHash) {
			t.Errorf("%s: no step result carries the keyed fingerprint", how)
		}
		secrets := ledgertest.Secrets("the BMC unlock", unlock)
		cmdBytes, _ := json.Marshal(cmd)
		ledger.AssertPresent(t, how+": the configure command", string(cmdBytes), secrets)
		ledger.AssertAbsent(t, append(secrets, ledgertest.Secrets("the previous release's unkeyed hash", legacyHash)...))
	}

	// Through the handler.
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/bmc/config",
		`{"kind":"bitscope","hostNodeId":"self-node","config":{"targets":[{"pos":"A-0","node_id":"node-1"}],"unlock":"`+unlock+`"}}`, c)
	if w.Code != http.StatusAccepted {
		t.Fatalf("set config: %d %s", w.Code, w.Body.String())
	}
	var j jobs.Job
	if err := json.Unmarshal(w.Body.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	f.runner.Wait()
	check(t, "the handler", j.ID, <-pushed)

	// Through the reconcile: the host registers advertising the previous
	// release's hash.
	submitted := make(chan string, 1)
	stop, err := bmc.StartReconcile(f.nc, st,
		func(context.Context) (bool, error) { return false, nil },
		func(ctx context.Context, kind string, spec json.RawMessage, by string) error {
			rj, serr := f.runner.Submit(ctx, kind, spec, by)
			if serr == nil {
				submitted <- rj.ID
			}
			return serr
		}, slog.New(slog.DiscardHandler), credmactest.Key(t))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if v, _ := st.Get(f.ctx, setup.KeyBMCHostNode); v != "self-node" {
		t.Fatalf("the configure job did not record the host: %q", v)
	}
	reg, _ := json.Marshal(proto.NodeRegisteredEvt{NodeID: "self-node", Ts: time.Now().UTC(),
		Metadata: map[string]any{proto.MetadataBMCConfigHash: legacyHash}})
	if err := f.nc.Publish(proto.NodeRegisteredSubject("self-node"), reg); err != nil {
		t.Fatal(err)
	}
	var reconcileJob string
	select {
	case reconcileJob = <-submitted:
	case <-time.After(5 * time.Second):
		t.Fatal("the reconcile submitted no re-push for a host advertising the previous release's hash")
	}
	f.runner.Wait()
	check(t, "the reconcile", reconcileJob, <-pushed)
}
