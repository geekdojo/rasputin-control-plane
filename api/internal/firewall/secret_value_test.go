package firewall

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// Vectors pinned from the previous release (origin/main 1c44e02), where the
// PPPoE secret was spliced back into the intent spec as a string before
// Compile. Typing the secret must not move a byte: the firewall agent hashes
// what it applied, so a changed hash reads as drift on every firewall.
const (
	// pppoeLegacyHash is the hash of pppoeIntent(t, "w1", pppoeSecret) alone.
	pppoeLegacyHash = "4136541b3c137e2035c97429ca2787351d4113569c568d517d5ff523f5e51983"

	// vectorHash and vectorCmd are for vectorIntents with the secret
	// pppoeSecret; vectorRotatedHash is the same with "SENTINEL-ROTATED".
	vectorHash        = "23dba914fbe610d66dedb1e3140395ddd7019e045844650e8a62b275840fa71d"
	vectorRotatedHash = "6f1bc206c51bb4aadca7ef54766f58400a434598e12007d9ec5a11dbe617e0d9"
	vectorCmd         = `{"state":{"firewall":{"redirect":[{"dest":"lan","dest_ip":"192.168.1.10","dest_port":"80","name":"web","proto":"tcp","src":"wan","src_dport":"8080","target":"DNAT"}],"rule":[]},"network":{"wan":{"password":"SENTINEL-PPPOE-PASSWORD","proto":"pppoe","service":"internet","username":"user@isp"}}},"intentHash":"23dba914fbe610d66dedb1e3140395ddd7019e045844650e8a62b275840fa71d"}`
)

// vectorIntents is a port forward and a PPPoE wan_config whose spec carries
// the given secret inline, the way the browser posts it.
func vectorIntents(secretText string) []*Intent {
	wanSpec := `{"proto":"pppoe","username":"user@isp","service":"internet"}`
	if secretText != "" {
		wanSpec = `{"proto":"pppoe","username":"user@isp","secret":"` + secretText + `","service":"internet"}`
	}
	return []*Intent{
		{ID: "p1", Kind: string(proto.IntentPortForward), Name: "web", Enabled: true,
			Spec: json.RawMessage(`{"wanPort":8080,"lanHost":"192.168.1.10","lanPort":80,"protocol":"tcp"}`)},
		{ID: "w1", Kind: string(proto.IntentWANConfig), Name: "isp", Enabled: true,
			Spec: json.RawMessage(wanSpec)},
	}
}

// applyHarness is a firewall.apply set-up on the real Runner and a real
// store, with a stub firewall agent that records every apply command.
type applyHarness struct {
	ctx      context.Context
	nc       *nats.Conn
	store    *Store
	jobStore *jobs.Store
	runner   *jobs.Runner
	applies  atomic.Int32
	lastCmd  atomic.Pointer[[]byte]
	pushStep func(sc *jobs.StepCtx) (json.RawMessage, error)
}

func newApplyHarness(t *testing.T, intents []*Intent) *applyHarness {
	t.Helper()
	h := &applyHarness{ctx: context.Background(), nc: startNATS(t)}
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")
	store, err := OpenStore(h.ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h.store = store
	jobStore, err := jobs.OpenStore(h.ctx, dbPath)
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = jobStore.Close() })
	h.jobStore = jobStore
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	for _, in := range intents {
		if err := store.CreateIntent(h.ctx, in); err != nil {
			t.Fatalf("CreateIntent: %v", err)
		}
	}
	sub, err := h.nc.Subscribe(proto.FirewallApplySubject("fw"), func(m *nats.Msg) {
		h.applies.Add(1)
		data := append([]byte(nil), m.Data...)
		h.lastCmd.Store(&data)
		var cmd proto.FirewallApplyCmd
		_ = json.Unmarshal(m.Data, &cmd)
		hash, _ := Hash(cmd.State)
		ack, _ := json.Marshal(proto.FirewallApplyAck{OK: true, Hash: hash})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	h.runner = jobs.NewRunner(jobStore, h.nc)
	h.runner.Register(ApplyWorkflow(store, inv, h.nc, nil))
	h.pushStep = applyPush(store, inv, h.nc)
	return h
}

// TC-825-28: firewall.apply on the real Runner sends the stored PPPoE secret
// in the apply command, byte-identical to the previous release, and the
// compile input carries the secret only as a secret.Value.
func TestApplyWorkflow_PPPoESecretIsAValueAndBytesAreUnchanged(t *testing.T) {
	h := newApplyHarness(t, vectorIntents(pppoeSecret))

	// The compile input: specs without the secret, the secret as a Value.
	intents, secrets, err := h.store.ListIntentsForCompile(h.ctx)
	if err != nil {
		t.Fatalf("ListIntentsForCompile: %v", err)
	}
	for _, in := range intents {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(in.Spec, &m)
		if _, ok := m[secretField]; ok {
			t.Errorf("intent %s spec carries a secret field: %s", in.ID, in.Spec)
		}
	}
	if got := string(secrets["w1"].Reveal()); got != pppoeSecret {
		t.Errorf("secrets[w1] = %q, want the stored secret", got)
	}
	DestroySecrets(secrets)

	j, err := h.runner.Submit(h.ctx, "firewall.apply", json.RawMessage(`{}`), "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	h.runner.Wait()
	done, err := h.jobStore.GetJob(h.ctx, j.ID)
	if err != nil || done == nil {
		t.Fatalf("GetJob: %v", err)
	}
	if done.Status != jobs.StatusSucceeded {
		t.Fatalf("apply failed: %s", done.Error)
	}
	got := h.lastCmd.Load()
	if got == nil {
		t.Fatal("the agent was never sent an apply command")
	}
	if string(*got) != vectorCmd {
		t.Errorf("apply command bytes changed:\n got %s\nwant %s", *got, vectorCmd)
	}
	var cmd proto.FirewallApplyCmd
	if err := json.Unmarshal(*got, &cmd); err != nil {
		t.Fatalf("decode command: %v", err)
	}
	if cmd.IntentHash != vectorHash {
		t.Errorf("IntentHash = %s, want %s", cmd.IntentHash, vectorHash)
	}
	pw, _ := cmd.State["network"].(map[string]any)["wan"].(map[string]any)["password"].(string)
	if pw != pppoeSecret {
		t.Errorf("state.network.wan.password = %q, want the stored secret", pw)
	}

	// The step results hold the hash and the count, or the node and the
	// hash, and nothing else.
	steps, err := h.jobStore.ListSteps(h.ctx, j.ID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	want := map[string][]string{"compile": {"hash", "intentCount"}, "push": {"hash", "nodeId"}}
	for _, st := range steps {
		keys, ok := want[st.Name]
		if !ok {
			continue
		}
		var res map[string]any
		if err := json.Unmarshal(st.Result, &res); err != nil {
			t.Fatalf("step %s result: %v", st.Name, err)
		}
		if len(res) != len(keys) {
			t.Errorf("step %s result has keys beyond %v: %s", st.Name, keys, st.Result)
		}
		for _, k := range keys {
			if _, ok := res[k]; !ok {
				t.Errorf("step %s result lacks %q: %s", st.Name, k, st.Result)
			}
		}
		if res["hash"] != vectorHash {
			t.Errorf("step %s hash = %v, want %s", st.Name, res["hash"], vectorHash)
		}
	}
}

// TC-825-28: Compile and the apply command produce the previous release's
// hash and bytes for the same intents, and the compiled state holds the
// password as a secret.Value, never as a string.
func TestCompile_PPPoEVectorsUnchanged(t *testing.T) {
	stripped := vectorIntents("")
	secrets := map[string]secret.Value{"w1": secret.New([]byte(pppoeSecret))}
	defer DestroySecrets(secrets)
	state, h, err := Compile(stripped, secrets)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if h != vectorHash {
		t.Errorf("hash = %s, want %s", h, vectorHash)
	}
	if _, ok := state["network"].(map[string]any)["wan"].(map[string]any)["password"].(secret.Value); !ok {
		t.Errorf("compiled password is not a secret.Value: %#v", state["network"])
	}
	if b, _ := json.Marshal(state); strings.Contains(string(b), pppoeSecret) {
		t.Errorf("marshalling the compiled state leaks the secret: %s", b)
	}
	cmd, err := applyCommand(state, h)
	if err != nil {
		t.Fatalf("applyCommand: %v", err)
	}
	if string(cmd) != vectorCmd {
		t.Errorf("command bytes:\n got %s\nwant %s", cmd, vectorCmd)
	}
	// revealState leaves the compiled state as it was.
	if _, ok := state["network"].(map[string]any)["wan"].(map[string]any)["password"].(secret.Value); !ok {
		t.Error("applyCommand modified the compiled state")
	}

	// An inline secret in a spec is never read: only the map counts.
	if _, _, err := Compile(vectorIntents(pppoeSecret), nil); err == nil || !strings.Contains(err.Error(), "secret is required") {
		t.Errorf("Compile with an inline secret and no map: err = %v, want secret is required", err)
	}
	rotated := map[string]secret.Value{"w1": secret.New([]byte("SENTINEL-ROTATED"))}
	defer DestroySecrets(rotated)
	if _, h2, err := Compile(stripped, rotated); err != nil || h2 != vectorRotatedHash {
		t.Errorf("rotated hash = %s (err %v), want %s", h2, err, vectorRotatedHash)
	}
}

// revealState returns state itself when there is nothing to reveal, and
// Hash agrees whether the password arrives as a Value or as the string the
// agent echoes back.
func TestRevealState_NothingToReveal(t *testing.T) {
	cases := map[string]map[string]any{
		"no network":     {"firewall": map[string]any{}},
		"no wan":         {"network": map[string]any{}},
		"string pw":      {"network": map[string]any{"wan": map[string]any{"password": "x"}}},
		"no pw (dhcp)":   {"network": map[string]any{"wan": map[string]any{"proto": "dhcp"}}},
		"network is odd": {"network": "x"},
	}
	for name, st := range cases {
		got := revealState(st)
		if len(got) != len(st) {
			t.Errorf("%s: revealState changed the state: %v", name, got)
		}
		gb, _ := json.Marshal(got)
		sb, _ := json.Marshal(st)
		if string(gb) != string(sb) {
			t.Errorf("%s: revealState = %s, want %s", name, gb, sb)
		}
	}
	asValue := map[string]any{"network": map[string]any{"wan": map[string]any{"password": secret.New([]byte("x"))}}}
	asString := map[string]any{"network": map[string]any{"wan": map[string]any{"password": "x"}}}
	hv, _ := Hash(asValue)
	hs, _ := Hash(asString)
	if hv != hs {
		t.Errorf("Hash(Value) = %s, Hash(string) = %s; the agent's echo would never match", hv, hs)
	}
}

// TC-825-29: a PPPoE intent with no stored secret fails both steps with
// "secret is required", and a failing secrets read fails both with
// "read intent secrets:"; neither sends an apply RPC.
func TestApplyWorkflow_PPPoEFailsClosed(t *testing.T) {
	t.Run("no stored secret", func(t *testing.T) {
		h := newApplyHarness(t, vectorIntents(""))
		sc := newStepCtxNATS(`{}`, h.nc)
		if _, err := applyCompile(h.store)(sc); err == nil || !strings.Contains(err.Error(), "secret is required") {
			t.Errorf("compile: err = %v, want secret is required", err)
		}
		if _, err := h.pushStep(sc); err == nil || !strings.Contains(err.Error(), "secret is required") {
			t.Errorf("push: err = %v, want secret is required", err)
		}
		_ = h.nc.Flush()
		if n := h.applies.Load(); n != 0 {
			t.Errorf("apply RPCs sent = %d, want 0", n)
		}
	})
	t.Run("secrets read fails", func(t *testing.T) {
		h := newApplyHarness(t, vectorIntents(pppoeSecret))
		// The intents still list (they only test that a secret row exists);
		// reading the secret itself fails.
		if _, err := h.store.db.ExecContext(h.ctx, `ALTER TABLE firewall_intent_secrets DROP COLUMN secret`); err != nil {
			t.Fatalf("drop column: %v", err)
		}
		sc := newStepCtxNATS(`{}`, h.nc)
		for name, step := range map[string]func(*jobs.StepCtx) (json.RawMessage, error){
			"compile": applyCompile(h.store), "push": h.pushStep,
		} {
			_, err := step(sc)
			if err == nil || !strings.Contains(err.Error(), "read intent secrets:") || !strings.Contains(err.Error(), "no such column") {
				t.Errorf("%s: err = %v, want read intent secrets: wrapping the store error", name, err)
			}
		}
		_ = h.nc.Flush()
		if n := h.applies.Load(); n != 0 {
			t.Errorf("apply RPCs sent = %d, want 0", n)
		}
	})
}
