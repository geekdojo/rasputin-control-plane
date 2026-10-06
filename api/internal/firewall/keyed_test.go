package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac/credmactest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/ledgertest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// Vectors. The legacy values are the previous release's: its compiled state
// bytes and the unkeyed SHA-256 it (and the firewall agent, which hashes its
// input verbatim) computed over them. The keyed values are HMAC-SHA256 under
// credmactest's key over "firewall.state" and the state bytes, each with a
// big-endian uint64 length prefix. All were computed outside Go, so none leans
// on the code under test.
const (
	// pppoeLegacyState and pppoeLegacyHash are for pppoeIntent(t, "w1",
	// pppoeSecret) alone.
	pppoeLegacyState = `{"firewall":{"redirect":[],"rule":[]},"network":{"wan":{"password":"SENTINEL-PPPOE-PASSWORD","proto":"pppoe","username":"user@isp"}}}`
	pppoeLegacyHash  = "4136541b3c137e2035c97429ca2787351d4113569c568d517d5ff523f5e51983"

	// vectorState is vectorIntents with the secret pppoeSecret, compiled.
	vectorState      = `{"firewall":{"redirect":[{"dest":"lan","dest_ip":"192.168.1.10","dest_port":"80","name":"web","proto":"tcp","src":"wan","src_dport":"8080","target":"DNAT"}],"rule":[]},"network":{"wan":{"password":"SENTINEL-PPPOE-PASSWORD","proto":"pppoe","service":"internet","username":"user@isp"}}}`
	vectorLegacyHash = "23dba914fbe610d66dedb1e3140395ddd7019e045844650e8a62b275840fa71d"
	vectorKeyed      = "k1-53c93b534ef46563336939f776a1d2c6652ea445e24653353a32482a62f188de"
	vectorCmd        = `{"state":` + vectorState + `,"intentHash":"` + vectorKeyed + `"}`

	// emptyKeyed is the fingerprint of the state with no intents.
	emptyKeyed = "k1-5a5ca665ae766d4ee3025236d656e711c2325fc8f9823997e4e0ea7fa6d0b722"
)

// newService is NewService over st under the fixed test key.
func newService(t *testing.T, st stateStore) *Service {
	t.Helper()
	svc, err := NewService(st, credmactest.Key(t))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// fingerprintOf is the keyed fingerprint of state under the fixed test key.
func fingerprintOf(t *testing.T, state map[string]any) string {
	t.Helper()
	h, err := (&Service{mac: credmactest.Key(t)}).fingerprint(state)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	return h
}

// revealedJSON is the canonical bytes of state with its secret revealed:
// what the agent is sent and what the fingerprint is over.
func revealedJSON(t *testing.T, state map[string]any) string {
	t.Helper()
	b, err := json.Marshal(revealState(state))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// decodeState is a state as it arrives off the bus.
func decodeState(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	return m
}

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

// harness is the firewall workflows on the real Runner and a real store, with
// a stub firewall agent: apply acks with ackFor's answer and records each
// command; get answers with the current reply.
type harness struct {
	ctx      context.Context
	nc       *nats.Conn
	store    *Store
	svc      *Service
	inv      *inventory.Store
	jobStore *jobs.Store
	runner   *jobs.Runner
	logs     *ledgertest.Log

	applies atomic.Int32
	lastCmd atomic.Pointer[[]byte]
	ackFor  atomic.Pointer[func(proto.FirewallApplyCmd) proto.FirewallApplyAck]
	reply   atomic.Pointer[string]
	changes *nats.Subscription
}

// newHarness builds the harness. wrap, when set, puts a stateStore double
// between the Service and the real store.
func newHarness(t *testing.T, intents []*Intent, wrap func(*Store) stateStore) *harness {
	t.Helper()
	h := &harness{ctx: context.Background(), nc: startNATS(t), logs: ledgertest.CaptureLog(t)}
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")
	store, err := OpenStore(h.ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h.store = store
	var st stateStore = store
	if wrap != nil {
		st = wrap(store)
	}
	h.svc = newService(t, st)
	jobStore, err := jobs.OpenStore(h.ctx, dbPath)
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = jobStore.Close() })
	h.jobStore = jobStore
	h.inv = newInventory(t)
	seedFirewallNode(t, h.inv, "fw")
	for _, in := range intents {
		if err := store.CreateIntent(h.ctx, in); err != nil {
			t.Fatalf("CreateIntent: %v", err)
		}
	}
	h.setAck(func(proto.FirewallApplyCmd) proto.FirewallApplyAck {
		return proto.FirewallApplyAck{OK: true, Hash: vectorLegacyHash}
	})
	applySub, err := h.nc.Subscribe(proto.FirewallApplySubject("fw"), func(m *nats.Msg) {
		h.applies.Add(1)
		data := append([]byte(nil), m.Data...)
		h.lastCmd.Store(&data)
		var cmd proto.FirewallApplyCmd
		_ = json.Unmarshal(m.Data, &cmd)
		ack, _ := json.Marshal((*h.ackFor.Load())(cmd))
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent apply sub: %v", err)
	}
	getSub, err := h.nc.Subscribe(proto.FirewallGetSubject("fw"), func(m *nats.Msg) {
		_ = m.Respond([]byte(*h.reply.Load()))
	})
	if err != nil {
		t.Fatalf("agent get sub: %v", err)
	}
	h.changes, err = h.nc.SubscribeSync("rasputin.firewall.fw.*")
	if err != nil {
		t.Fatalf("change sub: %v", err)
	}
	t.Cleanup(func() {
		_ = applySub.Unsubscribe()
		_ = getSub.Unsubscribe()
		_ = h.changes.Unsubscribe()
	})
	h.runner = jobs.NewRunner(jobStore, h.nc)
	h.runner.Register(ApplyWorkflow(h.svc, h.inv, h.nc, nil))
	h.runner.Register(ReconcileWorkflow(h.svc, h.inv, h.nc, nil))
	return h
}

func (h *harness) setAck(f func(proto.FirewallApplyCmd) proto.FirewallApplyAck) { h.ackFor.Store(&f) }

// agentReports sets what the stub agent's get answers: state (canonical JSON)
// and its own hash.
func (h *harness) agentReports(t *testing.T, state, hash string) {
	t.Helper()
	b, err := json.Marshal(struct {
		State json.RawMessage `json:"state"`
		Hash  string          `json:"hash"`
	}{json.RawMessage(state), hash})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	h.reply.Store(&s)
}

// ran is one finished job and its ledger.
type ran struct {
	job     *jobs.Job
	steps   map[string]*jobs.JobStep
	logs    []proto.LogEventData
	changes []proto.FirewallChangeEvt
	ledger  *ledgertest.Surfaces
}

// run submits kind, waits for it, and collects its ledger and the change
// events it published.
func (h *harness) run(t *testing.T, kind string) *ran {
	t.Helper()
	j, err := h.runner.Submit(h.ctx, kind, json.RawMessage(`{}`), "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	h.runner.Wait()
	done, err := h.jobStore.GetJob(h.ctx, j.ID)
	if err != nil || done == nil {
		t.Fatalf("GetJob: %v", err)
	}
	r := &ran{job: done, steps: map[string]*jobs.JobStep{},
		ledger: &ledgertest.Surfaces{Spec: string(done.Spec) + done.Error, Log: h.logs.String()}}
	steps, err := h.jobStore.ListSteps(h.ctx, j.ID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	for _, st := range steps {
		r.steps[st.Name] = st
		r.ledger.Steps += string(st.Result) + st.Error
	}
	events, err := h.jobStore.ListEvents(h.ctx, j.ID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, ev := range events {
		r.ledger.Events += string(ev.Data)
		if ev.Type == string(proto.JobLog) {
			var l proto.LogEventData
			_ = json.Unmarshal(ev.Data, &l)
			r.logs = append(r.logs, l)
		}
	}
	// Flush is a round trip: every change event published before it has
	// been delivered to the sync subscription once it returns.
	if err := h.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	for {
		if n, _, _ := h.changes.Pending(); n == 0 {
			break
		}
		m, err := h.changes.NextMsg(time.Second)
		if err != nil {
			t.Fatalf("change event: %v", err)
		}
		var ev proto.FirewallChangeEvt
		_ = json.Unmarshal(m.Data, &ev)
		r.changes = append(r.changes, ev)
		r.ledger.Events += string(m.Data)
	}
	return r
}

// logsAt is the step logs at level.
func (r *ran) logsAt(level string) []string {
	var out []string
	for _, l := range r.logs {
		if l.Level == level {
			out = append(out, l.Message)
		}
	}
	return out
}

// stepResult decodes one step's result.
func (r *ran) stepResult(t *testing.T, name string) map[string]any {
	t.Helper()
	st, ok := r.steps[name]
	if !ok {
		t.Fatalf("no %s step ran", name)
	}
	var m map[string]any
	if err := json.Unmarshal(st.Result, &m); err != nil {
		t.Fatalf("step %s result %s: %v", name, st.Result, err)
	}
	return m
}

// onlyChange is the one change event a reconcile published.
func (r *ran) onlyChange(t *testing.T) proto.FirewallChangeEvt {
	t.Helper()
	if len(r.changes) != 1 {
		t.Fatalf("published %d change event(s) %+v, want one", len(r.changes), r.changes)
	}
	return r.changes[0]
}

func (h *harness) intentHash(t *testing.T) string {
	t.Helper()
	ns, err := h.store.GetNodeState(h.ctx, "fw")
	if err != nil || ns == nil {
		t.Fatalf("GetNodeState: %+v, %v", ns, err)
	}
	return ns.IntentHash
}

// assertKeyed fails for any value in m that is not a keyed fingerprint or
// empty, under the given keys.
func assertKeyed(t *testing.T, where string, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		v, _ := m[k].(string)
		if v != "" && !credmac.IsKeyed(v) {
			t.Errorf("%s %s = %q, want a keyed fingerprint", where, k, v)
		}
	}
}

// TC-827-08 (firewall): NewService refuses a nil store, a typed nil *Store and
// a nil Fingerprinter.
func TestNewService_RefusesNilCollaborators(t *testing.T) {
	key := credmactest.Key(t)
	for name, build := range map[string]func() (*Service, error){
		"a nil store":         func() (*Service, error) { return NewService(nil, key) },
		"a typed nil *Store":  func() (*Service, error) { return NewService((*Store)(nil), key) },
		"a nil Fingerprinter": func() (*Service, error) { return NewService(newStore(t), nil) },
	} {
		if svc, err := build(); err == nil || svc != nil {
			t.Errorf("%s: svc %v, err %v; want nil and an error", name, svc, err)
		}
	}
}

// TC-827-11 (carries TC-825-28): firewall.apply on the real Runner. The bus
// carries the stored PPPoE secret, the State bytes are the previous release's,
// and IntentHash is keyed; the compile input holds the secret only as a
// secret.Value; the step results hold only the keyed fingerprint and the
// count or node; and no ledger surface holds the plaintext or the unkeyed
// SHA-256 of the sent state, which the stub agent acks with.
func TestApplyWorkflow_PPPoEKeyedAndBytesUnchanged(t *testing.T) {
	h := newHarness(t, vectorIntents(pppoeSecret), nil)

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

	r := h.run(t, "firewall.apply")
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("apply failed: %s", r.job.Error)
	}
	got := h.lastCmd.Load()
	if got == nil {
		t.Fatal("the agent was never sent an apply command")
	}
	if string(*got) != vectorCmd {
		t.Errorf("apply command bytes:\n got %s\nwant %s", *got, vectorCmd)
	}
	var cmd proto.FirewallApplyCmd
	if err := json.Unmarshal(*got, &cmd); err != nil {
		t.Fatalf("decode command: %v", err)
	}
	if !credmac.IsKeyed(cmd.IntentHash) {
		t.Errorf("IntentHash = %s, want keyed", cmd.IntentHash)
	}
	pw, _ := cmd.State["network"].(map[string]any)["wan"].(map[string]any)["password"].(string)
	if pw != pppoeSecret {
		t.Errorf("state.network.wan.password = %q, want the stored secret", pw)
	}

	want := map[string][]string{"compile": {"hash", "intentCount"}, "push": {"hash", "nodeId"}}
	for name, keys := range want {
		res := r.stepResult(t, name)
		if len(res) != len(keys) {
			t.Errorf("step %s result has keys beyond %v: %v", name, keys, res)
		}
		if res["hash"] != vectorKeyed {
			t.Errorf("step %s hash = %v, want %s", name, res["hash"], vectorKeyed)
		}
	}

	secretsList := ledgertest.Secrets("the PPPoE password", pppoeSecret)
	r.ledger.AssertPresent(t, "the apply command the agent received", string(*got), secretsList)
	r.ledger.AssertAbsent(t, append(secretsList,
		ledgertest.Secrets("the unkeyed SHA-256 of the sent state", vectorLegacyHash)...))

	// The allowlist rows for the two new Reveal sites and the rewritten
	// ConfigHash reason cite this change (F-827-05).
	allow, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "secret-reveal-allow.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{}
	for _, line := range strings.Split(string(allow), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) == 3 {
			rows[parts[0]+" "+parts[1]] = parts[2]
		}
	}
	for _, key := range []string{
		"api/internal/firewall/compile.go revealState",
		"api/internal/credmac/credmac.go Key.Sum",
		"api/internal/bmc/configure.go ConfigHash",
	} {
		if reason, ok := rows[key]; !ok || !strings.Contains(reason, "geekdojo/geekdojo-brain#827") {
			t.Errorf("allowlist row %s = %q, want it present and citing geekdojo/geekdojo-brain#827", key, reason)
		}
	}
}

// TC-827-11: the compiled state holds the password as a secret.Value, and
// revealState leaves it so.
func TestCompile_PPPoEPasswordIsAValue(t *testing.T) {
	secrets := map[string]secret.Value{"w1": secret.New([]byte(pppoeSecret))}
	defer DestroySecrets(secrets)
	state, err := Compile(vectorIntents(""), secrets)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, ok := state["network"].(map[string]any)["wan"].(map[string]any)["password"].(secret.Value); !ok {
		t.Errorf("compiled password is not a secret.Value: %#v", state["network"])
	}
	if b, _ := json.Marshal(state); strings.Contains(string(b), pppoeSecret) {
		t.Errorf("marshalling the compiled state leaks the secret: %s", b)
	}
	if got := revealedJSON(t, state); got != vectorState {
		t.Errorf("revealed state:\n got %s\nwant %s", got, vectorState)
	}
	if _, ok := state["network"].(map[string]any)["wan"].(map[string]any)["password"].(secret.Value); !ok {
		t.Error("revealState modified the compiled state")
	}
	// An inline secret in a spec is never read: only the map counts.
	if _, err := Compile(vectorIntents(pppoeSecret), nil); err == nil || !strings.Contains(err.Error(), "secret is required") {
		t.Errorf("Compile with an inline secret and no map: err = %v, want secret is required", err)
	}
}

// revealState returns state itself when there is nothing to reveal, and the
// fingerprint agrees whether the password arrives as a Value or as a string.
func TestRevealState_NothingToReveal(t *testing.T) {
	cases := map[string]map[string]any{
		"no network":     {"firewall": map[string]any{}},
		"no wan":         {"network": map[string]any{}},
		"string pw":      {"network": map[string]any{"wan": map[string]any{"password": "x"}}},
		"no pw (dhcp)":   {"network": map[string]any{"wan": map[string]any{"proto": "dhcp"}}},
		"network is odd": {"network": "x"},
	}
	for name, st := range cases {
		gb, _ := json.Marshal(revealState(st))
		sb, _ := json.Marshal(st)
		if string(gb) != string(sb) {
			t.Errorf("%s: revealState = %s, want %s", name, gb, sb)
		}
	}
	asValue := map[string]any{"network": map[string]any{"wan": map[string]any{"password": secret.New([]byte("x"))}}}
	asString := map[string]any{"network": map[string]any{"wan": map[string]any{"password": "x"}}}
	if hv, hs := fingerprintOf(t, asValue), fingerprintOf(t, asString); hv != hs {
		t.Errorf("fingerprint(Value) = %s, fingerprint(string) = %s", hv, hs)
	}
}

// TC-827-12 (carries TC-825-29): a PPPoE intent with no stored secret fails
// both steps with "secret is required", and a failing secrets read fails both
// with "read intent secrets:" wrapping the store error; neither sends an
// apply RPC.
func TestApplyWorkflow_PPPoEFailsClosed(t *testing.T) {
	steps := func(h *harness) map[string]jobs.DoFn {
		return map[string]jobs.DoFn{"compile": applyCompile(h.svc), "push": applyPush(h.svc, h.inv, h.nc)}
	}
	t.Run("no stored secret", func(t *testing.T) {
		h := newHarness(t, vectorIntents(""), nil)
		for name, step := range steps(h) {
			if _, err := step(newStepCtxNATS(`{}`, h.nc)); err == nil || !strings.Contains(err.Error(), "secret is required") {
				t.Errorf("%s: err = %v, want secret is required", name, err)
			}
		}
		_ = h.nc.Flush()
		if n := h.applies.Load(); n != 0 {
			t.Errorf("apply RPCs sent = %d, want 0", n)
		}
	})
	t.Run("secrets read fails", func(t *testing.T) {
		h := newHarness(t, vectorIntents(pppoeSecret), nil)
		// The intents still list (they only test that a secret row exists);
		// reading the secret itself fails.
		if _, err := h.store.db.ExecContext(h.ctx, `ALTER TABLE firewall_intent_secrets DROP COLUMN secret`); err != nil {
			t.Fatalf("drop column: %v", err)
		}
		for name, step := range steps(h) {
			_, err := step(newStepCtxNATS(`{}`, h.nc))
			if err == nil || !strings.Contains(err.Error(), "read intent secrets:") || !strings.Contains(err.Error(), "no such column") {
				t.Errorf("%s: err = %v, want read intent secrets: wrapping the store error", name, err)
			}
		}
		if _, err := h.svc.DesiredHash(h.ctx); err == nil || !strings.Contains(err.Error(), "read intent secrets:") {
			t.Errorf("DesiredHash: err = %v, want read intent secrets:", err)
		}
		_ = h.nc.Flush()
		if n := h.applies.Load(); n != 0 {
			t.Errorf("apply RPCs sent = %d, want 0", n)
		}
	})
}

// TC-827-14: the apply ack's hash is not compared. OK=true with a legacy
// hash, "" or garbage succeeds and stores the keyed fingerprint as both the
// intent and the observed hash; OK=false fails and writes no state.
func TestApplyPush_AckHashIgnoredOKRequired(t *testing.T) {
	for _, ackHash := range []string{vectorLegacyHash, "", "garbage"} {
		h := newHarness(t, vectorIntents(pppoeSecret), nil)
		h.setAck(func(proto.FirewallApplyCmd) proto.FirewallApplyAck {
			return proto.FirewallApplyAck{OK: true, Hash: ackHash}
		})
		r := h.run(t, "firewall.apply")
		if r.job.Status != jobs.StatusSucceeded {
			t.Errorf("ack hash %q: apply ended %s %q, want success", ackHash, r.job.Status, r.job.Error)
			continue
		}
		ns, _ := h.store.GetNodeState(h.ctx, "fw")
		if ns == nil || ns.IntentHash != vectorKeyed || ns.ObservedHash != vectorKeyed {
			t.Errorf("ack hash %q: state %+v, want intent and observed %s", ackHash, ns, vectorKeyed)
		}
	}

	h := newHarness(t, vectorIntents(pppoeSecret), nil)
	h.setAck(func(proto.FirewallApplyCmd) proto.FirewallApplyAck {
		return proto.FirewallApplyAck{OK: false, Hash: vectorLegacyHash}
	})
	r := h.run(t, "firewall.apply")
	if r.job.Status != jobs.StatusFailed || !strings.Contains(r.job.Error, "agent reported apply failed") {
		t.Errorf("OK=false: apply ended %s %q, want a failure saying the agent reported apply failed", r.job.Status, r.job.Error)
	}
	if ns, _ := h.store.GetNodeState(h.ctx, "fw"); ns != nil {
		t.Errorf("OK=false wrote state %+v", ns)
	}
}

// TC-827-15: a stored keyed intent hash equal to the fingerprint of what the
// agent reports is in sync: an in_sync event, only keyed values in the fetch
// and compare results, and no apply.
func TestReconcile_KeyedInSync(t *testing.T) {
	h := newHarness(t, nil, nil)
	if err := h.store.UpdateAfterApply(h.ctx, "fw", vectorKeyed, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h.agentReports(t, vectorState, vectorLegacyHash)
	r := h.run(t, "firewall.reconcile")
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("reconcile failed: %s", r.job.Error)
	}
	if ev := r.onlyChange(t); ev.Change != proto.FirewallInSync {
		t.Errorf("change = %s, want in_sync", ev.Change)
	}
	fetch := r.stepResult(t, "fetch_observed")
	if fetch["observedHash"] != vectorKeyed {
		t.Errorf("fetch observedHash = %v, want %s", fetch["observedHash"], vectorKeyed)
	}
	assertKeyed(t, "compare", r.stepResult(t, "compare"), "intentHash", "observedHash")
	if n := h.applies.Load(); n != 0 {
		t.Errorf("apply RPCs = %d, want 0", n)
	}
}

// TC-827-16: a stored pre-upgrade hash equal to the agent's own hash is
// adopted: the stored hash becomes the keyed fingerprint of what the agent
// reports, compare reports in_sync, nothing is applied, one INFO step log says
// so without a hash, and no surface carries the legacy value.
func TestReconcile_AdoptsAnInSyncLegacyHash(t *testing.T) {
	h := newHarness(t, nil, nil)
	if err := h.store.UpdateAfterApply(h.ctx, "fw", vectorLegacyHash, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h.agentReports(t, vectorState, vectorLegacyHash)
	before := h.intentHash(t)
	r := h.run(t, "firewall.reconcile")
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("reconcile failed: %s", r.job.Error)
	}
	if got := h.intentHash(t); got != vectorKeyed {
		t.Errorf("stored intent hash = %s, want the keyed %s", got, vectorKeyed)
	}
	if ev := r.onlyChange(t); ev.Change != proto.FirewallInSync {
		t.Errorf("change = %s, want in_sync", ev.Change)
	}
	if n := h.applies.Load(); n != 0 {
		t.Errorf("apply RPCs = %d, want 0", n)
	}
	infos := r.logsAt("info")
	adopted := 0
	for _, m := range infos {
		if strings.Contains(m, "adopted") {
			adopted++
			if strings.Contains(m, "k1-") || strings.Contains(m, vectorLegacyHash[:12]) {
				t.Errorf("the adoption log carries a hash: %q", m)
			}
		}
	}
	if adopted != 1 {
		t.Errorf("adoption INFO logs = %d (%v), want 1", adopted, infos)
	}
	legacy := ledgertest.Secrets("the pre-upgrade hash", vectorLegacyHash, "its prefix", vectorLegacyHash[:12])
	r.ledger.AssertPresent(t, "the stored row before the reconcile", before, legacy)
	r.ledger.AssertAbsent(t, legacy)
}

// TC-827-17: a stored pre-upgrade hash that differs from the agent's own is
// forgotten, not adopted: the stored hash becomes "", compare reports drift,
// one WARN step log carries no hash, and no surface carries the legacy value.
func TestReconcile_ForgetsADriftedLegacyHash(t *testing.T) {
	h := newHarness(t, nil, nil)
	if err := h.store.UpdateAfterApply(h.ctx, "fw", vectorLegacyHash, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h.agentReports(t, vectorState, pppoeLegacyHash)
	before := h.intentHash(t)
	r := h.run(t, "firewall.reconcile")
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("reconcile failed: %s", r.job.Error)
	}
	if got := h.intentHash(t); got != "" {
		t.Errorf("stored intent hash = %q, want it forgotten", got)
	}
	if ev := r.onlyChange(t); ev.Change != proto.FirewallDrift {
		t.Errorf("change = %s, want drift", ev.Change)
	}
	warns := r.logsAt("warn")
	forgot := 0
	for _, m := range warns {
		if strings.Contains(m, "before this upgrade") {
			forgot++
			if strings.Contains(m, "k1-") || strings.Contains(m, vectorLegacyHash[:12]) {
				t.Errorf("the forget log carries a hash: %q", m)
			}
		}
	}
	if forgot != 1 {
		t.Errorf("forget WARN logs = %d (%v), want 1", forgot, warns)
	}
	legacy := ledgertest.Secrets("the pre-upgrade hash", vectorLegacyHash, "its prefix", vectorLegacyHash[:12])
	r.ledger.AssertPresent(t, "the stored row before the reconcile", before, legacy)
	r.ledger.AssertAbsent(t, legacy)
}

// TC-827-18 (F-827-01): a never-applied node (intent hash "", no last
// applied) is left alone: two reconciles make no adoption or forget write, log
// no WARN, and report no drift.
func TestReconcile_NeverAppliedNodeIsLeftAlone(t *testing.T) {
	var writes atomic.Int32
	h := newHarness(t, nil, func(s *Store) stateStore { return &countingStore{Store: s, casWrites: &writes} })
	if err := h.store.UpdateAfterReconcile(h.ctx, "fw", "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h.agentReports(t, vectorState, vectorLegacyHash)
	for i := range 2 {
		r := h.run(t, "firewall.reconcile")
		if r.job.Status != jobs.StatusSucceeded {
			t.Fatalf("run %d: reconcile failed: %s", i, r.job.Error)
		}
		if ev := r.onlyChange(t); ev.Change == proto.FirewallDrift {
			t.Errorf("run %d: a never-applied node reported drift", i)
		}
		if w := r.logsAt("warn"); len(w) != 0 {
			t.Errorf("run %d: WARN logs %v, want none", i, w)
		}
		ns, _ := h.store.GetNodeState(h.ctx, "fw")
		if ns.IntentHash != "" || ns.LastApplied != nil {
			t.Errorf("run %d: the row changed: %+v", i, ns)
		}
	}
	if n := writes.Load(); n != 0 {
		t.Errorf("adoption/forget writes = %d, want 0", n)
	}
}

// TC-827-19 (F-827-01): with a pre-upgrade hash stored, an agent read failure
// (Hash "") leaves the stored value, fails the fetch step, never runs compare
// and leaks nothing; the next healthy reconcile adopts. With a keyed hash
// stored, the same failure records "" and reports no drift.
func TestReconcile_AgentReadFailureWithALegacyHash(t *testing.T) {
	h := newHarness(t, nil, nil)
	if err := h.store.UpdateAfterApply(h.ctx, "fw", vectorLegacyHash, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h.agentReports(t, `{}`, "")
	before := h.intentHash(t)
	r := h.run(t, "firewall.reconcile")
	if r.job.Status != jobs.StatusFailed {
		t.Fatalf("reconcile ended %s, want failed", r.job.Status)
	}
	if st := r.steps["fetch_observed"]; st == nil || st.Status != jobs.StepFailed {
		t.Errorf("fetch step: %+v, want failed", st)
	}
	if st, ran := r.steps["compare"]; ran {
		t.Errorf("compare ran: %+v", st)
	}
	if got := h.intentHash(t); got != vectorLegacyHash {
		t.Errorf("stored intent hash changed to %q", got)
	}
	if len(r.changes) != 0 {
		t.Errorf("published %+v, want nothing", r.changes)
	}
	legacy := ledgertest.Secrets("the pre-upgrade hash", vectorLegacyHash, "its prefix", vectorLegacyHash[:12])
	r.ledger.AssertPresent(t, "the stored row before the reconcile", before, legacy)
	r.ledger.AssertAbsent(t, legacy)

	h.agentReports(t, vectorState, vectorLegacyHash)
	if r := h.run(t, "firewall.reconcile"); r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("healthy reconcile failed: %s", r.job.Error)
	}
	if got := h.intentHash(t); got != vectorKeyed {
		t.Errorf("after a healthy reconcile the stored hash = %s, want adopted %s", got, vectorKeyed)
	}

	// Keyed stored, agent cannot read: observed "" and no drift.
	k := newHarness(t, nil, nil)
	if err := k.store.UpdateAfterApply(k.ctx, "fw", vectorKeyed, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	k.agentReports(t, `{}`, "")
	r = k.run(t, "firewall.reconcile")
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("keyed: reconcile failed: %s", r.job.Error)
	}
	if ns, _ := k.store.GetNodeState(k.ctx, "fw"); ns.ObservedHash != "" {
		t.Errorf("keyed: observed hash = %q, want \"\"", ns.ObservedHash)
	}
	if ev := r.onlyChange(t); ev.Change == proto.FirewallDrift {
		t.Error("keyed: an unread agent reported drift")
	}
}

// TC-827-20: a change to the observed WAN password alone is drift.
func TestReconcile_PasswordOnlyChangeIsDrift(t *testing.T) {
	h := newHarness(t, nil, nil)
	if err := h.store.UpdateAfterApply(h.ctx, "fw", vectorKeyed, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h.agentReports(t, strings.Replace(vectorState, pppoeSecret, "SENTINEL-CHANGED-ON-THE-BOX", 1), vectorLegacyHash)
	r := h.run(t, "firewall.reconcile")
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("reconcile failed: %s", r.job.Error)
	}
	if ev := r.onlyChange(t); ev.Change != proto.FirewallDrift {
		t.Errorf("change = %s, want drift", ev.Change)
	}
}

// TC-827-21: the observed password is sealed into a secret.Value and
// destroyed when the fetch returns, on success and on a failure after decode.
func TestObserve_DestroysTheSealedPassword(t *testing.T) {
	reply, _ := json.Marshal(proto.FirewallGetAck{State: decodeState(t, vectorState), Hash: vectorLegacyHash})
	for name, wrap := range map[string]func(*Store) stateStore{
		"success":                nil,
		"failure after decoding": func(s *Store) stateStore { return &failingStore{Store: s, failReconcile: true} },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil, wrap)
			var sealed secret.Value
			sealedLen := -1
			h.svc.onSealed = func(v secret.Value) { sealed, sealedLen = v, v.Len() }
			_, err := h.svc.observe(h.ctx, "fw", reply, time.Now().UTC(), func(string, string) {})
			if (wrap == nil) != (err == nil) {
				t.Fatalf("observe err = %v", err)
			}
			if sealedLen != len(pppoeSecret) {
				t.Fatalf("sealed %d bytes, want the %d-byte password", sealedLen, len(pppoeSecret))
			}
			if sealed.Len() != 0 {
				t.Errorf("the sealed password holds %d bytes after observe returned", sealed.Len())
			}
		})
	}
}

// TC-827-22: a failure of the adoption write, the forget write, or the
// observed-hash write fails the fetch step with "firewall: record reconcile
// state:" wrapping the cause, and compare never runs.
func TestReconcile_PersistenceFailureFailsTheStep(t *testing.T) {
	for name, tc := range map[string]struct {
		fail      failingStore
		agentHash string
	}{
		"adoption write":       {failingStore{failAdopt: true}, vectorLegacyHash},
		"forget write":         {failingStore{failForget: true}, pppoeLegacyHash},
		"UpdateAfterReconcile": {failingStore{failReconcile: true}, vectorLegacyHash},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil, func(s *Store) stateStore {
				f := tc.fail
				f.Store = s
				return &f
			})
			if err := h.store.UpdateAfterApply(h.ctx, "fw", vectorLegacyHash, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			h.agentReports(t, vectorState, tc.agentHash)
			r := h.run(t, "firewall.reconcile")
			st := r.steps["fetch_observed"]
			if st == nil || st.Status != jobs.StepFailed ||
				!strings.HasPrefix(st.Error, "firewall: record reconcile state: ") || !strings.Contains(st.Error, errInjected.Error()) {
				t.Errorf("fetch step: %+v, want a failure starting firewall: record reconcile state: and wrapping the cause", st)
			}
			if _, ran := r.steps["compare"]; ran {
				t.Error("compare ran after a persistence failure")
			}
		})
	}
}

// TC-827-23: the adoption and forget writes are compare-and-set: an apply that
// replaced the legacy hash first wins, and the write reports no change. Shown
// on the store, and through observe reading the legacy hash just before the
// apply lands.
func TestAdoptAndForget_LoseToAConcurrentApply(t *testing.T) {
	ctx := context.Background()
	for name, write := range map[string]func(*Store) (bool, error){
		"adopt":  func(s *Store) (bool, error) { return s.AdoptIntentHash(ctx, "fw", vectorLegacyHash, "k1-observed") },
		"forget": func(s *Store) (bool, error) { return s.ForgetIntentHash(ctx, "fw", vectorLegacyHash) },
	} {
		s := newStore(t)
		if err := s.UpdateAfterApply(ctx, "fw", vectorLegacyHash, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateAfterApply(ctx, "fw", vectorKeyed, time.Now().UTC()); err != nil { // the concurrent apply
			t.Fatal(err)
		}
		changed, err := write(s)
		if err != nil || changed {
			t.Errorf("%s: changed %v, err %v; want no change", name, changed, err)
		}
		if ns, _ := s.GetNodeState(ctx, "fw"); ns.IntentHash != vectorKeyed {
			t.Errorf("%s: stored %s, want the apply's %s", name, ns.IntentHash, vectorKeyed)
		}
	}

	for name, agentHash := range map[string]string{"adopt": vectorLegacyHash, "forget": pppoeLegacyHash} {
		t.Run("through observe: "+name, func(t *testing.T) {
			var st *staleStore
			h := newHarness(t, nil, func(s *Store) stateStore { st = &staleStore{Store: s}; return st })
			if err := h.store.UpdateAfterApply(h.ctx, "fw", vectorLegacyHash, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			st.applyAfterRead = func() {
				if err := h.store.UpdateAfterApply(h.ctx, "fw", emptyKeyed, time.Now().UTC()); err != nil {
					t.Error(err)
				}
			}
			reply, _ := json.Marshal(proto.FirewallGetAck{State: decodeState(t, vectorState), Hash: agentHash})
			var logs []string
			if _, err := h.svc.observe(h.ctx, "fw", reply, time.Now().UTC(), func(l, m string) { logs = append(logs, l+" "+m) }); err != nil {
				t.Fatalf("observe: %v", err)
			}
			if got := h.intentHash(t); got != emptyKeyed {
				t.Errorf("stored %s, want the concurrent apply's %s", got, emptyKeyed)
			}
			if len(logs) != 0 {
				t.Errorf("logged %v for a write that changed nothing", logs)
			}
		})
	}
}

// TC-827-24: the fingerprint of a compiled state equals the fingerprint of the
// same state after the bus round trip and sealing, for every intent kind; the
// empty state's fingerprint is EmptyHash, which is also what a stub agent's
// empty-state reply observes as.
func TestFingerprint_CanonicalEquality(t *testing.T) {
	dns := dnsForwardIntent(t, "d1", true, "home1.internal", "192.168.1.5")
	rule := makeRuleIntent(t, "r1", "block", proto.FirewallRuleSpec{Src: "iot", Dest: "lan", Proto: proto.RuleProtoTCP, DestPort: "22", Target: proto.RuleTargetReject, Log: true})
	intents := append(vectorIntents(""), rule, dns)
	secrets := map[string]secret.Value{"w1": secret.New([]byte(pppoeSecret))}
	defer DestroySecrets(secrets)
	compiled, err := Compile(intents, secrets)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	observed := decodeState(t, revealedJSON(t, compiled))
	sealed := sealObservedSecret(observed)
	defer sealed.Destroy()
	if sealed.Len() == 0 {
		t.Fatal("the observed password was not sealed")
	}
	if a, b := fingerprintOf(t, compiled), fingerprintOf(t, observed); a != b {
		t.Errorf("compiled %s != observed %s", a, b)
	}

	h := newHarness(t, nil, nil)
	empty, err := Compile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := fingerprintOf(t, empty); got != h.svc.EmptyHash() || got != emptyKeyed {
		t.Errorf("fingerprint(Compile(nil)) = %s, EmptyHash = %s, want both %s", got, h.svc.EmptyHash(), emptyKeyed)
	}
	reply := []byte(`{"state":{"firewall":{"redirect":[],"rule":[]}},"hash":"a58e6b84c49ec0e762571908e135228c891fd4b25be6ca878a9aad0ed4b81c47"}`)
	got, err := h.svc.observe(h.ctx, "fw", reply, time.Now().UTC(), func(string, string) {})
	if err != nil || got != h.svc.EmptyHash() {
		t.Errorf("an empty-state reply observes as %s (err %v), want EmptyHash %s", got, err, h.svc.EmptyHash())
	}
}

// TC-827-31: Service.NodeState is nil for a node with nothing stored, and a
// just-applied node is not drift. The drift rows are the retargeted
// TestNodeState_* tests in firewall_test.go.
func TestNodeState_NoRowAndJustApplied(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	svc := newService(t, s)
	if ns, err := svc.NodeState(ctx, "fw"); ns != nil || err != nil {
		t.Errorf("no row: %+v, %v; want nil", ns, err)
	}
	if err := s.UpdateAfterApply(ctx, "fw", vectorKeyed, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if ns, _ := svc.NodeState(ctx, "fw"); ns == nil || ns.Drift {
		t.Errorf("just applied: %+v, want no drift", ns)
	}
}

// errInjected is what the stateStore doubles fail with.
var errInjected = errors.New("SENTINEL-STORE-FAILURE")

// failingStore fails the chosen writes.
type failingStore struct {
	*Store
	failAdopt, failForget, failReconcile bool
}

func (f *failingStore) AdoptIntentHash(ctx context.Context, nodeID, legacy, keyed string) (bool, error) {
	if f.failAdopt {
		return false, errInjected
	}
	return f.Store.AdoptIntentHash(ctx, nodeID, legacy, keyed)
}

func (f *failingStore) ForgetIntentHash(ctx context.Context, nodeID, legacy string) (bool, error) {
	if f.failForget {
		return false, errInjected
	}
	return f.Store.ForgetIntentHash(ctx, nodeID, legacy)
}

func (f *failingStore) UpdateAfterReconcile(ctx context.Context, nodeID, observedHash string, ts time.Time) error {
	if f.failReconcile {
		return errInjected
	}
	return f.Store.UpdateAfterReconcile(ctx, nodeID, observedHash, ts)
}

// countingStore counts adoption and forget writes.
type countingStore struct {
	*Store
	casWrites *atomic.Int32
}

func (c *countingStore) AdoptIntentHash(ctx context.Context, nodeID, legacy, keyed string) (bool, error) {
	c.casWrites.Add(1)
	return c.Store.AdoptIntentHash(ctx, nodeID, legacy, keyed)
}

func (c *countingStore) ForgetIntentHash(ctx context.Context, nodeID, legacy string) (bool, error) {
	c.casWrites.Add(1)
	return c.Store.ForgetIntentHash(ctx, nodeID, legacy)
}

// staleStore runs applyAfterRead right after a node-state read: an apply that
// lands between the shim's read and its write.
type staleStore struct {
	*Store
	applyAfterRead func()
}

func (s *staleStore) GetNodeState(ctx context.Context, nodeID string) (*NodeState, error) {
	ns, err := s.Store.GetNodeState(ctx, nodeID)
	if s.applyAfterRead != nil {
		s.applyAfterRead()
		s.applyAfterRead = nil
	}
	return ns, err
}
