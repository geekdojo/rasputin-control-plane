package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/geekdojo/rasputin-control-plane/api/internal/ledgertest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
	_ "modernc.org/sqlite"
)

const pppoeSecret = "SENTINEL-PPPOE-PASSWORD"

func pppoeIntent(t *testing.T, id string, secret string) *Intent {
	t.Helper()
	return makeWANIntent(t, id, "isp", true, proto.WANConfigSpec{
		Proto: proto.WANProtoPppoe, Username: "user@isp", Secret: secret,
	})
}

// The PPPoE password is write-only: every read returns the spec without it and
// says one is stored; only the compile path gets it back.
func TestStore_PPPoESecretIsWriteOnly(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	in := pppoeIntent(t, "w1", pppoeSecret)
	if err := s.CreateIntent(ctx, in); err != nil {
		t.Fatalf("CreateIntent: %v", err)
	}
	// The caller's struct is what the create handler returns.
	if strings.Contains(string(in.Spec), pppoeSecret) || !in.SecretSet {
		t.Errorf("created intent as returned: spec=%s secretSet=%v", in.Spec, in.SecretSet)
	}
	got, err := s.GetIntent(ctx, "w1")
	if err != nil || got == nil {
		t.Fatalf("GetIntent: %v", err)
	}
	if strings.Contains(string(got.Spec), pppoeSecret) || strings.Contains(string(got.Spec), `"secret"`) {
		t.Errorf("GetIntent spec carries the secret: %s", got.Spec)
	}
	if !got.SecretSet {
		t.Error("GetIntent: secretSet = false, want true")
	}
	list, err := s.ListIntents(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListIntents: %v (%d)", err, len(list))
	}
	blob, _ := json.Marshal(list)
	ledgertest.AssertAbsentIn(t, "the ListIntents response", string(blob),
		ledgertest.Secrets("the PPPoE password", pppoeSecret))

	forCompile, err := s.ListIntentsForCompile(ctx)
	if err != nil {
		t.Fatalf("ListIntentsForCompile: %v", err)
	}
	var spec proto.WANConfigSpec
	if err := json.Unmarshal(forCompile[0].Spec, &spec); err != nil || spec.Secret != pppoeSecret {
		t.Errorf("compile input secret = %q (err %v), want the stored one", spec.Secret, err)
	}

	// An update without a secret keeps the stored one.
	got.Name = "renamed"
	if err := s.UpdateIntent(ctx, got); err != nil {
		t.Fatalf("UpdateIntent: %v", err)
	}
	if !got.SecretSet {
		t.Error("after an update with no secret, secretSet = false")
	}
	forCompile, _ = s.ListIntentsForCompile(ctx)
	_ = json.Unmarshal(forCompile[0].Spec, &spec)
	if spec.Secret != pppoeSecret {
		t.Errorf("an update with no secret changed it to %q", spec.Secret)
	}

	// An update with a secret replaces it.
	upd := pppoeIntent(t, "w1", "SENTINEL-ROTATED")
	upd.UpdatedAt = time.Now().UTC()
	if err := s.UpdateIntent(ctx, upd); err != nil {
		t.Fatalf("UpdateIntent: %v", err)
	}
	forCompile, _ = s.ListIntentsForCompile(ctx)
	_ = json.Unmarshal(forCompile[0].Spec, &spec)
	if spec.Secret != "SENTINEL-ROTATED" {
		t.Errorf("secret after rotation = %q", spec.Secret)
	}

	// Deleting the intent deletes its secret.
	if err := s.DeleteIntent(ctx, "w1"); err != nil {
		t.Fatalf("DeleteIntent: %v", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM firewall_intent_secrets`).Scan(&n); err != nil || n != 0 {
		t.Errorf("secret rows after delete = %d (err %v), want 0", n, err)
	}
}

// A database written before the slot existed has the password inside the
// spec. Opening the store moves it out, and the compiled hash — which the
// firewall agent computes over what it applied — does not change.
func TestOpenStore_MovesInlineSecretOutWithoutChangingTheHash(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "fw.db")
	in := pppoeIntent(t, "w1", pppoeSecret)
	_, wantHash, err := Compile([]*Intent{in})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Write the row the way the previous build did: secret inline.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `
        CREATE TABLE firewall_intents (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1, spec TEXT NOT NULL,
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
        INSERT INTO firewall_intents VALUES (?, ?, ?, 1, ?, 0, 0)`,
		in.ID, in.Kind, in.Name, string(in.Spec)); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	_ = raw.Close()

	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var spec string
	if err := s.db.QueryRowContext(ctx, `SELECT spec FROM firewall_intents WHERE id = 'w1'`).Scan(&spec); err != nil {
		t.Fatalf("read spec: %v", err)
	}
	if strings.Contains(spec, pppoeSecret) {
		t.Errorf("the secret is still inline after open: %s", spec)
	}
	intents, err := s.ListIntentsForCompile(ctx)
	if err != nil {
		t.Fatalf("ListIntentsForCompile: %v", err)
	}
	_, gotHash, err := Compile(intents)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if gotHash != wantHash {
		t.Errorf("hash changed across the move: %s -> %s (every firewall would report drift)", wantHash, gotHash)
	}

	// Re-opening is a no-op.
	_ = s.Close()
	s2, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	intents, _ = s2.ListIntentsForCompile(ctx)
	if _, h, _ := Compile(intents); h != wantHash {
		t.Errorf("hash after re-open = %s, want %s", h, wantHash)
	}
}

// No secret in the job ledger (geekdojo/geekdojo-brain#493, gate 6), for
// firewall.apply: a PPPoE wan_config's password reaches the agent's bus
// command, and nothing that is persisted — the spec, a step result, an event —
// or logged.
func TestApplyWorkflow_PPPoESecretNeverEntersTheLedger(t *testing.T) {
	ctx := context.Background()
	logs := ledgertest.CaptureLog(t)
	nc := startNATS(t)
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")
	store, err := OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	jobStore, err := jobs.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = jobStore.Close() })
	inv := newInventory(t)
	seedFirewallNode(t, inv, "fw")
	if err := store.CreateIntent(ctx, pppoeIntent(t, "w1", pppoeSecret)); err != nil {
		t.Fatalf("CreateIntent: %v", err)
	}

	gotPassword := make(chan string, 1)
	sub, err := nc.Subscribe(proto.FirewallApplySubject("fw"), func(m *nats.Msg) {
		var cmd proto.FirewallApplyCmd
		_ = json.Unmarshal(m.Data, &cmd)
		// The agent hashes what it applied; echo the api's hash of the same
		// state, recomputed here from the state it was sent.
		h, _ := Hash(cmd.State)
		var pw string
		if network, ok := cmd.State["network"].(map[string]any); ok {
			if wan, ok := network["wan"].(map[string]any); ok {
				pw, _ = wan["password"].(string)
			}
		}
		gotPassword <- pw
		ack, _ := json.Marshal(proto.FirewallApplyAck{OK: true, Hash: h})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	runner := jobs.NewRunner(jobStore, nc)
	runner.Register(ApplyWorkflow(store, inv, nc, nil))
	j, err := runner.Submit(ctx, "firewall.apply", json.RawMessage(`{}`), "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	runner.Wait()
	done, err := jobStore.GetJob(ctx, j.ID)
	if err != nil || done == nil {
		t.Fatalf("GetJob: %v", err)
	}
	if done.Status != jobs.StatusSucceeded {
		t.Fatalf("apply failed: %s", done.Error)
	}
	// Not vacuous: the agent really was sent the password.
	select {
	case pw := <-gotPassword:
		if pw != pppoeSecret {
			t.Fatalf("the agent was sent password %q, want the stored one", pw)
		}
	default:
		t.Fatal("the agent was never asked to apply")
	}

	secrets := ledgertest.Secrets("the PPPoE password", pppoeSecret)
	ledger := &ledgertest.Surfaces{Spec: string(done.Spec) + done.Error, Log: logs.String()}
	// Not vacuous: the agent really was sent the password, checked above.
	ledger.AssertPresent(t, "the apply command the agent received", pppoeSecret, secrets)

	steps, err := jobStore.ListSteps(ctx, j.ID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	for _, st := range steps {
		ledger.Steps += string(st.Result) + st.Error
		if st.Name == "compile" {
			var res map[string]any
			_ = json.Unmarshal(st.Result, &res)
			if _, ok := res["state"]; ok {
				t.Errorf("compile step result carries the compiled state: %s", st.Result)
			}
			if res["hash"] == "" || res["intentCount"] == nil {
				t.Errorf("compile step result should carry the hash and count: %s", st.Result)
			}
		}
	}
	events, err := jobStore.ListEvents(ctx, j.ID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, ev := range events {
		ledger.Events += string(ev.Data)
	}
	ledger.AssertAbsent(t, secrets)
}
