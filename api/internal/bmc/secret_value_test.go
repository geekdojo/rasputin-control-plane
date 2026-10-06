package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac/credmactest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup/setuptest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// The BMC credential is a secret.Value from its one reader to its exits: the
// configure command, the probe command and the config hash (ADR-0009,
// geekdojo/geekdojo-brain#825).

const bitscopeConfig = `{"targets":[{"pos":"A-0","node_id":"node-1"}]}`

// setupStoreAt opens a settings store and returns it with its path, so a test
// can make one of its keys unreadable (setuptest.UnreadableKey).
func setupStoreAt(t *testing.T) (*setup.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.db")
	st, err := setup.OpenStore(context.Background(), path)
	if err != nil {
		t.Fatalf("setup store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, path
}

// TC-825-10: bmc.configure on the real Runner. A stored credential reaches the
// configure command on the bus and neither the stored spec nor any step
// result; no stored credential injects nothing; an unreadable one fails the
// job before any RPC.
func TestConfigureJob_CredentialReachesOnlyTheBus(t *testing.T) {
	turingpiConfig := `{"endpoint":"https://turingpi.local","user":"root","pin":"` + testDevicePin + `","targets":[{"node_id":"node-1","slot":1}]}`
	for _, tc := range []struct {
		name, kind, config, stored string
		unreadable                 bool
	}{
		{name: "bitscope, stored", kind: "bitscope", config: bitscopeConfig, stored: "SENTINEL-BITSCOPE-UNLOCK"},
		{name: "turingpi, stored", kind: "turingpi", config: turingpiConfig, stored: "SENTINEL-TURINGPI-PASS"},
		{name: "bitscope, none stored", kind: "bitscope", config: bitscopeConfig},
		{name: "bitscope, unreadable", kind: "bitscope", config: bitscopeConfig, unreadable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			inv := newInvStore(t)
			insertNode(t, f, inv, "host-1")
			insertNode(t, f, inv, "node-1")
			st, path := setupStoreAt(t)
			cred, _ := CredentialFor(tc.kind)
			if tc.stored != "" {
				if err := st.Set(f.ctx, cred.SettingsKey, tc.stored); err != nil {
					t.Fatal(err)
				}
			}
			if tc.unreadable {
				setuptest.UnreadableKey(t, path, cred.SettingsKey)
			}

			var rpcs atomic.Int32
			pushed := make(chan proto.BMCConfigureCmd, 1)
			sub, err := f.nc.Subscribe(proto.BMCConfigureSubject("host-1"), func(m *nats.Msg) {
				rpcs.Add(1)
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

			jst, err := jobs.OpenStore(f.ctx, filepath.Join(t.TempDir(), "jobs.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = jst.Close() })
			runner := jobs.NewRunner(jst, f.nc)
			runner.Register(ConfigureWorkflow(f.svc, inv, st, NewSessionManager(f.svc), nil))
			j, err := runner.Submit(f.ctx, "bmc.configure", ConfigureSpec{
				Kind: tc.kind, HostNodeID: "host-1", Config: json.RawMessage(tc.config), ConfigHash: "h",
			}, "test")
			if err != nil {
				t.Fatalf("submit: %v", err)
			}
			runner.Wait()
			done, err := jst.GetJob(f.ctx, j.ID)
			if err != nil || done == nil {
				t.Fatalf("GetJob: %v", err)
			}

			if tc.unreadable {
				if done.Status != jobs.StatusFailed || !strings.Contains(done.Error, "read "+tc.kind+" credential:") {
					t.Fatalf("job ended %s %q, want a failure reading the %s credential", done.Status, done.Error, tc.kind)
				}
				if rpcs.Load() != 0 {
					t.Fatalf("%d configure RPC(s) sent with an unreadable credential, want none", rpcs.Load())
				}
				return
			}
			if done.Status != jobs.StatusSucceeded {
				t.Fatalf("job ended %s: %s", done.Status, done.Error)
			}
			cmd := <-pushed
			var cfg map[string]any
			if err := json.Unmarshal(cmd.Config, &cfg); err != nil {
				t.Fatal(err)
			}
			got, present := cfg[cred.Field]
			if tc.stored == "" {
				if present {
					t.Fatalf("no credential is stored but the command carries %q=%v", cred.Field, got)
				}
				return
			}
			if got != tc.stored {
				t.Fatalf("the command's %q is %v, want the stored credential", cred.Field, got)
			}
			if strings.Contains(string(done.Spec), tc.stored) {
				t.Errorf("the stored spec carries the credential: %s", done.Spec)
			}
			steps, _ := jst.ListSteps(f.ctx, j.ID)
			if len(steps) != 3 {
				t.Fatalf("recorded %d steps, want 3", len(steps))
			}
			for _, s := range steps {
				if strings.Contains(string(s.Result), tc.stored) || strings.Contains(s.Error, tc.stored) {
					t.Errorf("step %s carries the credential: %s %q", s.Name, s.Result, s.Error)
				}
			}
		})
	}
}

// legacyBitscopeHash is the previous release's unkeyed ConfigHash for the
// bitscope selection below with the unlock "s3kr1t-unlock": the first 16 hex
// of sha256(kind, config and credential, newline-joined), computed outside Go.
const legacyBitscopeHash = "d305fd5a1713d3b5"

// TC-827-07: ConfigHash is keyed: a pinned vector under the test key, still
// moved by rotating only the credential, and not the previous release's
// unkeyed value for the same inputs. The vectors were computed outside Go as
// HMAC-SHA256 under credmactest's key over "bmc.config", the kind, the config
// and the credential, each with a big-endian uint64 length prefix.
func TestConfigHash_KeyedAndRotationSensitive(t *testing.T) {
	const (
		wantKeyed   = "k1-e810f60e516e16c21f348a9d86c4a6440d9aeae43b23f44ca1d7e35b0ea4e72b"
		wantRotated = "k1-c3d0832f3bcf7fac266018d2445b502d12c021f318b76f83177ffa9d7ba4dc93"
	)
	mac := credmactest.Key(t)
	cred := secret.New([]byte("s3kr1t-unlock"))
	defer cred.Destroy()
	got := ConfigHash(mac, "bitscope", json.RawMessage(bitscopeConfig), cred)
	if got != wantKeyed {
		t.Errorf("ConfigHash = %s, want %s", got, wantKeyed)
	}
	if !credmac.IsKeyed(got) {
		t.Errorf("ConfigHash = %s is not keyed", got)
	}
	rotated := secret.New([]byte("rotated-unlock"))
	defer rotated.Destroy()
	gotRotated := ConfigHash(mac, "bitscope", json.RawMessage(bitscopeConfig), rotated)
	if gotRotated == got || gotRotated != wantRotated {
		t.Errorf("after rotating only the credential ConfigHash = %s, want %s (and not %s)", gotRotated, wantRotated, got)
	}
	if got == legacyBitscopeHash || strings.Contains(got, legacyBitscopeHash) {
		t.Errorf("ConfigHash still carries the previous release's unkeyed value %s", legacyBitscopeHash)
	}
	// The Service's ConfigHash is the same function under its own key.
	f := newFixture(t)
	if svcGot := f.svc.ConfigHash("bitscope", json.RawMessage(bitscopeConfig), cred); svcGot != wantKeyed {
		t.Errorf("Service.ConfigHash = %s, want %s", svcGot, wantKeyed)
	}
}

// TC-827-08 (bmc): NewService refuses a Config with no MAC, and
// StartReconcile refuses a nil Fingerprinter and subscribes to nothing.
func TestBMC_RefusesANilFingerprinter(t *testing.T) {
	f := newFixture(t)
	if svc, err := NewService(Config{HostNodeID: "host-1"}, f.store, f.nc); err == nil || svc != nil {
		t.Errorf("NewService with no MAC: svc %v, err %v; want nil and an error", svc, err)
	}
	before := f.nc.NumSubscriptions()
	stop, err := StartReconcile(f.nc, newSetupStore(t),
		func(context.Context) (bool, error) { return false, nil },
		func(context.Context, string, json.RawMessage, string) error { return nil },
		slog.New(slog.DiscardHandler), nil)
	if err == nil || stop != nil {
		if stop != nil {
			stop()
		}
		t.Fatalf("StartReconcile with a nil Fingerprinter: stop-nil=%t err=%v; want a refusal", stop == nil, err)
	}
	if after := f.nc.NumSubscriptions(); after != before {
		t.Errorf("a refused StartReconcile left %d new subscription(s)", after-before)
	}
}

// TC-827-09: a host still advertising the previous release's unkeyed hash is
// re-pushed exactly once with the keyed hash; the same registration inside
// the debounce window and one advertising the keyed hash submit nothing. The
// re-push is logged at INFO with the host, the kind and advertised_keyed, and
// no record carries either hash.
func TestReconcile_UpgradeRepushesOnceAndLogsNoHash(t *testing.T) {
	st := newSetupStore(t)
	ctx := context.Background()
	for k, val := range map[string]string{
		setup.KeyBMCBackend:        "bitscope",
		setup.KeyBMCHostNode:       "host-1",
		setup.KeyBMCConfig:         bitscopeConfig,
		setup.KeyBMCBitscopeUnlock: "s3kr1t-unlock",
	} {
		if err := st.Set(ctx, k, val); err != nil {
			t.Fatal(err)
		}
	}
	logger, rec := logkittest.New()
	var specs []ConfigureSpec
	r := &reconciler{
		st:   st,
		busy: func(context.Context) (bool, error) { return false, nil },
		submit: func(_ context.Context, kind string, spec json.RawMessage, _ string) error {
			if kind != "bmc.configure" {
				t.Errorf("submitted %q", kind)
			}
			var cs ConfigureSpec
			if err := json.Unmarshal(spec, &cs); err != nil {
				t.Fatal(err)
			}
			specs = append(specs, cs)
			return nil
		},
		log: logger,
		mac: credmactest.Key(t),
	}
	const desired = "k1-e810f60e516e16c21f348a9d86c4a6440d9aeae43b23f44ca1d7e35b0ea4e72b"

	r.onRegistered(regMsg(t, "host-1", map[string]any{proto.MetadataBMCConfigHash: legacyBitscopeHash}))
	if len(specs) != 1 || specs[0].ConfigHash != desired {
		t.Fatalf("after the upgrade registration: %d submit(s) %+v, want one with configHash %s", len(specs), specs, desired)
	}
	r.onRegistered(regMsg(t, "host-1", map[string]any{proto.MetadataBMCConfigHash: legacyBitscopeHash}))
	r.onRegistered(regMsg(t, "host-1", map[string]any{proto.MetadataBMCConfigHash: desired}))
	if len(specs) != 1 {
		t.Errorf("submitted %d job(s) in all, want exactly 1", len(specs))
	}

	infos := rec.AtLevel(slog.LevelInfo)
	var repush []slog.Record
	for _, r := range infos {
		if strings.Contains(r.Message, "re-pushing") {
			repush = append(repush, r)
		}
	}
	if len(repush) != 1 {
		t.Fatalf("want one INFO re-push record, got:\n%s", rec.Text())
	}
	for key, want := range map[string]string{"host": "host-1", "kind": "bitscope", "advertised_keyed": "false"} {
		if got, ok := logkittest.Attr(repush[0], key); !ok || got != want {
			t.Errorf("re-push record %s = %q, want %q", key, got, want)
		}
	}
	for _, h := range []string{legacyBitscopeHash, desired, strings.TrimPrefix(desired, "k1-")} {
		if strings.Contains(rec.Text(), h) {
			t.Errorf("a log record carries a hash value %s:\n%s", h, rec.Text())
		}
	}
}

// TC-825-12: the registration reconcile refuses when the stored credential
// cannot be read — on the hash path and on the legacy-credential move — and
// says so at ERROR with the host, the kind and the error.
func TestReconcile_UnreadableCredentialSubmitsNothingAndLogs(t *testing.T) {
	for _, tc := range []struct{ name, config string }{
		{"hash path", bitscopeConfig},
		{"legacy-credential move", `{"targets":[{"pos":"A-0","node_id":"node-1"}],"unlock":"inline"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, path := setupStoreAt(t)
			for k, v := range map[string]string{
				setup.KeyBMCBackend:  "bitscope",
				setup.KeyBMCHostNode: "host-1",
				setup.KeyBMCConfig:   tc.config,
			} {
				if err := st.Set(ctx, k, v); err != nil {
					t.Fatal(err)
				}
			}
			setuptest.UnreadableKey(t, path, setup.KeyBMCBitscopeUnlock)
			logger, rec := logkittest.New()
			submitted := 0
			r := &reconciler{
				st:     st,
				busy:   func(context.Context) (bool, error) { return false, nil },
				submit: func(context.Context, string, json.RawMessage, string) error { submitted++; return nil },
				log:    logger,
				mac:    credmactest.Key(t),
			}
			r.onRegistered(regMsg(t, "host-1", nil))
			if submitted != 0 {
				t.Fatalf("submitted %d job(s) with an unreadable credential, want 0", submitted)
			}
			errs := rec.AtLevel(slog.LevelError)
			if len(errs) != 1 {
				t.Fatalf("want one ERROR record, got:\n%s", rec.Text())
			}
			for key, want := range map[string]string{"host": "host-1", "kind": "bitscope"} {
				if got, ok := logkittest.Attr(errs[0], key); !ok || got != want {
					t.Errorf("record %s = %q, want %q", key, got, want)
				}
			}
			if got, ok := logkittest.Attr(errs[0], "err"); !ok || !strings.Contains(got, "read bitscope credential") {
				t.Errorf("record err = %q, want the wrapped read error", got)
			}
		})
	}
}

// TC-825-12: StartReconcile refuses a nil logger rather than failing later,
// on the first registration it cannot log about.
func TestStartReconcile_RefusesANilLogger(t *testing.T) {
	f := newFixture(t)
	stop, err := StartReconcile(f.nc, newSetupStore(t),
		func(context.Context) (bool, error) { return false, nil },
		func(context.Context, string, json.RawMessage, string) error { return nil }, nil, credmactest.Key(t))
	if err == nil {
		stop()
		t.Fatal("StartReconcile accepted a nil logger")
	}
	if stop != nil {
		t.Error("a refused StartReconcile returned an unsubscribe func")
	}
}

// TC-825-12: the one reader. An absent setting and a kind with no credential
// are the zero Value with no error; a failed read is an error and the zero
// Value, never an empty credential.
func TestStoredCredential_FailsClosed(t *testing.T) {
	ctx := context.Background()
	st, path := setupStoreAt(t)
	for _, kind := range []string{"bitscope", "mock"} {
		if v, err := StoredCredential(ctx, st, kind); err != nil || v.Len() != 0 {
			t.Errorf("%s with nothing stored: %d bytes, err %v; want the zero Value and no error", kind, v.Len(), err)
		}
	}
	setuptest.UnreadableKey(t, path, setup.KeyBMCBitscopeUnlock)
	v, err := StoredCredential(ctx, st, "bitscope")
	if err == nil || v.Len() != 0 {
		t.Fatalf("unreadable: %d bytes, err %v; want an error and the zero Value", v.Len(), err)
	}
	if !strings.Contains(err.Error(), "read bitscope credential") || errors.Unwrap(err) == nil {
		t.Errorf("err = %v, want the store error wrapped with the kind", err)
	}
}
