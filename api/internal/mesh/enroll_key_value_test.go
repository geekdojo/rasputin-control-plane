package mesh

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// TC-825-31: enrollDispatch sends the minted pre-auth key as
// MeshEnrollCmd.AuthKey, expires it on every outcome, and destroys the held
// secret.Value before the step returns.
func TestEnrollDispatch_PreAuthKeyIsAValueDestroyedOnEveryOutcome(t *testing.T) {
	// reply answers the enrol command; nil reply means no answer (timeout).
	cases := []struct {
		name    string
		reply   func(m *nats.Msg)
		timeout time.Duration
		wantErr string
	}{
		{name: "ack", reply: func(m *nats.Msg) {
			b, _ := json.Marshal(proto.MeshEnrollAck{OK: true, TailnetID: "hs-1", TailnetIP: "100.64.0.9", Backend: "test"})
			_ = m.Respond(b)
		}},
		{name: "rejection", wantErr: "nope", reply: func(m *nats.Msg) {
			b, _ := json.Marshal(proto.MeshEnrollAck{OK: false, Backend: "test", Detail: "nope"})
			_ = m.Respond(b)
		}},
		{name: "timeout", wantErr: "dispatch timed out", timeout: 300 * time.Millisecond},
		{name: "bad ack", wantErr: "decode ack", reply: func(m *nats.Msg) { _ = m.Respond([]byte("not json")) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newConvergeFixture(t)
			f.addNode(t, "node-1", proto.RoleCompute, time.Now().UTC())
			var mu sync.Mutex
			var gotAuthKey string
			sub, err := f.nc.Subscribe(proto.MeshEnrollSubject("node-1"), func(m *nats.Msg) {
				var cmd proto.MeshEnrollCmd
				_ = json.Unmarshal(m.Data, &cmd)
				mu.Lock()
				gotAuthKey = cmd.AuthKey
				mu.Unlock()
				if tc.reply != nil {
					tc.reply(m)
				}
			})
			if err != nil {
				t.Fatalf("subscribe: %v", err)
			}
			t.Cleanup(func() { _ = sub.Unsubscribe() })
			var held secret.Value
			var heldBytes string
			f.svc.heldEnrolKey = func(v secret.Value) {
				held = v
				heldBytes = string(v.Reveal())
			}
			ctx := f.ctx
			if tc.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(f.ctx, tc.timeout)
				defer cancel()
			}
			_, err = runWholeEnroll(t, f, "node-1", ctx)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("enroll: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("enroll err = %v, want one containing %q", err, tc.wantErr)
			}
			values, expired := f.client.minted()
			if len(values) != 1 {
				t.Fatalf("minted %d keys, want 1", len(values))
			}
			mu.Lock()
			sent := gotAuthKey
			mu.Unlock()
			if sent != values[0] {
				t.Errorf("MeshEnrollCmd.AuthKey = %q, want the minted key %q", sent, values[0])
			}
			if heldBytes != values[0] {
				t.Errorf("held key = %q, want the minted key", heldBytes)
			}
			if held.Len() != 0 {
				t.Errorf("the held key has %d bytes after the step returned, want it destroyed", held.Len())
			}
			if len(expired) != 1 {
				t.Errorf("expired %v, want exactly the minted key", expired)
			}
		})
	}
}

// TC-825-31: a mint error fails the step with "mint key:" and sends no RPC.
func TestEnrollDispatch_MintErrorSendsNothing(t *testing.T) {
	f := newConvergeFixture(t)
	f.addNode(t, "node-1", proto.RoleCompute, time.Now().UTC())
	f.client.createKeyErr = errors.New("headscale down")
	var mu sync.Mutex
	calls := 0
	sub, err := f.nc.Subscribe(proto.MeshEnrollSubject("node-1"), func(*nats.Msg) {
		mu.Lock()
		calls++
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	_, err = runWholeEnroll(t, f, "node-1", f.ctx)
	if err == nil || !strings.HasPrefix(err.Error(), "mint key:") {
		t.Fatalf("enroll err = %v, want mint key: ...", err)
	}
	_ = f.nc.Flush()
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Errorf("enrol RPCs sent = %d, want 0", calls)
	}
}

// TC-825-31: enrollCommand carries the key's bytes and the spec's fields.
func TestEnrollCommand_CarriesTheKey(t *testing.T) {
	key := secret.New([]byte("tskey-auth-example"))
	defer key.Destroy()
	b, err := enrollCommand("https://hs.example", key, EnrollSpec{NodeID: "n1", AdvertiseRoutes: []string{"10.0.0.0/24"}}, []byte("CA"))
	if err != nil {
		t.Fatalf("enrollCommand: %v", err)
	}
	var cmd proto.MeshEnrollCmd
	if err := json.Unmarshal(b, &cmd); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cmd.AuthKey != "tskey-auth-example" || cmd.LoginServer != "https://hs.example" || cmd.Hostname != "n1" ||
		!slices.Equal(cmd.AdvertiseRoutes, []string{"10.0.0.0/24"}) || !cmd.AcceptDNS || !cmd.AcceptRoutes || string(cmd.MeshCAPEM) != "CA" {
		t.Errorf("enroll command = %+v", cmd)
	}
}

// TC-825-33: the sweep writes each renewed leaf's key through writeKey, and the
// key file pairs with its certificate; a writeKey failure fails that leaf with
// the wrapped error and the rest are still swept.
func TestLeafSweep_KeysGoThroughWriteKey(t *testing.T) {
	ca := sweepTestCA(t)
	dueA, dueB, keyBlocked := t.TempDir(), t.TempDir(), t.TempDir()
	// writeKey cannot replace a directory with a file.
	if err := os.Mkdir(LeafPathsIn(keyBlocked).KeyPath, 0o700); err != nil {
		t.Fatal(err)
	}
	s := NewLeafSweeper(ca)
	for _, c := range []struct{ name, dir string }{{"a-due", dueA}, {"b-key-blocked", keyBlocked}, {"c-due", dueB}} {
		cn := c.name + ".local"
		if err := s.Register(LeafConsumer{Name: c.name, Dir: c.dir, Spec: func() (LeafSpec, error) {
			return LeafSpec{CommonName: cn, DNSNames: []string{cn}}, nil
		}}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	var logs []string
	rep := s.Sweep(context.Background(), func(_, msg string) { logs = append(logs, msg) })
	if !slices.Equal(rep.Renewed, []string{"a-due", "c-due"}) {
		t.Errorf("renewed = %v, want a-due and c-due", rep.Renewed)
	}
	if !slices.Equal(rep.Failed, []string{"b-key-blocked"}) {
		t.Errorf("failed = %v, want b-key-blocked", rep.Failed)
	}
	for _, dir := range []string{dueA, dueB} {
		paths := LeafPathsIn(dir)
		if _, err := tls.LoadX509KeyPair(paths.CertPath, paths.KeyPath); err != nil {
			t.Errorf("%s: the written key does not pair with its certificate: %v", dir, err)
		}
		st, err := os.Stat(paths.KeyPath)
		if err != nil {
			t.Fatalf("%s: stat key: %v", dir, err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s: key file mode = %v, want 0600", dir, st.Mode().Perm())
		}
	}
	if !slices.ContainsFunc(logs, func(m string) bool {
		return strings.Contains(m, "b-key-blocked: mint: mesh:")
	}) {
		t.Errorf("the writeKey failure is not logged with its wrapped error: %v", logs)
	}
}
