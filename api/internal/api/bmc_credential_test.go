package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup/setuptest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// probeAgent answers the BMC host's probe subject and hands the test each
// command it received.
func probeAgent(t *testing.T, nc *nats.Conn, host string) (<-chan proto.BMCProbeCmd, *atomic.Int32) {
	t.Helper()
	got := make(chan proto.BMCProbeCmd, 4)
	var n atomic.Int32
	sub, err := nc.Subscribe(proto.BMCProbeSubject(host), func(m *nats.Msg) {
		n.Add(1)
		var cmd proto.BMCProbeCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd
		res, _ := json.Marshal(proto.BMCProbeResult{OK: true})
		_ = m.Respond(res)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return got, &n
}

// assertCredentialUnreadable checks a refusal is the coded 500 with a
// correlation id, that the store's error stays out of the body, and that the
// log carries it under that id.
func assertCredentialUnreadable(t *testing.T, f *apiFixture, code int, body []byte) {
	t.Helper()
	if code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500: %s", code, body)
	}
	var e codedError
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if e.Code != codeCredentialUnreadable || e.CorrelationID == "" {
		t.Fatalf("body = %+v, want code %q and a correlation id", e, codeCredentialUnreadable)
	}
	for _, leak := range []string{"NULL", "Scan", "sql:"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("the store's error reached the client (%q): %s", leak, body)
		}
	}
	recs := f.logs.withAttr("correlation_id", e.CorrelationID)
	if len(recs) != 1 {
		t.Fatalf("want one log record under the correlation id, got %d", len(recs))
	}
	var cause string
	recs[0].Attrs(func(a slog.Attr) bool {
		if a.Key == "err" {
			cause = a.Value.String()
		}
		return true
	})
	if !strings.Contains(cause, "credential") {
		t.Errorf("the log record's err = %q, want the store error", cause)
	}
}

// TC-825-12: set-config and the probe refuse with credential_unreadable when
// the stored credential cannot be read. Set-config submits no job; the probe
// sends no RPC.
func TestBMC_UnreadableCredentialRefusesSetConfigAndProbe(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	st := f.setupSvc.Store()
	if err := st.Set(f.ctx, setup.KeyBMCHostNode, "self-node"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "setup.db")
	setuptest.UnreadableKey(t, path, setup.KeyBMCBitscopeUnlock)
	setuptest.UnreadableKey(t, path, setup.KeyBMCTuringPiPass)

	w := f.do(t, http.MethodPost, "/api/bmc/config",
		`{"kind":"bitscope","hostNodeId":"self-node","config":{"targets":[{"pos":"A-0","node_id":"self-node"}]}}`, cookie)
	assertCredentialUnreadable(t, f, w.Code, w.Body.Bytes())
	if js, err := f.jobsStore.ListJobs(f.ctx, 10); err != nil || len(js) != 0 {
		t.Errorf("set-config submitted %d job(s) (err %v), want none", len(js), err)
	}

	_, rpcs := probeAgent(t, f.nc, "self-node")
	w = f.do(t, http.MethodPost, "/api/bmc/probe", `{"kind":"turingpi"}`, cookie)
	assertCredentialUnreadable(t, f, w.Code, w.Body.Bytes())
	if err := f.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if rpcs.Load() != 0 {
		t.Errorf("the probe sent %d RPC(s) with an unreadable credential, want none", rpcs.Load())
	}
}

// TC-825-13: a blank probe password is filled from the stored credential on
// the bus command; a typed one is sent as typed.
func TestBMCProbe_InjectsTheStoredCredential(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	st := f.setupSvc.Store()
	for k, v := range map[string]string{
		setup.KeyBMCHostNode:     "self-node",
		setup.KeyBMCTuringPiPass: "SENTINEL-STORED-PASS",
	} {
		if err := st.Set(f.ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := probeAgent(t, f.nc, "self-node")

	for _, tc := range []struct{ body, want string }{
		{`{"kind":"turingpi","user":"root"}`, "SENTINEL-STORED-PASS"},
		{`{"kind":"turingpi","user":"root","pass":"typed-by-operator"}`, "typed-by-operator"},
	} {
		w := f.do(t, http.MethodPost, "/api/bmc/probe", tc.body, cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("probe %s: %d %s", tc.body, w.Code, w.Body.String())
		}
		select {
		case cmd := <-got:
			if cmd.Pass != tc.want {
				t.Errorf("probe %s: the command's pass is %q, want %q", tc.body, cmd.Pass, tc.want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("probe %s: the host agent never received the command", tc.body)
		}
	}
}
