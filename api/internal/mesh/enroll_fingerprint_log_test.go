package mesh

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// F-741-24: after an acked enroll, the dispatch step compares the fingerprint
// the agent reports trusting with the api's. It logs "now trusts bundle" on a
// match and a warning on a mismatch, and says nothing about trust when either
// side has no fingerprint (a mesh built without trust, or an agent that
// predates the fingerprint). Each case drives the real workflow steps and
// reads the step log.
func TestEnrollDispatch_LogsTheAckedTrustFingerprint(t *testing.T) {
	apiFP := proto.TrustFingerprint(trustOriginalCA)
	otherFP := proto.TrustFingerprint(trustInterimCA)
	const (
		matchLine    = "node-1 now trusts bundle "
		mismatchLine = "node-1 reports trusting "
	)
	cases := []struct {
		name     string
		apiFP    string
		ackFP    string
		wantLine string // "" means neither line is written
		wantLvl  string
	}{
		{name: "match", apiFP: apiFP, ackFP: apiFP, wantLine: matchLine + proto.ShortFingerprint(apiFP), wantLvl: "info"},
		{name: "mismatch", apiFP: apiFP, ackFP: otherFP,
			wantLine: mismatchLine + proto.ShortFingerprint(otherFP) + " after enroll, but the api delivered " + proto.ShortFingerprint(apiFP),
			wantLvl:  "warn"},
		{name: "no api fingerprint", apiFP: "", ackFP: otherFP},
		{name: "no ack fingerprint", apiFP: apiFP, ackFP: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newConvergeFixture(t)
			// Trust is nil so no trust.install runs; only the fingerprint
			// the api compares against is set.
			f.svc = NewService(Config{TrustFingerprint: fixedFP(tc.apiFP)}, f.store, f.client, NewNoopSupervisor())
			f.addNode(t, "node-1", proto.RoleCompute, time.Now().UTC())
			sub, err := f.nc.Subscribe(proto.MeshEnrollSubject("node-1"), func(m *nats.Msg) {
				b, _ := json.Marshal(proto.MeshEnrollAck{OK: true, TailnetID: "hs-1", TailnetIP: "100.64.0.9", Backend: "test", TrustFingerprint: tc.ackFP})
				_ = m.Respond(b)
			})
			if err != nil {
				t.Fatalf("subscribe: %v", err)
			}
			t.Cleanup(func() { _ = sub.Unsubscribe() })

			type line struct{ level, msg string }
			var mu sync.Mutex
			var logs []line
			wf := EnrollNodeWorkflow(f.svc, f.inv, f.nc)
			spec, _ := json.Marshal(EnrollSpec{NodeID: "node-1"})
			prior := map[string]json.RawMessage{}
			for _, st := range wf.Steps {
				sc := &jobs.StepCtx{Ctx: f.ctx, JobID: "test-job", Spec: spec, NATS: f.nc, PriorResults: prior,
					Log: func(level, msg string) {
						mu.Lock()
						logs = append(logs, line{level, msg})
						mu.Unlock()
					}}
				res, err := st.Do(sc)
				if err != nil {
					t.Fatalf("step %s: %v", st.Name, err)
				}
				if res != nil {
					prior[st.Name] = res
				}
			}

			mu.Lock()
			defer mu.Unlock()
			var trustLines []line
			for _, l := range logs {
				if strings.Contains(l.msg, matchLine) || strings.Contains(l.msg, mismatchLine) {
					trustLines = append(trustLines, l)
				}
			}
			if tc.wantLine == "" {
				if len(trustLines) != 0 {
					t.Fatalf("trust log lines = %v, want none", trustLines)
				}
				return
			}
			if len(trustLines) != 1 || trustLines[0].msg != tc.wantLine || trustLines[0].level != tc.wantLvl {
				t.Fatalf("trust log lines = %v, want exactly [%s %q]", trustLines, tc.wantLvl, tc.wantLine)
			}
		})
	}
}
