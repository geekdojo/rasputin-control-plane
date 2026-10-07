package nodetrust

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

var bundle = []byte("-----BEGIN CERTIFICATE-----\nCONTROLPLANE\n-----END CERTIFICATE-----\n")

func embeddedNATS(t *testing.T) *nats.Conn {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Cleanup(func() { ns.Shutdown(); ns.WaitForShutdown() })
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// logs captures slog records.
type logs struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *logs) Enabled(context.Context, slog.Level) bool { return true }
func (h *logs) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r.Clone())
	return nil
}
func (h *logs) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logs) WithGroup(string) slog.Handler      { return h }

func (h *logs) at(level slog.Level) []map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []map[string]string
	for _, r := range h.recs {
		if r.Level != level {
			continue
		}
		m := map[string]string{"msg": r.Message}
		r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.String(); return true })
		out = append(out, m)
	}
	return out
}

type fixture struct {
	ctx context.Context
	nc  *nats.Conn
	inv *inventory.Store
	svc *Service
	log *logs

	mu  sync.Mutex
	got []string // node ids that received trust.install
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	inv, err := inventory.OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	f := &fixture{ctx: ctx, nc: embeddedNATS(t), inv: inv, log: &logs{}}
	svc, err := New(Options{Bundle: bundle, Nodes: inv, Log: slog.New(f.log)})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

func floor(t *testing.T) string {
	t.Helper()
	v, ok := proto.VerbMinAgentVersion(proto.TrustInstallVerb)
	if !ok {
		t.Fatal("trust.install has no floor")
	}
	return v
}

const oldAgent = "2026.09.1-dev.150"

func (f *fixture) node(t *testing.T, id, version, fp string, lastSeen time.Time) {
	t.Helper()
	n := &proto.Node{ID: id, Role: proto.RoleCompute, Hostname: id, AgentVersion: version, FirstSeen: lastSeen, LastSeen: lastSeen}
	if fp != "" {
		n.Metadata = map[string]any{proto.MetadataTrustFingerprint: fp}
	}
	if err := f.inv.Insert(f.ctx, n); err != nil {
		t.Fatal(err)
	}
}

// agent answers trust.install for id with reply(cmd).
func (f *fixture) agent(t *testing.T, id string, reply func(proto.TrustInstallCmd) any) {
	t.Helper()
	sub, err := f.nc.Subscribe(proto.TrustInstallSubject(id), func(m *nats.Msg) {
		var cmd proto.TrustInstallCmd
		_ = json.Unmarshal(m.Data, &cmd)
		f.mu.Lock()
		f.got = append(f.got, id)
		f.mu.Unlock()
		var b []byte
		switch r := reply(cmd).(type) {
		case []byte:
			b = r
		default:
			b, _ = json.Marshal(r)
		}
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := f.nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

func okAck(id string) func(proto.TrustInstallCmd) any {
	return func(c proto.TrustInstallCmd) any {
		return proto.TrustInstallAck{NodeID: id, OK: true, Changed: true, Fingerprint: proto.TrustFingerprint(c.BundlePEM)}
	}
}

func TestNew_RefusesAnEmptyBundleOrMissingCollaborators(t *testing.T) {
	log := slog.New(&logs{})
	for name, o := range map[string]Options{
		"no bundle":         {Nodes: &inventory.Store{}, Log: log},
		"whitespace bundle": {Bundle: []byte(" \n"), Nodes: &inventory.Store{}, Log: log},
		"no nodes":          {Bundle: bundle, Log: log},
		"no log":            {Bundle: bundle, Nodes: &inventory.Store{}},
	} {
		if s, err := New(o); err == nil || s != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TC-741-14: every Deliver outcome, against an embedded nats-server.
func TestDeliver_Outcomes(t *testing.T) {
	now := time.Now()
	want := proto.TrustFingerprint(bundle)
	for _, tc := range []struct {
		name    string
		version string
		seen    time.Time
		reply   func(proto.TrustInstallCmd) any // nil: no responder
		check   func(t *testing.T, ack proto.TrustInstallAck, err error)
	}{
		{"an OK ack with the api's fingerprint", floor(t), now, okAck("n1"), func(t *testing.T, ack proto.TrustInstallAck, err error) {
			if err != nil || !ack.OK || ack.Fingerprint != want {
				t.Errorf("ack %+v err %v", ack, err)
			}
		}},
		{"an OK ack for another bundle", floor(t), now, func(proto.TrustInstallCmd) any {
			return proto.TrustInstallAck{OK: true, Fingerprint: "0123456789abcdef-other"}
		}, func(t *testing.T, _ proto.TrustInstallAck, err error) {
			if err == nil || !strings.Contains(err.Error(), "0123456789ab") || !strings.Contains(err.Error(), proto.ShortFingerprint(want)) {
				t.Errorf("err %v, want both fingerprints named", err)
			}
		}},
		{"an OK=false ack", floor(t), now, func(proto.TrustInstallCmd) any {
			return proto.TrustInstallAck{Detail: "installed; reloading tailscaled failed: boom"}
		}, func(t *testing.T, _ proto.TrustInstallAck, err error) {
			if err == nil || !strings.Contains(err.Error(), "reloading tailscaled failed: boom") {
				t.Errorf("err %v, want the detail", err)
			}
		}},
		{"a malformed ack", floor(t), now, func(proto.TrustInstallCmd) any { return []byte("{not json") }, func(t *testing.T, _ proto.TrustInstallAck, err error) {
			if err == nil || !strings.Contains(err.Error(), "could not be read") {
				t.Errorf("err %v", err)
			}
		}},
		{"no responder, agent below the floor", oldAgent, now, nil, func(t *testing.T, _ proto.TrustInstallAck, err error) {
			if !errors.Is(err, ErrAgentPredatesVerb) {
				t.Errorf("err %v, want ErrAgentPredatesVerb", err)
			}
		}},
		{"no responder, agent at the floor", floor(t), now, nil, func(t *testing.T, _ proto.TrustInstallAck, err error) {
			if err == nil || errors.Is(err, ErrAgentPredatesVerb) || !strings.Contains(err.Error(), "should answer "+proto.TrustInstallVerb) {
				t.Errorf("err %v, want the ExplainNoResponder sentence", err)
			}
		}},
		{"no responder, node offline", floor(t), now.Add(-time.Hour), nil, func(t *testing.T, _ proto.TrustInstallAck, err error) {
			if err == nil || errors.Is(err, ErrAgentPredatesVerb) || !strings.Contains(err.Error(), "offline") {
				t.Errorf("err %v, want an offline reading", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.node(t, "n1", tc.version, "", tc.seen)
			if tc.reply != nil {
				f.agent(t, "n1", tc.reply)
			}
			ack, err := f.svc.Deliver(f.ctx, f.nc, "n1")
			tc.check(t, ack, err)
		})
	}
}

// TC-741-15: trust.converge selects the stale, online, current-agent nodes
// (mesh enrollment does not matter; "none" and "reload-pending" are stale),
// counts below-floor nodes as legacy_agent, skips offline ones, goes on past
// one node's failure with a WARN naming it, and logs one INFO summary. Online
// is inventory's Status at its injected clock: the nodes' last-seen is an
// hour before the wall clock, so a pass that read the wall clock would find
// every node offline.
func TestConverge_Selection(t *testing.T) {
	f := newFixture(t)
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	f.inv.SetNow(func() time.Time { return at })
	current := proto.TrustFingerprint(bundle)
	fl := floor(t)
	f.node(t, "stale", fl, "some-other-bundle", at)
	f.node(t, "none", fl, proto.TrustFingerprintNone, at)
	f.node(t, "pending", fl, proto.TrustFingerprintReloadPending, at)
	f.node(t, "failing", fl, "some-other-bundle", at)
	f.node(t, "current", fl, current, at)
	f.node(t, "unreported", fl, "", at)
	f.node(t, "legacy", oldAgent, "some-other-bundle", at)
	f.node(t, "offline", fl, "some-other-bundle", at.Add(-time.Hour))
	for _, id := range []string{"stale", "none", "pending", "current", "unreported", "legacy", "offline"} {
		f.agent(t, id, okAck(id))
	}
	f.agent(t, "failing", func(proto.TrustInstallCmd) any { return proto.TrustInstallAck{Detail: "write refused"} })

	var feed []string
	res, err := f.svc.Converge(f.ctx, f.nc, func(level, msg string) { feed = append(feed, level+": "+msg) })
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(f.got)
	if want := []string{"failing", "none", "pending", "stale"}; !slices.Equal(f.got, want) {
		t.Errorf("trust.install sent to %v, want %v", f.got, want)
	}
	if want := []string{"none", "pending", "stale"}; !slices.Equal(res.Redelivered, want) {
		t.Errorf("redelivered %v, want %v", res.Redelivered, want)
	}
	if want := []string{"failing", "legacy", "none", "offline", "pending", "stale"}; !slices.Equal(res.Stale, want) {
		t.Errorf("stale %v, want %v", res.Stale, want)
	}
	if !slices.Equal(res.Current, []string{"current"}) || !slices.Equal(res.Unreported, []string{"unreported"}) {
		t.Errorf("current %v unreported %v", res.Current, res.Unreported)
	}
	if res.Skipped["legacy_agent"] != 1 || res.Skipped["offline"] != 1 || res.Skipped["delivery_failed"] != 1 {
		t.Errorf("skipped %v", res.Skipped)
	}
	if res.CAFingerprint != current {
		t.Errorf("result fingerprint %s", res.CAFingerprint)
	}
	warns := f.log.at(slog.LevelWarn)
	if len(warns) != 1 || warns[0]["node"] != "failing" || !strings.Contains(warns[0]["err"], "write refused") {
		t.Errorf("WARN records %v, want one naming the failing node and its err", warns)
	}
	infos := f.log.at(slog.LevelInfo)
	if len(infos) != 1 || infos[0]["installed"] != "3" || infos[0]["stale"] != "6" || infos[0]["current"] != "1" {
		t.Errorf("INFO records %v, want one summary with the counts", infos)
	}
	raw, _ := json.Marshal(res)
	all := string(raw) + strings.Join(feed, "\n")
	for _, r := range f.log.recs {
		all += r.Message
		r.Attrs(func(a slog.Attr) bool { all += a.Value.String(); return true })
	}
	if strings.Contains(all, "BEGIN CERTIFICATE") || strings.Contains(all, "CONTROLPLANE") {
		t.Error("PEM material reached a log or the result")
	}
}

// answered is a Requester over nc that reports each subject whose request
// came back with an answer.
type answered struct {
	nc   *nats.Conn
	done chan string
}

func (a answered) RequestWithContext(ctx context.Context, subj string, data []byte) (*nats.Msg, error) {
	m, err := a.nc.RequestWithContext(ctx, subj, data)
	if err == nil {
		a.done <- subj
	}
	return m, err
}

// TC-741-15 (F-741-20): one slow node does not starve the rest, and a pass
// its context ends still returns its result. The slow node is first in
// inventory order and does not answer until the test lets it; the other two
// are delivered to while it hangs. Once both have answered, the pass's
// context ends, as the step deadline would: the slow node is counted under
// Skipped["deadline"] and named in one WARN, not counted as a failure, and
// Converge returns the partial result with no error.
func TestConverge_SlowNodeDoesNotStarveTheRest(t *testing.T) {
	f := newFixture(t)
	at := time.Now().UTC().Truncate(time.Second)
	f.inv.SetNow(func() time.Time { return at })
	fl := floor(t)
	f.node(t, "a-slow", fl, "some-other-bundle", at.Add(-2*time.Second))
	f.node(t, "b-fast", fl, "some-other-bundle", at.Add(-time.Second))
	f.node(t, "c-fast", fl, "some-other-bundle", at)
	release := make(chan struct{})
	f.agent(t, "a-slow", func(c proto.TrustInstallCmd) any { <-release; return okAck("a-slow")(c) })
	defer close(release)
	f.agent(t, "b-fast", okAck("b-fast"))
	f.agent(t, "c-fast", okAck("c-fast"))

	ctx, end := context.WithCancelCause(f.ctx)
	req := answered{nc: f.nc, done: make(chan string, 3)}
	go func() {
		// Ends the pass once both fast nodes have answered. The bound only
		// turns a serial regression into a failure instead of a hang.
		bound := time.After(30 * time.Second)
		for n := 0; n < 2; n++ {
			select {
			case <-req.done:
			case <-bound:
				end(errors.New("test bound: the fast nodes never answered"))
				return
			}
		}
		end(errors.New("step deadline"))
	}()

	res, err := f.svc.Converge(ctx, req, nil)
	if err != nil {
		t.Fatalf("a pass its context ended returned %v, want its result and no error", err)
	}
	if want := []string{"b-fast", "c-fast"}; !slices.Equal(res.Redelivered, want) {
		t.Errorf("redelivered %v, want %v: the slow node starved the rest", res.Redelivered, want)
	}
	if want := []string{"a-slow", "b-fast", "c-fast"}; !slices.Equal(res.Stale, want) {
		t.Errorf("stale %v, want %v", res.Stale, want)
	}
	if res.Skipped["deadline"] != 1 || res.Skipped["delivery_failed"] != 0 {
		t.Errorf("skipped %v, want the slow node under deadline only", res.Skipped)
	}
	warns := f.log.at(slog.LevelWarn)
	if len(warns) != 1 || warns[0]["nodes"] != "a-slow" || warns[0]["count"] != "1" || warns[0]["err"] != "step deadline" {
		t.Errorf("WARN records %v, want one naming the cut-off node and the cause", warns)
	}
	if infos := f.log.at(slog.LevelInfo); len(infos) != 1 || infos[0]["installed"] != "2" {
		t.Errorf("INFO records %v, want the summary", infos)
	}
}

// The workflow is one step, converge, of kind trust.converge, and its result
// is the ConvergeResult.
func TestConvergeWorkflow(t *testing.T) {
	f := newFixture(t)
	wf := f.svc.ConvergeWorkflow()
	if wf.Kind != ConvergeKind || ConvergeKind != "trust.converge" || len(wf.Steps) != 1 || wf.Steps[0].Name != "converge" || wf.Steps[0].Timeout <= 0 {
		t.Fatalf("workflow %+v", wf)
	}
	f.node(t, "n1", floor(t), "other", time.Now())
	f.agent(t, "n1", okAck("n1"))
	raw, err := wf.Steps[0].Do(&jobs.StepCtx{Ctx: f.ctx, NATS: f.nc, Log: func(string, string) {}})
	if err != nil {
		t.Fatal(err)
	}
	var res ConvergeResult
	if err := json.Unmarshal(raw, &res); err != nil || !slices.Equal(res.Redelivered, []string{"n1"}) {
		t.Errorf("result %s err %v", raw, err)
	}
	if f.svc.Fingerprint() != proto.TrustFingerprint(bundle) {
		t.Error("Fingerprint is not the bundle's")
	}
}
