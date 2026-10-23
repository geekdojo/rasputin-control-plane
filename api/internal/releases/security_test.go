package releases

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// stubSource is a LatestFor whose answer a test changes between refreshes.
type stubSource struct {
	mu    sync.Mutex
	info  *ReleaseInfo
	err   error
	calls int
}

func (s *stubSource) LatestFor(context.Context, Component, string) (*ReleaseInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.info, s.err
}

func (s *stubSource) set(info *ReleaseInfo, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.info, s.err = info, err
}

func (s *stubSource) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// releaseJSON is a release whose manifest is decoded from raw JSON, so "no
// field" and `"securityFloor": ""` are what a real manifest would carry.
func releaseJSON(t *testing.T, version, manifest string) *ReleaseInfo {
	t.Helper()
	info := &ReleaseInfo{Component: "os", Version: version, Channel: ChannelStable}
	if err := json.Unmarshal([]byte(manifest), &info.Manifest); err != nil {
		t.Fatal(err)
	}
	return info
}

// release is a release on version declaring floor.
func release(version, floor string) *ReleaseInfo {
	return &ReleaseInfo{Component: "os", Version: version, Channel: ChannelStable,
		Manifest: Manifest{Version: version, Channel: ChannelStable, SecurityFloor: floor}}
}

// fakeNodes is a mutable inventory.
type fakeNodes struct {
	mu    sync.Mutex
	nodes []*proto.Node
	err   error
}

func (f *fakeNodes) List(context.Context) ([]*proto.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*proto.Node, 0, len(f.nodes))
	for _, n := range f.nodes {
		c := *n
		out = append(out, &c)
	}
	return out, f.err
}

func (f *fakeNodes) setVersion(id, version string, confirmed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.nodes {
		if n.ID == id {
			n.ImageVersion = version
			n.ImageVersionConfirmedAt = confirmedAt(confirmed)
		}
	}
}

func confirmedAt(confirmed bool) *time.Time {
	if !confirmed {
		return nil
	}
	t := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return &t
}

func osNode(id string, role proto.NodeRole, version string, confirmed bool) *proto.Node {
	return &proto.Node{ID: id, Role: role, ImageVersion: version, ImageVersionConfirmedAt: confirmedAt(confirmed)}
}

// clock is an injected Now a test advances.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type watchEnv struct {
	w     *SecurityWatch
	src   *stubSource
	nodes *fakeNodes
	rec   *logkittest.Recorder
	clk   *clock
}

func newWatchEnv(t *testing.T, nodes ...*proto.Node) *watchEnv {
	t.Helper()
	e := &watchEnv{src: &stubSource{}, nodes: &fakeNodes{nodes: nodes},
		clk: &clock{t: time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)}}
	var log *slog.Logger
	log, e.rec = logkittest.New()
	w, err := NewSecurityWatch(SecurityDeps{Source: e.src, Nodes: e.nodes, Channel: ChannelStable, Log: log, Now: e.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	e.w = w
	return e
}

// step runs the workflow's one step as the runner would, for job id.
func (e *watchEnv) step(jobID string) error {
	_, err := e.w.Workflow().Steps[0].Do(&jobs.StepCtx{Ctx: context.Background(), JobID: jobID})
	return err
}

func (e *watchEnv) alerts(t *testing.T) []proto.Alert {
	t.Helper()
	got, err := e.w.Alerts(context.Background(), e.clk.now())
	if err != nil {
		t.Fatalf("Alerts: %v", err)
	}
	return got
}

func attr(t *testing.T, rec slog.Record, key string) string {
	t.Helper()
	v, ok := logkittest.Attr(rec, key)
	if !ok {
		t.Errorf("record %q has no %s field", rec.Message, key)
	}
	return v
}

const (
	sentenceLagging     = "These nodes run an older version:"
	sentenceUnconfirmed = "These nodes' versions could not be confirmed after their last update:"
)

// TC-772-01: a floor above node a's confirmed version raises one crit alert
// that names the release read (not the floor) and node a, not node b, and
// whose Since is the time this floor was first seen.
func TestSecurityWatch_RaisesForANodeBelowTheFloor(t *testing.T) {
	e := newWatchEnv(t,
		osNode("a", proto.RoleCompute, "2026.10.1", true),
		osNode("b", proto.RoleControlPlane, "2026.10.2", true))
	e.src.set(release("2026.10.3", "2026.10.2"), nil)
	first := e.clk.now()
	if err := e.step("job-1"); err != nil {
		t.Fatalf("step: %v", err)
	}

	got := e.alerts(t)
	if len(got) != 1 {
		t.Fatalf("alerts = %+v, want exactly one", got)
	}
	a := got[0]
	if a.ID != "security-update:os" || a.Severity != proto.AlertCrit || a.Source != proto.AlertSourceSecurity {
		t.Errorf("alert = %s %s %s, want security-update:os crit security", a.ID, a.Severity, a.Source)
	}
	if a.Title != "A security update is available for Rasputin OS" {
		t.Errorf("title = %q", a.Title)
	}
	if !strings.HasPrefix(a.Detail, "Rasputin OS 2026.10.3 includes a security fix.") {
		t.Errorf("detail %q does not start with the release that was read", a.Detail)
	}
	if !strings.Contains(a.Detail, "a (2026.10.1)") || strings.Contains(a.Detail, "b (") {
		t.Errorf("detail %q must name a and not b", a.Detail)
	}
	if !a.Since.Equal(first) {
		t.Errorf("since = %v, want the first refresh's %v", a.Since, first)
	}

	e.clk.advance(24 * time.Hour)
	if err := e.step("job-2"); err != nil {
		t.Fatalf("second step: %v", err)
	}
	if got := e.alerts(t); len(got) != 1 || !got[0].Since.Equal(first) {
		t.Errorf("after a refresh with the same floor, alerts = %+v; want Since still %v", got, first)
	}
}

// TC-772-02: once node a reports a confirmed version at the floor, the next
// alerts read clears the alert with no second manifest read.
func TestSecurityWatch_ClearsOnInstallWithoutARefresh(t *testing.T) {
	e := newWatchEnv(t,
		osNode("a", proto.RoleCompute, "2026.10.1", true),
		osNode("b", proto.RoleControlPlane, "2026.10.2", true))
	e.src.set(release("2026.10.3", "2026.10.2"), nil)
	if err := e.step("job-1"); err != nil {
		t.Fatal(err)
	}
	if len(e.alerts(t)) != 1 {
		t.Fatal("precondition: the alert is raised")
	}

	e.nodes.setVersion("a", "2026.10.2", true)
	if got := e.alerts(t); len(got) != 0 {
		t.Errorf("alerts = %+v, want none once every node is at the floor", got)
	}
	if n := e.src.callCount(); n != 1 {
		t.Errorf("LatestFor calls = %d, want 1: clearing must not read the manifest again", n)
	}
}

// TC-772-03: a manifest with no securityFloor, or an empty one, raises
// nothing even with a lagging node, and the step succeeds.
func TestSecurityWatch_NoMarkerRaisesNothing(t *testing.T) {
	for name, manifest := range map[string]string{
		"field absent": `{"version":"2026.10.3","channel":"stable","artifacts":[]}`,
		"field empty":  `{"version":"2026.10.3","channel":"stable","artifacts":[],"securityFloor":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newWatchEnv(t, osNode("a", proto.RoleCompute, "2026.01.1", true))
			e.src.set(releaseJSON(t, "2026.10.3", manifest), nil)
			if err := e.step("job-1"); err != nil {
				t.Errorf("step: %v, want success", err)
			}
			if got := e.alerts(t); len(got) != 0 {
				t.Errorf("alerts = %+v, want none", got)
			}
		})
	}
}

// TC-772-04: a newer manifest without the field drops the floor and the
// alert, with one INFO carrying the job's id; a later different floor logs
// another INFO with the same fields.
func TestSecurityWatch_DroppedOrChangedFloor(t *testing.T) {
	e := newWatchEnv(t, osNode("a", proto.RoleCompute, "2026.10.1", true))
	e.src.set(release("2026.10.3", "2026.10.2"), nil)
	if err := e.step("job-1"); err != nil {
		t.Fatal(err)
	}
	if len(e.alerts(t)) != 1 {
		t.Fatal("precondition: the alert is raised")
	}
	infos := func() []slog.Record { return e.rec.Matching(slog.LevelInfo, "release security floor changed") }
	if n := len(infos()); n != 1 {
		t.Fatalf("INFO records after the floor was set = %d, want 1", n)
	}

	e.src.set(releaseJSON(t, "2026.10.4", `{"version":"2026.10.4","channel":"stable","artifacts":[]}`), nil)
	if err := e.step("job-2"); err != nil {
		t.Fatalf("step: %v", err)
	}
	if got := e.alerts(t); len(got) != 0 {
		t.Errorf("alerts = %+v, want none once the floor is dropped", got)
	}
	recs := infos()
	if len(recs) != 2 {
		t.Fatalf("INFO records = %d, want one more for the drop", len(recs))
	}
	drop := recs[1]
	if attr(t, drop, "component") != "os" || attr(t, drop, "channel") != ChannelStable ||
		attr(t, drop, "floor") != "" || attr(t, drop, "job_id") != "job-2" {
		t.Errorf("drop record = %s", e.rec.Text())
	}
	attr(t, drop, "release")

	e.src.set(release("2026.10.5", "2026.10.5"), nil)
	if err := e.step("job-3"); err != nil {
		t.Fatal(err)
	}
	recs = infos()
	if len(recs) != 3 {
		t.Fatalf("INFO records = %d, want one more for the new floor", len(recs))
	}
	set := recs[2]
	if attr(t, set, "component") != "os" || attr(t, set, "channel") != ChannelStable || attr(t, set, "release") != "2026.10.5" ||
		attr(t, set, "floor") != "2026.10.5" || attr(t, set, "job_id") != "job-3" {
		t.Errorf("change record = %s", e.rec.Text())
	}
}

// TC-772-05: no release on the channel clears the floor, and the step
// succeeds.
func TestSecurityWatch_NoReleaseClearsTheFloor(t *testing.T) {
	e := newWatchEnv(t, osNode("a", proto.RoleCompute, "2026.10.1", true))
	e.src.set(release("2026.10.3", "2026.10.2"), nil)
	if err := e.step("job-1"); err != nil {
		t.Fatal(err)
	}
	e.src.set(nil, nil)
	if err := e.step("job-2"); err != nil {
		t.Errorf("step: %v, want success", err)
	}
	if got := e.alerts(t); len(got) != 0 {
		t.Errorf("alerts = %+v, want none", got)
	}
}

// failureCases are the read failures TC-772-06 and TC-772-11 run.
func failureCases() map[string]error {
	return map[string]error{
		"network": fmt.Errorf("Get \"https://api.github.com/repos/geekdojo/rasputin-os/releases\": %w",
			&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}),
		"403":      &httpError{status: 403, url: "https://api.github.com/repos/geekdojo/rasputin-os/releases", body: "API rate limit exceeded"},
		"429":      &httpError{status: 429, url: "https://api.github.com/repos/geekdojo/rasputin-os/releases", body: "slow down"},
		"unsigned": fmt.Errorf("%w: os 2026.10.4 publishes no manifest.json.sig, and every release from 2026.08.4 onward must", ErrManifestUnsigned),
	}
}

// TC-772-06: a failed read keeps the alert, its Since and its release; the
// step's error is friendlyFetchError's host-free text; one WARN per failure
// carries the job's id.
func TestSecurityWatch_FailedReadKeepsTheAlert(t *testing.T) {
	e := newWatchEnv(t, osNode("a", proto.RoleCompute, "2026.10.1", true))
	e.src.set(release("2026.10.3", "2026.10.2"), nil)
	if err := e.step("job-1"); err != nil {
		t.Fatal(err)
	}
	before := e.alerts(t)
	if len(before) != 1 {
		t.Fatal("precondition: the alert is raised")
	}

	n := 0
	for name, cause := range failureCases() {
		t.Run(name, func(t *testing.T) {
			n++
			e.clk.advance(time.Hour)
			e.src.set(nil, cause)
			jobID := "job-fail-" + name
			err := e.step(jobID)
			if err == nil {
				t.Fatal("step succeeded on a failed read")
			}
			if err.Error() != friendlyFetchError(cause) {
				t.Errorf("step error = %q, want %q", err, friendlyFetchError(cause))
			}
			low := strings.ToLower(err.Error())
			for _, bad := range []string{"http", "github", "api.", "://", "rasputin-os"} {
				if strings.Contains(low, bad) {
					t.Errorf("step error %q contains %q", err, bad)
				}
			}
			got := e.alerts(t)
			if len(got) != 1 || got[0].Detail != before[0].Detail || !got[0].Since.Equal(before[0].Since) {
				t.Errorf("alerts = %+v, want the alert unchanged: %+v", got, before)
			}
			warns := e.rec.Matching(slog.LevelWarn, "release security check failed; keeping the last known floor")
			if len(warns) != n {
				t.Fatalf("WARN records = %d, want %d", len(warns), n)
			}
			w := warns[n-1]
			if attr(t, w, "component") != "os" || attr(t, w, "channel") != ChannelStable ||
				attr(t, w, "err") != cause.Error() || attr(t, w, "job_id") != jobID {
				t.Errorf("WARN = %s", e.rec.Text())
			}
		})
	}
}

// TC-772-07: a floor that is not a version keeps the previous floor and alert,
// fails the step with the exact sentence, and logs one WARN with the job id.
func TestSecurityWatch_UnreadableFloorKeepsTheLastOne(t *testing.T) {
	e := newWatchEnv(t, osNode("a", proto.RoleCompute, "2026.10.1", true))
	e.src.set(release("2026.10.3", "2026.10.2"), nil)
	if err := e.step("job-1"); err != nil {
		t.Fatal(err)
	}
	before := e.alerts(t)

	e.src.set(release("2026.10.4", "not-a-version"), nil)
	err := e.step("job-2")
	if err == nil || err.Error() != "The newest release declares a security floor this control plane cannot read." {
		t.Fatalf("step error = %v", err)
	}
	if got := e.alerts(t); len(got) != 1 || got[0].Detail != before[0].Detail || !got[0].Since.Equal(before[0].Since) {
		t.Errorf("alerts = %+v, want the previous alert %+v", got, before)
	}
	warns := e.rec.Matching(slog.LevelWarn, "release security floor unreadable; keeping the last known floor")
	if len(warns) != 1 {
		t.Fatalf("WARN records = %d, want 1", len(warns))
	}
	w := warns[0]
	if attr(t, w, "component") != "os" || attr(t, w, "channel") != ChannelStable || attr(t, w, "release") != "2026.10.4" ||
		attr(t, w, "floor") != "not-a-version" || attr(t, w, "job_id") != "job-2" {
		t.Errorf("WARN = %s", e.rec.Text())
	}
}

// TC-772-08: with a floor, an unconfirmed node at the floor raises the alert
// with only the unconfirmed sentence; a lagging and an unconfirmed node give
// both sentences. Every Detail ends with the instruction.
func TestSecurityWatch_UnconfirmedNodeWithAFloor(t *testing.T) {
	t.Run("unconfirmed only", func(t *testing.T) {
		e := newWatchEnv(t, osNode("c", proto.RoleStorage, "2026.10.2", false))
		e.src.set(release("2026.10.3", "2026.10.2"), nil)
		if err := e.step("job-1"); err != nil {
			t.Fatal(err)
		}
		got := e.alerts(t)
		if len(got) != 1 || got[0].Severity != proto.AlertCrit {
			t.Fatalf("alerts = %+v, want one crit", got)
		}
		d := got[0].Detail
		if !strings.Contains(d, sentenceUnconfirmed+" c (2026.10.2).") {
			t.Errorf("detail %q lacks the unconfirmed sentence naming c", d)
		}
		if strings.Contains(d, sentenceLagging) {
			t.Errorf("detail %q carries the older-version sentence with no lagging node", d)
		}
		if !strings.HasSuffix(d, "Open Updates, download and stage the latest release, and deploy it.") {
			t.Errorf("detail %q does not end with the instruction", d)
		}
	})
	t.Run("lagging and unconfirmed", func(t *testing.T) {
		e := newWatchEnv(t,
			osNode("a", proto.RoleCompute, "2026.10.1", true),
			osNode("c", proto.RoleStorage, "2026.10.2", false))
		e.src.set(release("2026.10.3", "2026.10.2"), nil)
		if err := e.step("job-1"); err != nil {
			t.Fatal(err)
		}
		got := e.alerts(t)
		if len(got) != 1 {
			t.Fatalf("alerts = %+v, want one", got)
		}
		d := got[0].Detail
		if !strings.Contains(d, sentenceLagging+" a (2026.10.1).") || !strings.Contains(d, sentenceUnconfirmed+" c (2026.10.2).") {
			t.Errorf("detail %q lacks one of the two sentences", d)
		}
		if !strings.HasSuffix(d, "Open Updates, download and stage the latest release, and deploy it.") {
			t.Errorf("detail %q does not end with the instruction", d)
		}
	})
}

// TC-772-09: no floor means no alert, whatever the nodes report: never
// refreshed (the state right after an upgrade), refreshed to a manifest with
// no field, and refreshed to no release.
func TestSecurityWatch_NoFloorNoAlert(t *testing.T) {
	nodes := func() []*proto.Node {
		return []*proto.Node{
			osNode("a", proto.RoleCompute, "2026.01.1", true),
			osNode("c", proto.RoleStorage, "2026.01.1", false),
		}
	}
	states := map[string]func(e *watchEnv) error{
		"never refreshed": func(*watchEnv) error { return nil },
		"no field": func(e *watchEnv) error {
			e.src.set(releaseJSON(t, "2026.10.3", `{"version":"2026.10.3","channel":"stable","artifacts":[]}`), nil)
			return e.step("job-1")
		},
		"no release": func(e *watchEnv) error {
			e.src.set(nil, nil)
			return e.step("job-1")
		},
	}
	for name, arrange := range states {
		t.Run(name, func(t *testing.T) {
			e := newWatchEnv(t, nodes()...)
			if err := arrange(e); err != nil {
				t.Fatal(err)
			}
			got, err := e.w.Alerts(context.Background(), e.clk.now())
			if err != nil || len(got) != 0 {
				t.Errorf("Alerts = %+v, %v; want none and no error", got, err)
			}
		})
	}
}

// TC-772-10: a firewall node below the floor is never named, and raises no
// alert of its own.
func TestSecurityWatch_FirewallNodesAreNotWatched(t *testing.T) {
	t.Run("alongside a lagging OS node", func(t *testing.T) {
		e := newWatchEnv(t,
			osNode("a", proto.RoleCompute, "2026.10.1", true),
			osNode("fw", proto.RoleFirewall, "2026.01.1", false))
		e.src.set(release("2026.10.3", "2026.10.2"), nil)
		if err := e.step("job-1"); err != nil {
			t.Fatal(err)
		}
		got := e.alerts(t)
		if len(got) != 1 {
			t.Fatalf("alerts = %+v, want at most the one OS alert", got)
		}
		if strings.Contains(got[0].Detail, "fw (") {
			t.Errorf("detail %q names the firewall node", got[0].Detail)
		}
	})
	t.Run("only a firewall node lags", func(t *testing.T) {
		e := newWatchEnv(t,
			osNode("b", proto.RoleControlPlane, "2026.10.2", true),
			osNode("fw", proto.RoleFirewall, "2026.01.1", false))
		e.src.set(release("2026.10.3", "2026.10.2"), nil)
		if err := e.step("job-1"); err != nil {
			t.Fatal(err)
		}
		if got := e.alerts(t); len(got) != 0 {
			t.Errorf("alerts = %+v, want none for a firewall-only lag", got)
		}
	})
}

// vendorTerms are names the operator-facing copy must never carry
// (design/principles.md, vendor-neutral copy).
var vendorTerms = []string{"OpenBao", "Vault", "OpenWrt", "UCI", "LuCI", "Headscale", "Docker", "Compose", "RAUC", "VictoriaMetrics", "GitHub"}

// TC-772-11: every rendered Title and Detail, the unreadable-floor error and
// each failure-path step error are free of vendor names, and every sentence
// ends with a full stop.
func TestSecurityWatch_CopyIsVendorNeutral(t *testing.T) {
	fixtureIDs := []string{"a", "c"}
	for _, id := range fixtureIDs {
		for _, term := range vendorTerms {
			if strings.Contains(strings.ToLower(id), strings.ToLower(term)) {
				t.Fatalf("node-id fixture %q contains %q", id, term)
			}
		}
	}
	shapes := map[string][]*proto.Node{
		"lagging":     {osNode("a", proto.RoleCompute, "2026.10.1", true)},
		"unconfirmed": {osNode("c", proto.RoleStorage, "2026.10.2", false)},
		"combined":    {osNode("a", proto.RoleCompute, "2026.10.1", true), osNode("c", proto.RoleStorage, "2026.10.2", false)},
	}
	type text struct{ name, s string }
	var texts []text
	var details []text
	for name, nodes := range shapes {
		e := newWatchEnv(t, nodes...)
		e.src.set(release("2026.10.3", "2026.10.2"), nil)
		if err := e.step("job-1"); err != nil {
			t.Fatal(err)
		}
		got := e.alerts(t)
		if len(got) != 1 {
			t.Fatalf("%s: alerts = %+v", name, got)
		}
		texts = append(texts, text{name + " title", got[0].Title}, text{name + " detail", got[0].Detail})
		details = append(details, text{name + " detail", got[0].Detail})
	}

	e := newWatchEnv(t, osNode("a", proto.RoleCompute, "2026.10.1", true))
	e.src.set(release("2026.10.4", "not-a-version"), nil)
	errs := []text{}
	if err := e.step("job-1"); err != nil {
		errs = append(errs, text{"unreadable floor", err.Error()})
	}
	for name, cause := range failureCases() {
		e.src.set(nil, cause)
		if err := e.step("job-" + name); err != nil {
			errs = append(errs, text{"failure " + name, err.Error()})
		}
	}
	if len(errs) != 1+len(failureCases()) {
		t.Fatalf("collected %d step errors, want %d", len(errs), 1+len(failureCases()))
	}
	texts = append(texts, errs...)

	for _, tx := range texts {
		low := strings.ToLower(tx.s)
		for _, term := range vendorTerms {
			if strings.Contains(low, strings.ToLower(term)) {
				t.Errorf("%s %q contains %q", tx.name, tx.s, term)
			}
		}
	}
	for _, tx := range errs {
		if !strings.HasSuffix(tx.s, ".") {
			t.Errorf("%s %q does not end with a full stop", tx.name, tx.s)
		}
	}
	// Each Detail sentence starts with one of these; the text before every
	// sentence but the first must end with a full stop, and so must the last.
	starts := []string{"Rasputin OS ", sentenceLagging, sentenceUnconfirmed, "Open Updates"}
	for _, d := range details {
		if !strings.HasSuffix(d.s, ".") {
			t.Errorf("%s %q does not end with a full stop", d.name, d.s)
		}
		for _, st := range starts {
			i := strings.Index(d.s, st)
			if i > 0 && !strings.HasSuffix(d.s[:i], ". ") {
				t.Errorf("%s: the sentence before %q does not end with a full stop: %q", d.name, st, d.s)
			}
		}
	}
}

// TC-772-12: through the real release source and the real verifier, a
// signed manifest's floor raises the alert; with the signature omitted, or
// with the manifest's bytes no longer the ones signed, the step fails, no
// floor is set and no alert is raised.
func TestSecurityWatch_SignedEndToEnd(t *testing.T) {
	const tag = "2026.10.2"
	manifest, err := os.ReadFile("testdata/security-floor-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile("testdata/security-floor-manifest.json.sig")
	if err != nil {
		t.Fatal(err)
	}
	verifier := realVerifier{root: "testdata/security-floor-root-ca.pem"}
	comp, _ := ComponentByID("os")
	if !SignedManifestRequired(comp, tag) {
		t.Fatalf("precondition: %s must be at or above the signing floor %s", tag, comp.SignedManifestFrom)
	}

	watch := func(t *testing.T, g *ghStub) *watchEnv {
		t.Helper()
		e := newWatchEnv(t, osNode("a", proto.RoleCompute, "2026.10.1", true))
		log, rec := logkittest.New()
		w, err := NewSecurityWatch(SecurityDeps{Source: NewGithubPublicSource(g.srv.URL, verifier), Nodes: e.nodes,
			Channel: ChannelStable, Log: log, Now: e.clk.now})
		if err != nil {
			t.Fatal(err)
		}
		e.w, e.rec = w, rec
		return e
	}

	t.Run("signed", func(t *testing.T) {
		e := watch(t, newGHStub(t, tag, manifest, sig))
		if err := e.step("job-1"); err != nil {
			t.Fatalf("step: %v", err)
		}
		got := e.alerts(t)
		if len(got) != 1 || !strings.HasPrefix(got[0].Detail, "Rasputin OS 2026.10.2 includes a security fix.") {
			t.Errorf("alerts = %+v, want the security alert", got)
		}
	})
	t.Run("signature omitted", func(t *testing.T) {
		g := newGHStub(t, tag, manifest, nil)
		g.omitSigAsset = true
		e := watch(t, g)
		err := e.step("job-1")
		if err == nil || !strings.Contains(err.Error(), "no signature on its manifest") {
			t.Errorf("step error = %v, want the unsigned-manifest text", err)
		}
		if got := e.alerts(t); len(got) != 0 {
			t.Errorf("alerts = %+v, want none: an unsigned manifest must set no floor", got)
		}
	})
	t.Run("bad signature", func(t *testing.T) {
		tampered := bytes.Replace(manifest, []byte(`"securityFloor":"2026.10.2"`), []byte(`"securityFloor":"2026.10.1"`), 1)
		if bytes.Equal(tampered, manifest) {
			t.Fatal("precondition: the fixture carries the floor this test rewrites")
		}
		e := watch(t, newGHStub(t, tag, tampered, sig))
		err := e.step("job-1")
		if err == nil {
			t.Fatal("step succeeded on a manifest its signature does not cover")
		}
		// A signature that does not verify has no class of its own in
		// friendlyFetchError, so it gets the generic, host-free sentence.
		if err.Error() != "Couldn't check for updates. Try again shortly." {
			t.Errorf("step error = %q, want the generic friendly text", err)
		}
		if got := e.alerts(t); len(got) != 0 {
			t.Errorf("alerts = %+v, want none: unverified bytes must set no floor", got)
		}
	})
}

// TC-772-13: the constructor refuses each nil collaborator and an empty or
// unknown channel, naming the field, and returns no watch.
func TestNewSecurityWatch_RefusesBadDeps(t *testing.T) {
	log, _ := logkittest.New()
	good := func() SecurityDeps {
		return SecurityDeps{Source: &stubSource{}, Nodes: &fakeNodes{}, Channel: ChannelDev, Log: log, Now: time.Now}
	}
	cases := map[string]struct {
		mut  func(*SecurityDeps)
		want string
	}{
		"Source nil":    {func(d *SecurityDeps) { d.Source = nil }, "Source"},
		"Nodes nil":     {func(d *SecurityDeps) { d.Nodes = nil }, "Nodes"},
		"Log nil":       {func(d *SecurityDeps) { d.Log = nil }, "Log"},
		"Now nil":       {func(d *SecurityDeps) { d.Now = nil }, "Now"},
		"Channel empty": {func(d *SecurityDeps) { d.Channel = "" }, "Channel"},
		"Channel beta":  {func(d *SecurityDeps) { d.Channel = "beta" }, "Channel"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := good()
			c.mut(&d)
			w, err := NewSecurityWatch(d)
			if err == nil || w != nil {
				t.Fatalf("NewSecurityWatch = %v, %v; want nil and an error", w, err)
			}
			if !strings.Contains(err.Error(), "SecurityDeps."+c.want) {
				t.Errorf("error %q does not name %s", err, c.want)
			}
		})
	}
	if w, err := NewSecurityWatch(good()); err != nil || w == nil {
		t.Errorf("good deps: %v, %v", w, err)
	}
}

// TC-772-15: with a floor known, an inventory failure fails Alerts with the
// watch's prefix, wrapping the cause.
func TestSecurityWatch_InventoryFailureFailsAlerts(t *testing.T) {
	e := newWatchEnv(t)
	e.src.set(release("2026.10.3", "2026.10.2"), nil)
	if err := e.step("job-1"); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("database is locked")
	e.nodes.err = cause
	got, err := e.w.Alerts(context.Background(), e.clk.now())
	if got != nil || !errors.Is(err, cause) {
		t.Fatalf("Alerts = %v, %v; want nil and an error wrapping the cause", got, err)
	}
	if !strings.Contains(err.Error(), "releases: security alerts: list nodes") {
		t.Errorf("error %q lacks the prefix", err)
	}
}

// TC-772-17: Refresh and Alerts run concurrently (under -race in CI), and
// every Alerts result is the old floor's alert or the new one's.
func TestSecurityWatch_ConcurrentRefreshAndAlerts(t *testing.T) {
	e := newWatchEnv(t, osNode("a", proto.RoleCompute, "2026.10.1", true))
	old, next := release("2026.10.2", "2026.10.2"), release("2026.10.5", "2026.10.5")
	e.src.set(old, nil)
	if err := e.step("job-0"); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, r := range []string{"2026.10.2", "2026.10.5"} {
		want["Rasputin OS "+r+" includes a security fix. "+sentenceLagging+" a (2026.10.1). "+securityAlertNext] = true
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if i%2 == 0 {
				e.src.set(next, nil)
			} else {
				e.src.set(old, nil)
			}
			if err := e.w.Refresh(context.Background()); err != nil {
				t.Errorf("Refresh: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			got, err := e.w.Alerts(context.Background(), time.Time{})
			if err != nil {
				t.Errorf("Alerts: %v", err)
				return
			}
			if len(got) != 1 || !want[got[0].Detail] {
				t.Errorf("Alerts = %+v, want the old floor's alert or the new one's", got)
				return
			}
		}
	}()
	wg.Wait()
}
