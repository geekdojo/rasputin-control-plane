package storage

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Node-listener transfer from the run's side: which destination each node is
// handed, which node is refused, and what the feed says about it.

// ledgerLines is the job's feed: every Log line, level and message.
func (h *runHarness) ledgerLines(t *testing.T, jobID string) []proto.LogEventData {
	t.Helper()
	events, err := h.jobStore.ListEvents(context.Background(), jobID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var out []proto.LogEventData
	for _, ev := range events {
		if ev.Type != string(proto.JobLog) {
			continue
		}
		var d proto.LogEventData
		if err := json.Unmarshal(ev.Data, &d); err != nil {
			t.Fatalf("log event: %v", err)
		}
		out = append(out, d)
	}
	return out
}

// countLines counts the feed lines at level containing every sub.
func countLines(lines []proto.LogEventData, level string, sub ...string) int {
	n := 0
outer:
	for _, l := range lines {
		if l.Level != level {
			continue
		}
		for _, s := range sub {
			if !strings.Contains(l.Message, s) {
				continue outer
			}
		}
		n++
	}
	return n
}

// twoNodeApps puts two captured volumes on each of runNodeID and
// computeNodeID.
func twoNodeApps() ([]*apps.App, fakeTiles) {
	list := []*apps.App{
		testApp("app-vw", "vaultwarden", runNodeID, "vaultwarden"),
		testApp("app-pl", "paperless", runNodeID, "paperless"),
		testApp("app-im", "immich", computeNodeID, "immich"),
		testApp("app-nc", "nextcloud", computeNodeID, "nextcloud"),
	}
	tiles := fakeTiles{
		"vaultwarden": testTile("vaultwarden", vol("vaultwarden-data", tileschema.BackupCritical, tileschema.QuiesceStop)),
		"paperless":   testTile("paperless", vol("paperless-data", tileschema.BackupState, tileschema.QuiesceStop)),
		"immich":      testTile("immich", vol("immich-upload", tileschema.BackupState, tileschema.QuiesceStop)),
		"nextcloud":   testTile("nextcloud", vol("nextcloud-data", tileschema.BackupState, tileschema.QuiesceStop)),
	}
	return list, tiles
}

// TC-514-11: the fan-out routes each node by its own answer, asked once,
// and every node it routes is handed the node listener.
func TestFanOutRoutesEachNode(t *testing.T) {
	list, tiles := twoNodeApps()
	reader := &fakeRouteNodes{} // both nodes capable with an agent key
	r := runWithApps(t, runHarnessOpts{apps: list, tiles: tiles, computeAgent: true, routeNodes: reader})
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", r.job.Error)
	}
	auth := r.h.ingest.Authority()
	for _, a := range []*fakeBackupAgent{r.h.agent, r.h.compute} {
		recs := a.transferRecords()
		if len(recs) != 2 {
			t.Fatalf("%s: %d transfer commands, want 2", a.nodeID, len(recs))
		}
		for _, tr := range recs {
			if want := r.h.nodeURL + backupxfer.IngestPathPrefix; tr.cmd.Destination != want {
				t.Errorf("%s: destination %s, want %s", a.nodeID, tr.cmd.Destination, want)
			}
			g, err := auth.Verify(tr.cmd.Credential)
			if err != nil {
				t.Fatalf("%s: credential: %v", a.nodeID, err)
			}
			if g.NodeID != a.nodeID {
				t.Errorf("%s: credential issued to %s", a.nodeID, g.NodeID)
			}
			if !tr.ack.OK {
				t.Errorf("%s: %s did not land: %+v", a.nodeID, tr.cmd.Member, tr.ack)
			}
		}
	}
	for _, n := range []string{runNodeID, computeNodeID} {
		if c := reader.getCalls(n); c != 1 {
			t.Errorf("the router read %s %d times in the pass, want 1", n, c)
		}
		if c := countLines(r.h.ledgerLines(t, r.jobID), "info", "node "+n+" uploads over its node key"); c != 1 {
			t.Errorf("node-key route lines for %s: %d, want 1", n, c)
		}
	}
}

// TC-516-05: a mixed fleet. The capable, keyed node lands its volume over its
// key; the node whose agent predates key-bound transfer has its volume FAILED
// by name before anything is asked of it, so its app is never stopped.
func TestFanOutRefusesANodeThatPredatesKeyBoundTransfer(t *testing.T) {
	list := []*apps.App{
		testApp("app-vw", "vaultwarden", runNodeID, "vaultwarden"),
		testApp("app-im", "immich", computeNodeID, "immich"),
	}
	tiles := fakeTiles{
		"vaultwarden": testTile("vaultwarden", vol("vaultwarden-data", tileschema.BackupCritical, tileschema.QuiesceStop)),
		"immich":      testTile("immich", vol("immich-upload", tileschema.BackupState, tileschema.QuiesceStop)),
	}
	reader := (&fakeRouteNodes{}).predates(computeNodeID, "2026.09.5")
	logger, records := logkittest.New()
	r := runWithApps(t, runHarnessOpts{apps: list, tiles: tiles, computeAgent: true, routeNodes: reader, ingestLog: logger})

	// B: FAILED with the cause, and nothing sent to it.
	rec := r.record(t, "immich", "immich-upload")
	if rec.Captured || !rec.Failed || !strings.Contains(rec.Reason, "predates key-bound transfer") ||
		!strings.Contains(rec.Reason, computeNodeID) || !strings.Contains(rec.Reason, "update the node") {
		t.Errorf("immich-upload: %+v; want FAILED naming %s, the cause and the remedy", rec, computeNodeID)
	}
	r.h.compute.mu.Lock()
	staged := len(r.h.compute.staged)
	r.h.compute.mu.Unlock()
	if staged != 0 {
		t.Errorf("%d stage command(s) reached %s; its app must not be stopped", staged, computeNodeID)
	}
	if n := len(r.h.compute.transferRecords()); n != 0 {
		t.Errorf("%d transfer command(s) reached %s", n, computeNodeID)
	}

	// A: landed, presented by its own key.
	if rec := r.record(t, "vaultwarden", "vaultwarden-data"); !rec.Captured || rec.Failed {
		t.Errorf("vaultwarden-data did not land: %+v", rec)
	}
	landed := records.Matching(slog.LevelInfo, "landed")
	if len(landed) != 1 {
		t.Fatalf("landing records = %d, want 1:\n%s", len(landed), records.Text())
	}
	if v, _ := logkittest.Attr(landed[0], "presenting_node"); v != runNodeID {
		t.Errorf("presenting_node = %q, want %s", v, runNodeID)
	}

	// The feed: one error for B, one node-key line for A, no bearer line.
	lines := r.h.ledgerLines(t, r.jobID)
	if c := countLines(lines, "error", "node "+computeNodeID+" has no upload route", "predates key-bound transfer"); c != 1 {
		t.Errorf("no-route error lines for %s: %d, want 1", computeNodeID, c)
	}
	if c := countLines(lines, "info", "node "+runNodeID+" uploads over its node key"); c != 1 {
		t.Errorf("node-key route lines for %s: %d, want 1", runNodeID, c)
	}
	for _, l := range lines {
		if strings.Contains(strings.ToLower(l.Message), "bearer") {
			t.Errorf("a feed line mentions a bearer route: %s %q", l.Level, l.Message)
		}
	}
}

// TC-514-12 (and F-514-05): a node with no route has its volumes FAILED
// before anything is asked of it — no stage verb, so its apps are never
// stopped for a copy that could not be uploaded — and the other node's
// volumes land.
func TestFanOutFailsOnlyTheNodeWithNoRoute(t *testing.T) {
	list, tiles := twoNodeApps()
	reader := (&fakeRouteNodes{}).
		capable(runNodeID, agentKeys()).
		capable(computeNodeID, proto.NodeKeys{proto.NodeKeyCollector: "spki-collector"}) // capable, no agent key
	r := runWithApps(t, runHarnessOpts{apps: list, tiles: tiles, computeAgent: true, routeNodes: reader})

	for _, v := range []string{"immich-upload", "nextcloud-data"} {
		app := map[string]string{"immich-upload": "immich", "nextcloud-data": "nextcloud"}[v]
		rec := r.record(t, app, v)
		if rec.Captured || !rec.Failed || !strings.Contains(rec.Reason, computeNodeID) || !strings.Contains(rec.Reason, "no registered agent key") {
			t.Errorf("%s: %+v; want FAILED naming %s and the missing agent key", v, rec, computeNodeID)
		}
	}
	r.h.compute.mu.Lock()
	staged := len(r.h.compute.staged)
	r.h.compute.mu.Unlock()
	if staged != 0 {
		t.Errorf("%d stage command(s) reached %s, which has no route; its apps must not be stopped", staged, computeNodeID)
	}
	if n := len(r.h.compute.transferRecords()); n != 0 {
		t.Errorf("%d transfer command(s) reached %s", n, computeNodeID)
	}
	for _, v := range []string{"vaultwarden-data", "paperless-data"} {
		app := map[string]string{"vaultwarden-data": "vaultwarden", "paperless-data": "paperless"}[v]
		if rec := r.record(t, app, v); !rec.Captured || rec.Failed {
			t.Errorf("%s did not land: %+v", v, rec)
		}
	}
	if c := reader.getCalls(computeNodeID); c != 1 {
		t.Errorf("the router read %s %d times, want once for the pass", computeNodeID, c)
	}
	if c := countLines(r.h.ledgerLines(t, r.jobID), "error", "node "+computeNodeID+" has no upload route"); c != 1 {
		t.Errorf("no-route error lines for %s: %d, want 1", computeNodeID, c)
	}
}

// TC-514-13: step 1 refuses a run that has no router.
func TestRunRefusesWithoutATransferRouter(t *testing.T) {
	list, tiles := twoNodeApps()
	r := runWithApps(t, runHarnessOpts{apps: list, tiles: tiles, noRouter: true})
	if r.job.Status != jobs.StatusFailed || !strings.Contains(r.job.Error, "cannot route uploads") {
		t.Fatalf("job = %s %q", r.job.Status, r.job.Error)
	}
	r.h.agent.mu.Lock()
	staged, preflights := len(r.h.agent.staged), len(r.h.agent.preflightCmds)
	r.h.agent.mu.Unlock()
	if staged != 0 || preflights != 0 {
		t.Errorf("after the step-1 refusal: %d stage and %d preflight command(s) were sent", staged, preflights)
	}
}

// TC-514-14: an app restore takes its node's route, and a node with none is
// refused before any restore verb is sent.
// TC-516-06: that includes a node whose agent predates key-bound transfer and
// an api with no node listener: refused with "nothing was touched" and the
// cause, no session armed, no stop, restore or fetch sent.
func TestRestoreAppUsesTheRoute(t *testing.T) {
	t.Run("capable and keyed: the node listener", func(t *testing.T) {
		c := newRestoreCase(t, runHarnessOpts{})
		c.corrupt(t)
		j, jobID := c.restore(t, c.spec())
		if j.Status != jobs.StatusSucceeded {
			t.Fatalf("restore job %s: %s", j.Status, j.Error)
		}
		calls := c.h.agent.restoreCalls()
		if len(calls) != 1 || !calls[0].ack.OK {
			t.Fatalf("restore calls: %+v", calls)
		}
		g, err := c.h.ingest.Authority().Verify(calls[0].cmd.Credential)
		if err != nil {
			t.Fatalf("credential: %v", err)
		}
		if want := c.h.nodeURL + backupxfer.EgressPathPrefix; calls[0].cmd.Source != want || g.NodeID != runNodeID {
			t.Fatalf("source %s, grant node %s; want %s, %s", calls[0].cmd.Source, g.NodeID, want, runNodeID)
		}
		if n := countLines(c.h.ledgerLines(t, jobID), "info", "node "+runNodeID+" fetches the restore stream over its node key"); n != 1 {
			t.Errorf("node-key fetch lines: %d, want 1", n)
		}
	})
	for _, tc := range []struct {
		name    string
		breakIt func(*runHarness, *fakeRouteNodes)
		want    []string
	}{
		{"capable with no agent key", func(_ *runHarness, f *fakeRouteNodes) {
			f.capable(runNodeID, proto.NodeKeys{proto.NodeKeyCollector: "spki-collector"})
		}, []string{"node " + runNodeID, "no registered agent key"}},
		{"absent", func(_ *runHarness, f *fakeRouteNodes) {
			f.mu.Lock()
			f.absent = map[string]bool{runNodeID: true}
			f.mu.Unlock()
		}, []string{"node " + runNodeID, "not in inventory"}},
		{"agent predates key-bound transfer", func(_ *runHarness, f *fakeRouteNodes) {
			f.predates(runNodeID, "2026.09.5")
		}, []string{"node " + runNodeID, "2026.09.5", "predates key-bound transfer", "update the node"}},
		{"api with no node listener", func(h *runHarness, f *fakeRouteNodes) {
			none, err := NewTransferRouter(f, "")
			if err != nil {
				panic(err)
			}
			*h.router = *none // the router the restore was wired with
		}, []string{"node " + runNodeID, "RASPUTIN_HTTPS_ADDR"}},
	} {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			reader := &fakeRouteNodes{}
			c := newRestoreCase(t, runHarnessOpts{routeNodes: reader}) // backed up over the node key
			tc.breakIt(c.h, reader)
			j, jobID := c.restore(t, c.spec())
			if j.Status != jobs.StatusFailed {
				t.Fatalf("job: %s %s", j.Status, j.Error)
			}
			for _, sub := range append([]string{"nothing was touched"}, tc.want...) {
				if !strings.Contains(j.Error, sub) {
					t.Errorf("error %q lacks %q", j.Error, sub)
				}
			}
			if n := len(c.h.agent.restoreCalls()); n != 0 {
				t.Fatalf("%d restore verb(s) were sent", n)
			}
			if stops, starts := c.h.agent.quiesceCounts(); stops != 0 || starts != 0 {
				t.Errorf("stops=%d starts=%d; the app must not be touched", stops, starts)
			}
			if _, armed := c.h.sessions.Lookup(jobID, c.genID, proto.BackupMemberPath("vaultwarden", "vaultwarden-data")); armed {
				t.Error("a restore session was armed for the refused job")
			}
		})
	}
}
