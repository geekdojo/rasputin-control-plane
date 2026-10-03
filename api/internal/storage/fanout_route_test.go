package storage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Key-bound transfer from the run's side: which route each node is handed,
// what the credential says, and what the feed says about it.

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

// TC-514-11: the fan-out routes each node by its own answer, asked once.
func TestFanOutRoutesEachNode(t *testing.T) {
	list, tiles := twoNodeApps()
	reader := (&fakeRouteNodes{}).capable(runNodeID, agentKeys()) // computeNodeID predates the capability
	r := runWithApps(t, runHarnessOpts{apps: list, tiles: tiles, computeAgent: true, routeNodes: reader})
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", r.job.Error)
	}
	auth := r.h.ingest.Authority()
	check := func(a *fakeBackupAgent, wantDest string, wantBound bool) {
		t.Helper()
		recs := a.transferRecords()
		if len(recs) != 2 {
			t.Fatalf("%s: %d transfer commands, want 2", a.nodeID, len(recs))
		}
		for _, tr := range recs {
			if tr.cmd.Destination != wantDest {
				t.Errorf("%s: destination %s, want %s", a.nodeID, tr.cmd.Destination, wantDest)
			}
			g, err := auth.Verify(tr.cmd.Credential)
			if err != nil {
				t.Fatalf("%s: credential: %v", a.nodeID, err)
			}
			if g.KeyBound != wantBound {
				t.Errorf("%s: credential KeyBound = %v, want %v", a.nodeID, g.KeyBound, wantBound)
			}
			if !tr.ack.OK {
				t.Errorf("%s: %s did not land: %+v", a.nodeID, tr.cmd.Member, tr.ack)
			}
		}
	}
	check(r.h.agent, r.h.nodeURL+backupxfer.IngestPathPrefix, true)
	check(r.h.compute, r.h.baseURL+backupxfer.IngestPathPrefix, false)

	for _, n := range []string{runNodeID, computeNodeID} {
		if c := reader.getCalls(n); c != 1 {
			t.Errorf("the router read %s %d times in the pass, want 1", n, c)
		}
	}
	lines := r.h.ledgerLines(t, r.jobID)
	if c := countLines(lines, "info", "node "+runNodeID+" uploads over its node key"); c != 1 {
		t.Errorf("node-key route lines for %s: %d, want 1", runNodeID, c)
	}
	if c := countLines(lines, "info", "node "+computeNodeID+" uploads by bearer credential"); c != 1 {
		t.Errorf("bearer route lines for %s: %d, want 1", computeNodeID, c)
	}
	if c := countLines(lines, "info", "uploads by bearer credential"); c != 1 {
		t.Errorf("bearer route lines: %d, want 1", c)
	}
	if c := countLines(lines, "warn", "is not on the node-key route"); c != 1 {
		t.Errorf("bearer warn lines: %d, want exactly 1", c)
	}
	if c := countLines(lines, "warn", computeNodeID, "agent predates key-bound transfer"); c != 1 {
		t.Errorf("bearer warn line for %s naming why: %d, want 1", computeNodeID, c)
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
func TestRestoreAppUsesTheRoute(t *testing.T) {
	verified := func(t *testing.T, c *restoreCase) (proto.BackupRestoreVolumeCmd, backupxfer.Grant) {
		t.Helper()
		calls := c.h.agent.restoreCalls()
		if len(calls) != 1 || !calls[0].ack.OK {
			t.Fatalf("restore calls: %+v", calls)
		}
		g, err := c.h.ingest.Authority().Verify(calls[0].cmd.Credential)
		if err != nil {
			t.Fatalf("credential: %v", err)
		}
		return calls[0].cmd, g
	}

	t.Run("capable and keyed: the node listener, key-bound", func(t *testing.T) {
		reader := (&fakeRouteNodes{}).capable(runNodeID, agentKeys())
		c := newRestoreCase(t, runHarnessOpts{routeNodes: reader})
		c.corrupt(t)
		if j, _ := c.restore(t, c.spec()); j.Status != jobs.StatusSucceeded {
			t.Fatalf("restore job %s: %s", j.Status, j.Error)
		}
		cmd, g := verified(t, c)
		if cmd.Source != c.h.nodeURL+backupxfer.EgressPathPrefix || !g.KeyBound {
			t.Fatalf("source %s, KeyBound %v; want %s, true", cmd.Source, g.KeyBound, c.h.nodeURL+backupxfer.EgressPathPrefix)
		}
	})
	t.Run("not capable: the public base, unbound", func(t *testing.T) {
		c := newRestoreCase(t, runHarnessOpts{})
		c.corrupt(t)
		if j, _ := c.restore(t, c.spec()); j.Status != jobs.StatusSucceeded {
			t.Fatalf("restore job %s: %s", j.Status, j.Error)
		}
		cmd, g := verified(t, c)
		if cmd.Source != c.h.baseURL+backupxfer.EgressPathPrefix || g.KeyBound {
			t.Fatalf("source %s, KeyBound %v; want %s, false", cmd.Source, g.KeyBound, c.h.baseURL+backupxfer.EgressPathPrefix)
		}
	})
	for _, tc := range []struct {
		name    string
		breakIt func(*fakeRouteNodes)
		want    []string
	}{
		{"capable with no agent key", func(f *fakeRouteNodes) {
			f.capable(runNodeID, proto.NodeKeys{proto.NodeKeyCollector: "spki-collector"})
		}, []string{"node " + runNodeID, "no registered agent key"}},
		{"absent", func(f *fakeRouteNodes) {
			f.mu.Lock()
			f.absent = map[string]bool{runNodeID: true}
			f.mu.Unlock()
		}, []string{"node " + runNodeID, "not in inventory"}},
	} {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			reader := &fakeRouteNodes{}
			c := newRestoreCase(t, runHarnessOpts{routeNodes: reader}) // backed up by bearer
			tc.breakIt(reader)
			j, _ := c.restore(t, c.spec())
			if j.Status != jobs.StatusFailed {
				t.Fatalf("job: %s %s", j.Status, j.Error)
			}
			for _, sub := range tc.want {
				if !strings.Contains(j.Error, sub) {
					t.Errorf("error %q lacks %q", j.Error, sub)
				}
			}
			if n := len(c.h.agent.restoreCalls()); n != 0 {
				t.Fatalf("%d restore verb(s) were sent", n)
			}
		})
	}
}
