package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// specAppIDsRefused is every appId an app.* spec parser must refuse: the
// empty id, then invalidAppIDs (path separators, dot segments, wrong length,
// wrong alphabet).
func specAppIDsRefused() []string {
	return append([]string{""}, invalidAppIDs...)
}

func mustSpecJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	return b
}

// appSpecParsers is every parser that reads an appId from an app.* job spec,
// each wrapped to take the id and return the id it decoded.
func appSpecParsers(t *testing.T) []struct {
	name  string
	parse func(appID string) (string, error)
} {
	return []struct {
		name  string
		parse func(appID string) (string, error)
	}{
		{"parseSpec", func(id string) (string, error) {
			spec, err := parseSpec(mustSpecJSON(t, DeploySpec{AppID: id}))
			if err != nil {
				return "", err
			}
			return spec.AppID, nil
		}},
		{"parseComposeChangeSpec", func(id string) (string, error) {
			spec, err := parseComposeChangeSpec(mustSpecJSON(t, ComposeChangeSpec{AppID: id}))
			if err != nil {
				return "", err
			}
			return spec.AppID, nil
		}},
		{"parseRevertSpec", func(id string) (string, error) {
			spec, err := parseRevertSpec(mustSpecJSON(t, RevertSpec{AppID: id, ComposeSHA256: ComposeHash(composeV1)}))
			if err != nil {
				return "", err
			}
			return spec.AppID, nil
		}},
		{"parseDeleteSpec", func(id string) (string, error) {
			spec, err := parseDeleteSpec(mustSpecJSON(t, DeleteSpec{AppID: id}))
			if err != nil {
				return "", err
			}
			return spec.AppID, nil
		}},
	}
}

func TestAppSpecParsers_RejectInvalidAppID(t *testing.T) {
	for _, p := range appSpecParsers(t) {
		t.Run(p.name, func(t *testing.T) {
			for _, id := range specAppIDsRefused() {
				if got, err := p.parse(id); err == nil {
					t.Errorf("accepted appId %q (decoded %q)", id, got)
				} else if !strings.Contains(err.Error(), "appId") {
					t.Errorf("appId %q: error %q does not name appId", id, err)
				}
			}
		})
	}
}

func TestAppSpecParsers_AcceptValidAppID(t *testing.T) {
	for _, p := range appSpecParsers(t) {
		t.Run(p.name, func(t *testing.T) {
			// Either case is an app id.
			for _, id := range []string{testAppID, strings.ToLower(testAppID)} {
				if got, err := p.parse(id); err != nil || got != id {
					t.Errorf("parse(%q) = %q, %v; want accepted", id, got, err)
				}
			}
		})
	}
}

// Each app.* saga, given a spec whose appId is not an app id, fails at its
// first step with the parser's error. A row is stored under every such id on
// an online compute node, so a first step that looked the id up would find an
// app and succeed; none does. The runner ends a job at its first failed step,
// so only that step is run here. Nothing is published on the bus and no row
// changes.
func TestAppSagas_InvalidAppIDFailsAtFirstStep(t *testing.T) {
	customApp := func(id string) *App {
		now := time.Now().UTC().Add(-time.Hour)
		return &App{
			ID: id, Name: "mine", ComposeYAML: customV1, TargetNode: "n",
			LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now,
		}
	}
	lookup := lookupOf(upgradeTile(composeV2), 2)

	kinds := []struct {
		kind  string
		seed  func(id string) *App
		build func(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.Workflow
		spec  func(t *testing.T, id string) string
	}{
		{"app.deploy", installedApp,
			func(s *Store, i *inventory.Store, nc *nats.Conn) jobs.Workflow { return DeployWorkflow(s, i, nc, nil) },
			func(t *testing.T, id string) string { return string(mustSpecJSON(t, DeploySpec{AppID: id})) }},
		{"app.stop", installedApp,
			func(s *Store, i *inventory.Store, nc *nats.Conn) jobs.Workflow { return StopWorkflow(s, i, nc) },
			func(t *testing.T, id string) string { return string(mustSpecJSON(t, DeploySpec{AppID: id})) }},
		{"app.upgrade", installedApp,
			func(s *Store, i *inventory.Store, nc *nats.Conn) jobs.Workflow {
				return UpgradeWorkflow(s, i, nc, nil, lookup)
			},
			func(t *testing.T, id string) string { return string(mustSpecJSON(t, ComposeChangeSpec{AppID: id})) }},
		{"app.edit", customApp,
			func(s *Store, i *inventory.Store, nc *nats.Conn) jobs.Workflow {
				return EditWorkflow(s, i, nc, nil, NewComposeStash())
			},
			func(t *testing.T, id string) string { return string(mustSpecJSON(t, ComposeChangeSpec{AppID: id})) }},
		{"app.revert", installedApp,
			func(s *Store, i *inventory.Store, nc *nats.Conn) jobs.Workflow { return RevertWorkflow(s, i, nc, nil) },
			func(t *testing.T, id string) string {
				return string(mustSpecJSON(t, RevertSpec{AppID: id, ComposeSHA256: ComposeHash(composeV2)}))
			}},
	}

	for _, k := range kinds {
		t.Run(k.kind, func(t *testing.T) {
			ctx := context.Background()
			nc := startNATS(t)
			store, inv := newStore(t), newInventory(t)
			if err := inv.Insert(ctx, &proto.Node{
				ID: "n", Role: proto.RoleCompute, Hostname: "n.test", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
			}); err != nil {
				t.Fatal(err)
			}
			ids := specAppIDsRefused()
			for i, id := range ids {
				a := k.seed(id)
				a.Name = fmt.Sprintf("app-%d", i)
				if err := store.Create(ctx, a); err != nil {
					t.Fatalf("seed row %q: %v", id, err)
				}
			}
			before := map[string]*App{}
			for _, id := range ids {
				before[id], _ = store.Get(ctx, id)
			}

			events, err := nc.SubscribeSync(">")
			if err != nil {
				t.Fatalf("subscribe: %v", err)
			}
			defer func() { _ = events.Unsubscribe() }()

			w := k.build(store, inv, nc)
			first := w.Steps[0].Name
			firstOnly := jobs.Workflow{Kind: w.Kind, Steps: w.Steps[:1]}
			for _, id := range ids {
				run := runWorkflow(t, firstOnly, nc, k.spec(t, id), "job-test")
				if run.err == nil || errors.Is(run.err, jobs.ErrStopWorkflow) {
					t.Errorf("appId %q: saga did not fail (err %v)", id, run.err)
					continue
				}
				if run.failedAt != first {
					t.Errorf("appId %q: failed at step %q, want %q", id, run.failedAt, first)
				}
				if !strings.Contains(run.err.Error(), "appId") {
					t.Errorf("appId %q: error %q is not the spec's appId check", id, run.err)
				}
			}

			for _, id := range ids {
				if got, _ := store.Get(ctx, id); sameRecord(before[id], got) != "" || got.LastStatus != before[id].LastStatus {
					t.Errorf("row %q changed: %+v", id, got)
				}
			}
			if err := nc.Flush(); err != nil {
				t.Fatalf("flush: %v", err)
			}
			if msg, err := events.NextMsg(200 * time.Millisecond); err == nil {
				t.Errorf("a refused spec published %q", msg.Subject)
			}
		})
	}
}
