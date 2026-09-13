package apps

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The dropped-volume gate (geekdojo/geekdojo-brain#412), below the HTTP layer:
// every compose saga refuses, before it pulls or writes, a change that would
// orphan a named volume the app has on disk, unless the spec names exactly
// those volumes — and then deletes them only after `up` succeeded.

const gateAppID = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"

func gateVol(key string) proto.AppDroppedVolume {
	return proto.AppDroppedVolume{Name: proto.AppVolumeName(gateAppID, key), Volume: key}
}

// nodeLog is the order in which the fake node was asked to do things.
type nodeLog struct {
	mu     sync.Mutex
	events []string
	drops  []proto.AppVolumesDropCmd
}

func (l *nodeLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *nodeLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.events, ",")
}

// gateNodeAgent answers every verb a compose saga sends node n: the volumes
// check reports dropped, pull and deploy answer with the acks given, and drop
// removes whatever it is sent unless refuse names a reason.
func gateNodeAgent(t *testing.T, nc *nats.Conn, dropped []proto.AppDroppedVolume, deploy proto.AppDeployAck, refuse string) *nodeLog {
	t.Helper()
	l := &nodeLog{}
	sub := func(subject string, answer func(m *nats.Msg) any) {
		s, err := nc.Subscribe(subject, func(m *nats.Msg) {
			b, _ := json.Marshal(answer(m))
			_ = m.Respond(b)
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Unsubscribe() })
	}
	sub(proto.AppVolumesCheckSubject("n"), func(*nats.Msg) any {
		l.add("check")
		return proto.AppVolumesCheckAck{OK: true, Declared: []string{}, Dropped: dropped}
	})
	sub(proto.AppPullSubject("n"), func(*nats.Msg) any {
		l.add("pull")
		return proto.AppPullAck{OK: true}
	})
	sub(proto.AppDeploySubject("n"), func(*nats.Msg) any {
		l.add("deploy")
		return deploy
	})
	sub(proto.AppVolumesDropSubject("n"), func(m *nats.Msg) any {
		l.add("drop")
		var cmd proto.AppVolumesDropCmd
		_ = json.Unmarshal(m.Data, &cmd)
		l.mu.Lock()
		l.drops = append(l.drops, cmd)
		l.mu.Unlock()
		ack := proto.AppVolumesRemoveAck{OK: true, Removed: []string{}, Refused: []proto.AppVolumeRefusal{}}
		for _, n := range cmd.Names {
			if refuse != "" {
				ack.Refused = append(ack.Refused, proto.AppVolumeRefusal{Name: n, Reason: refuse})
			} else {
				ack.Removed = append(ack.Removed, n)
			}
		}
		return ack
	})
	return l
}

// gateVariant is one of the three compose sagas, set up against an app that
// is running and whose change would reach the node.
type gateVariant struct {
	name string
	// setup seeds the app and returns the store, inventory, and a func that
	// runs the saga with deleteVolumes in its spec.
	setup func(t *testing.T, nc *nats.Conn) (*Store, *inventory.Store, func(deleteVolumes []string) workflowRun)
}

func gateVariants() []gateVariant {
	return []gateVariant{
		{"upgrade", func(t *testing.T, nc *nats.Conn) (*Store, *inventory.Store, func([]string) workflowRun) {
			store, inv := seedUpgradeApp(t, gateAppID)
			return store, inv, func(dv []string) workflowRun {
				spec, _ := json.Marshal(ComposeChangeSpec{AppID: gateAppID, DeleteVolumes: dv})
				return runWorkflow(t, UpgradeWorkflow(store, inv, nc, nil, lookupOf(upgradeTile(composeV2), 2)), nc, string(spec), "job-up")
			}
		}},
		{"edit", func(t *testing.T, nc *nats.Conn) (*Store, *inventory.Store, func([]string) workflowRun) {
			store, inv := seedCustomApp(t, gateAppID)
			stash := NewComposeStash()
			if err := stash.Put("job-edit", customV2); err != nil {
				t.Fatal(err)
			}
			return store, inv, func(dv []string) workflowRun {
				spec, _ := json.Marshal(ComposeChangeSpec{AppID: gateAppID, DeleteVolumes: dv})
				return runWorkflow(t, EditWorkflow(store, inv, nc, nil, stash), nc, string(spec), "job-edit")
			}
		}},
		{"revert", func(t *testing.T, nc *nats.Conn) (*Store, *inventory.Store, func([]string) workflowRun) {
			store, inv := seedUpgradeApp(t, gateAppID)
			if err := store.UpgradeCompose(context.Background(), gateAppID, ComposeHash(composeV1), UpgradeTarget{Tile: upgradeTile(composeV2), CatalogVersion: 2}.ComposeUpgrade(), time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			return store, inv, func(dv []string) workflowRun {
				spec, _ := json.Marshal(RevertSpec{AppID: gateAppID, ComposeSHA256: ComposeHash(composeV1), DeleteVolumes: dv})
				return runWorkflow(t, RevertWorkflow(store, inv, nc, nil), nc, string(spec), "job-revert")
			}
		}},
	}
}

func TestGateDroppedVolumes(t *testing.T) {
	data, cache := gateVol("data"), gateVol("cache")
	cases := []struct {
		name       string
		dropped    []proto.AppDroppedVolume
		named      []string
		unnamed    []string
		notDropped []string
	}{
		{"nothing dropped, nothing named", nil, nil, nil, nil},
		{"exact set", []proto.AppDroppedVolume{data, cache}, []string{cache.Name, data.Name}, nil, nil},
		{"renamed key, not named", []proto.AppDroppedVolume{data}, nil, []string{data.Name}, nil},
		{"partial set", []proto.AppDroppedVolume{data, cache}, []string{data.Name}, []string{cache.Name}, nil},
		{"names a volume not dropped", nil, []string{data.Name}, nil, []string{data.Name}},
		{"both", []proto.AppDroppedVolume{cache}, []string{data.Name}, []string{cache.Name}, []string{data.Name}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := GateDroppedVolumes(c.dropped, c.named)
			if c.unnamed == nil && c.notDropped == nil {
				if err != nil {
					t.Fatalf("want proceed, got %v", err)
				}
				return
			}
			var gate *VolumeGateError
			if !errors.As(err, &gate) {
				t.Fatalf("want a *VolumeGateError, got %v", err)
			}
			var unnamed []string
			for _, v := range gate.Unnamed {
				unnamed = append(unnamed, v.Name)
			}
			if strings.Join(unnamed, ",") != strings.Join(c.unnamed, ",") || strings.Join(gate.NotDropped, ",") != strings.Join(c.notDropped, ",") {
				t.Errorf("unnamed %v notDropped %v, want %v %v", unnamed, gate.NotDropped, c.unnamed, c.notDropped)
			}
			if len(gate.Dropped) != len(c.dropped) {
				t.Errorf("Dropped = %v, want every dropped volume listed", gate.Dropped)
			}
			for _, n := range append(c.unnamed, c.notDropped...) {
				if !strings.Contains(err.Error(), n) {
					t.Errorf("error %q does not name %s", err, n)
				}
			}
		})
	}
}

func TestValidateDeleteVolumes(t *testing.T) {
	ok := [][]string{nil, {}, {proto.AppVolumeName(gateAppID, "data")}, {proto.AppVolumeName(strings.ToLower(gateAppID), "a"), proto.AppVolumeName(gateAppID, "b")}}
	for _, names := range ok {
		if err := ValidateDeleteVolumes(gateAppID, names); err != nil {
			t.Errorf("%v: %v", names, err)
		}
	}
	for name, names := range map[string][]string{
		"another app's": {proto.AppVolumeName("01J9ZK3Q0M8X7Y6W5V4T3S2R1B", "data")},
		"anonymous":     {strings.Repeat("ab", 32)},
		"not ours":      {"myproj_data"},
		"twice":         {proto.AppVolumeName(gateAppID, "data"), proto.AppVolumeName(gateAppID, "data")},
	} {
		if err := ValidateDeleteVolumes(gateAppID, names); err == nil {
			t.Errorf("%s: accepted %v", name, names)
		}
	}
}

func TestDroppedByDeclared(t *testing.T) {
	other := "01J9ZK3Q0M8X7Y6W5V4T3S2R1B"
	onNode := []proto.AppVolumeInfo{
		{Name: proto.AppVolumeName(gateAppID, "config"), AppID: gateAppID, Volume: "config"},
		{Name: proto.AppVolumeName(gateAppID, "old"), AppID: gateAppID, Volume: "old"},
		{Name: strings.Repeat("ab", 32), AppID: gateAppID, Anonymous: true},
		{Name: proto.AppVolumeName(other, "old"), AppID: other, Volume: "old"},
	}
	got := DroppedByDeclared(gateAppID, onNode, []string{"config", "cache"})
	if len(got) != 1 || got[0] != gateVol("old") {
		t.Errorf("dropped = %+v, want only this app's renamed-away volume", got)
	}
}

// A spec is checked on its own: a job submitted without the handler cannot
// name another app's volume, an anonymous one, or one twice.
func TestComposeSpecs_RefuseBadDeleteVolumes(t *testing.T) {
	bad := proto.AppVolumeName("01J9ZK3Q0M8X7Y6W5V4T3S2R1B", "data")
	if _, err := parseComposeChangeSpec(json.RawMessage(`{"appId":"` + gateAppID + `","deleteVolumes":["` + bad + `"]}`)); err == nil {
		t.Error("ComposeChangeSpec accepted another app's volume")
	}
	if _, err := parseRevertSpec(json.RawMessage(`{"appId":"` + gateAppID + `","sha256":"` + ComposeHash(composeV1) + `","deleteVolumes":["` + bad + `"]}`)); err == nil {
		t.Error("RevertSpec accepted another app's volume")
	}
	if _, err := parseSpec(json.RawMessage(`{"appId":"` + testAppID + `","deleteVolumes":[]}`)); err == nil {
		t.Error("app.deploy's spec must still refuse deleteVolumes")
	}
}

// The saga refuses on its own, whatever the handler did: a renamed key (or a
// dropped service — to the gate both are a volume on disk the compose does not
// declare) fails the pull step before the node is asked to pull, writes
// nothing, puts the status back with the volumes named, and deletes nothing.
func TestComposeSagas_RefuseAnUnnamedDroppedVolumeBeforeThePull(t *testing.T) {
	for _, v := range gateVariants() {
		t.Run(v.name, func(t *testing.T) {
			nc := startNATS(t)
			store, _, run := v.setup(t, nc)
			before, _ := store.Get(context.Background(), gateAppID)
			node := gateNodeAgent(t, nc, []proto.AppDroppedVolume{gateVol("data"), gateVol("worker-cache")}, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning}, "")

			r := run(nil)
			var gate *VolumeGateError
			if r.failedAt != "pull" || !errors.As(r.err, &gate) || len(gate.Unnamed) != 2 {
				t.Fatalf("want the pull step to refuse with both volumes, got step=%q err=%v", r.failedAt, r.err)
			}
			if got := node.String(); got != "check" {
				t.Errorf("node was asked %q, want only the check", got)
			}
			after, _ := store.Get(context.Background(), gateAppID)
			if field := sameRecord(before, after); field != "" {
				t.Errorf("a refused change wrote the row's %s", field)
			}
			if after.LastStatus != proto.AppStatusRunning ||
				!strings.Contains(after.LastDetail, gateVol("data").Name) || !strings.Contains(after.LastDetail, gateVol("worker-cache").Name) {
				t.Errorf("status = %s %q, want running with both volumes named", after.LastStatus, after.LastDetail)
			}
		})
	}
}

// A partial set, and a name the change does not drop, are refused the same way.
func TestComposeSagas_RefuseAPartialOrWrongDeleteSet(t *testing.T) {
	for _, v := range gateVariants() {
		for name, named := range map[string][]string{
			"partial":      {gateVol("data").Name},
			"not dropped":  {gateVol("data").Name, gateVol("worker-cache").Name, gateVol("still-declared").Name},
			"only another": {gateVol("still-declared").Name},
		} {
			t.Run(v.name+"/"+name, func(t *testing.T) {
				nc := startNATS(t)
				_, _, run := v.setup(t, nc)
				node := gateNodeAgent(t, nc, []proto.AppDroppedVolume{gateVol("data"), gateVol("worker-cache")}, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning}, "")
				r := run(named)
				var gate *VolumeGateError
				if r.failedAt != "pull" || !errors.As(r.err, &gate) {
					t.Fatalf("want the pull step to refuse, got step=%q err=%v", r.failedAt, r.err)
				}
				if got := node.String(); got != "check" {
					t.Errorf("node was asked %q, want only the check", got)
				}
			})
		}
	}
}

// The owner names exactly the dropped set: the change goes through, and the
// volumes are deleted after the deploy — exactly those, and nothing sent
// before `up` answered.
func TestComposeSagas_DeleteExactlyTheNamedDroppedVolumesAfterUp(t *testing.T) {
	for _, v := range gateVariants() {
		t.Run(v.name, func(t *testing.T) {
			nc := startNATS(t)
			_, _, run := v.setup(t, nc)
			dropped := []proto.AppDroppedVolume{gateVol("worker-cache"), gateVol("data")}
			node := gateNodeAgent(t, nc, dropped, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning}, "")

			r := run([]string{gateVol("worker-cache").Name, gateVol("data").Name})
			if r.err != nil {
				t.Fatalf("step %s: %v", r.failedAt, r.err)
			}
			if got := node.String(); got != "check,pull,deploy,drop" {
				t.Errorf("node was asked %q, want check,pull,deploy,drop", got)
			}
			if len(node.drops) != 1 || node.drops[0].AppID != gateAppID ||
				strings.Join(node.drops[0].Names, ",") != gateVol("data").Name+","+gateVol("worker-cache").Name {
				t.Errorf("drop = %+v, want exactly the two dropped volumes", node.drops)
			}
			var res dropVolumesResult
			if err := json.Unmarshal(r.results["drop_volumes"], &res); err != nil || len(res.Removed) != 2 {
				t.Errorf("drop step result = %s (%v)", r.results["drop_volumes"], err)
			}
		})
	}
}

// Only adding a volume drops nothing: the change proceeds, and no drop is
// sent.
func TestComposeSagas_AnAddedVolumeProceedsWithoutDeleting(t *testing.T) {
	for _, v := range gateVariants() {
		t.Run(v.name, func(t *testing.T) {
			nc := startNATS(t)
			_, _, run := v.setup(t, nc)
			node := gateNodeAgent(t, nc, nil, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning}, "")
			if r := run(nil); r.err != nil {
				t.Fatalf("step %s: %v", r.failedAt, r.err)
			}
			if got := node.String(); got != "check,pull,deploy" {
				t.Errorf("node was asked %q, want check,pull,deploy", got)
			}
		})
	}
}

// `up` fails: nothing is deleted — the old compose may be re-applied, and it
// needs those volumes.
func TestComposeSagas_AFailedUpDeletesNothing(t *testing.T) {
	for _, v := range gateVariants() {
		t.Run(v.name, func(t *testing.T) {
			nc := startNATS(t)
			_, _, run := v.setup(t, nc)
			node := gateNodeAgent(t, nc, []proto.AppDroppedVolume{gateVol("data")}, proto.AppDeployAck{OK: false, Status: proto.AppStatusFailed, Detail: "port is already allocated"}, "")
			r := run([]string{gateVol("data").Name})
			if r.failedAt != "push" {
				t.Fatalf("want the push to fail, got step=%q err=%v", r.failedAt, r.err)
			}
			if got := node.String(); got != "check,pull,deploy" {
				t.Errorf("node was asked %q, want no drop after a failed up", got)
			}
		})
	}
}

// The node refuses a removal: the job fails naming the volume and why, and the
// change it made stays made.
func TestComposeSagas_ARefusedDropFailsTheJobNamingTheVolume(t *testing.T) {
	nc := startNATS(t)
	v := gateVariants()[0]
	store, _, run := v.setup(t, nc)
	gateNodeAgent(t, nc, []proto.AppDroppedVolume{gateVol("data")}, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning}, "still referenced by 1 container(s): c1")
	r := run([]string{gateVol("data").Name})
	if r.failedAt != "drop_volumes" || !strings.Contains(r.err.Error(), gateVol("data").Name) || !strings.Contains(r.err.Error(), "still referenced") {
		t.Fatalf("want the drop step to fail naming the volume, got step=%q err=%v", r.failedAt, r.err)
	}
	if row, _ := store.Get(context.Background(), gateAppID); row.ComposeYAML != composeV2 || row.LastStatus != proto.AppStatusRunning {
		t.Errorf("row = %q %s, want the upgrade applied and running", row.ComposeYAML, row.LastStatus)
	}
}

// A node that cannot answer the check is not an answer: the change is refused
// with the no-responder reading, and nothing is pulled.
func TestComposeSagas_AnUnansweredCheckChangesNothing(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedUpgradeApp(t, gateAppID)
	pulls := fakePullOnly(t, nc, proto.AppPullAck{OK: true}, nil)
	r := runWorkflow(t, UpgradeWorkflow(store, inv, nc, nil, lookupOf(upgradeTile(composeV2), 2)), nc, `{"appId":"`+gateAppID+`"}`, "j")
	if r.failedAt != "pull" || !strings.Contains(r.err.Error(), "docker.volumes.check") {
		t.Fatalf("want a refusal naming docker.volumes.check, got step=%q err=%v", r.failedAt, r.err)
	}
	select {
	case cmd := <-pulls:
		t.Fatalf("pulled without an answer: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	if row, _ := store.Get(context.Background(), gateAppID); row.ComposeYAML != composeV1 || row.LastStatus != proto.AppStatusRunning {
		t.Errorf("row = %q %s", row.ComposeYAML, row.LastStatus)
	}
}
