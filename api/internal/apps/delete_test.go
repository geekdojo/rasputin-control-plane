package apps

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// delAppID is the app every test in this file seeds. Delete specs are refused
// unless their appId is shaped like an app id, so it is a real ULID.
const delAppID = "01J8Z3K5QW6X7Y8Z9A0B1C2D3E"

// missingAppID is a well-formed id that no test seeds.
const missingAppID = "01J8Z3K5QW6X7Y8Z9A0B1C2D3F"

// Online node: deleteStop RPCs the agent's docker.stop and succeeds; deleteRemove
// then drops the row and emits the deleted event.
func TestDelete_OnlineStopsThenRemoves(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "uptime-kuma")

	sub, err := nc.Subscribe(proto.AppStopSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppStopAck{OK: true, Status: proto.AppStatusStopped})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	deletedSub, err := nc.SubscribeSync(proto.AppChangeSubject(delAppID, proto.AppDeleted))
	if err != nil {
		t.Fatalf("change sub: %v", err)
	}
	defer func() { _ = deletedSub.Unsubscribe() }()

	// Step 1: stop.
	if _, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc)); err != nil {
		t.Fatalf("deleteStop: %v", err)
	}
	// Step 2: remove.
	if _, err := deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc)); err != nil {
		t.Fatalf("deleteRemove: %v", err)
	}

	if got, _ := store.Get(ctx, delAppID); got != nil {
		t.Errorf("app row should be gone, got %+v", got)
	}
	if _, err := deletedSub.NextMsg(time.Second); err != nil {
		t.Errorf("expected AppDeleted change event: %v", err)
	}
}

// Online node whose stop fails: deleteStop returns an error and the row is kept
// (no silent orphan on a reachable node).
func TestDelete_OnlineStopFailsKeepsRow(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "uptime-kuma")

	sub, _ := nc.Subscribe(proto.AppStopSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppStopAck{OK: false, Detail: "compose down failed"})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	if _, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc)); err == nil {
		t.Fatal("expected deleteStop to fail when the agent reports stop failed")
	}
	if got, _ := store.Get(ctx, delAppID); got == nil {
		t.Error("app row must remain after a failed stop on a reachable node")
	}
}

// Offline node: deleteStop can't reach the agent, so it skips the stop (with a
// warning) and lets deleteRemove drop the record anyway.
func TestDelete_OfflineNodeSkipsStopButRemoves(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	stale := time.Now().Add(-5 * time.Minute).UTC()
	if err := inv.Insert(ctx, &proto.Node{
		ID: "n", Role: proto.RoleCompute, Hostname: "n.test", FirstSeen: stale, LastSeen: stale,
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	a := makeApp(delAppID, "uptime-kuma")
	a.TargetNode = "n"
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("Create app: %v", err)
	}

	// No agent responder — the node is offline; deleteStop must not block on it.
	out, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc))
	if err != nil {
		t.Fatalf("deleteStop on offline node should not fail: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected a step result")
	}
	if _, err := deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc)); err != nil {
		t.Fatalf("deleteRemove: %v", err)
	}
	if got, _ := store.Get(ctx, delAppID); got != nil {
		t.Errorf("app row should be gone, got %+v", got)
	}
}

// deleteStop is idempotent: a missing app is a success (a retry after remove
// already ran).
func TestDelete_MissingAppIsIdempotent(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	if _, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"`+missingAppID+`"}`, nc)); err != nil {
		t.Errorf("deleteStop on a missing app should succeed, got %v", err)
	}
	if _, err := deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"`+missingAppID+`"}`, nc)); err != nil {
		t.Errorf("deleteRemove on a missing app should succeed, got %v", err)
	}
}

// --- geekdojo/geekdojo-brain#399: "Delete volumes?" rides the delete spec ---

// captureStopCmd installs a fake agent that records the AppStopCmd it was sent
// and acks stopped.
func captureStopCmd(t *testing.T, nc *nats.Conn, nodeID string) *proto.AppStopCmd {
	t.Helper()
	got := &proto.AppStopCmd{}
	sub, err := nc.Subscribe(proto.AppStopSubject(nodeID), func(m *nats.Msg) {
		_ = json.Unmarshal(m.Data, got)
		ack, _ := json.Marshal(proto.AppStopAck{OK: true, Status: proto.AppStatusStopped})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return got
}

// A delete spec without deleteVolumes — every client that predates the field
// — stops with plain `compose down`: the agent sees false.
func TestDelete_DefaultKeepsVolumes(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	got := captureStopCmd(t, nc, "n")
	out, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc))
	if err != nil {
		t.Fatalf("deleteStop: %v", err)
	}
	if got.AppID != delAppID || got.DeleteVolumes {
		t.Fatalf("agent received %+v; deleteVolumes must default to false", got)
	}
	if !strings.Contains(string(out), `"volumes":"kept"`) {
		t.Errorf("step result must say the volumes were kept: %s", out)
	}
}

// A deleteVolumes list that is exactly the app's volumes on the node deletes
// them: a plain stop first, then the listing, then the stop that deletes.
func TestDelete_DeleteVolumesReachesAgent(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	agent := fakeDeleteAgent(t, nc, "n", delVolData, delVolAnon)
	out, err := deleteStop(store, inv, nc)(newStepCtxNATS(deleteSpecJSON(delVolData.Name, delVolAnon.Name), nc))
	if err != nil {
		t.Fatalf("deleteStop: %v", err)
	}
	if got := agent.stops(); len(got) != 2 || got[0] || !got[1] {
		t.Fatalf("stops sent = %v; want a plain stop, then one that deletes", got)
	}
	if agent.lists() != 1 {
		t.Fatalf("volume listings = %d; want one, between the two stops", agent.lists())
	}
	if !strings.Contains(string(out), `"volumes":"deleted"`) {
		t.Errorf("step result must say the volumes were deleted: %s", out)
	}
}

// A list that leaves out a volume the app has on the node is refused after
// the plain stop: nothing is deleted, the row stays and says why, naming the
// volume nobody confirmed.
func TestDelete_UnconfirmedVolumeRefusesAfterStop(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	agent := fakeDeleteAgent(t, nc, "n", delVolData, delVolAnon)
	_, err := deleteStop(store, inv, nc)(newStepCtxNATS(deleteSpecJSON(delVolData.Name), nc))
	if err == nil || !strings.Contains(err.Error(), delVolAnon.Name) || !strings.Contains(err.Error(), "no volume was deleted") {
		t.Fatalf("deleteStop = %v; want a refusal naming the unconfirmed volume", err)
	}
	if got := agent.stops(); len(got) != 1 || got[0] {
		t.Fatalf("stops sent = %v; want only the plain stop", got)
	}
	got, _ := store.Get(ctx, delAppID)
	if got == nil {
		t.Fatal("the app row must remain when nothing was deleted")
	}
	if got.LastStatus != proto.AppStatusStopped || !strings.Contains(got.LastDetail, delVolAnon.Name) {
		t.Errorf("row = %s %q; want stopped, naming the volume", got.LastStatus, got.LastDetail)
	}
}

// A name the node does not list for the app — shaped like one of its volumes
// or an anonymous one, but not there — is refused the same way.
func TestDelete_NameNotOnNodeRefusesAfterStop(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	agent := fakeDeleteAgent(t, nc, "n", delVolData)
	ghost := proto.AppVolumeName(delAppID, "ghost")
	_, err := deleteStop(store, inv, nc)(newStepCtxNATS(deleteSpecJSON(delVolData.Name, ghost), nc))
	if err == nil || !strings.Contains(err.Error(), ghost) || !strings.Contains(err.Error(), "does not have") {
		t.Fatalf("deleteStop = %v; want a refusal naming %s", err, ghost)
	}
	if got := agent.stops(); len(got) != 1 || got[0] {
		t.Fatalf("stops sent = %v; want only the plain stop", got)
	}
}

// Another app's volume on the same node never counts as this app's.
func TestDelete_OtherAppsVolumeIsNotThisAppsToDelete(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	other := proto.AppVolumeInfo{Name: proto.AppVolumeName(missingAppID, "data"), AppID: missingAppID, Volume: "data"}
	agent := fakeDeleteAgent(t, nc, "n", delVolData, other)
	if _, err := deleteStop(store, inv, nc)(newStepCtxNATS(deleteSpecJSON(delVolData.Name), nc)); err != nil {
		t.Fatalf("deleteStop: %v — another app's volume must not be required", err)
	}
	if got := agent.stops(); len(got) != 2 || !got[1] {
		t.Fatalf("stops sent = %v", got)
	}
	// And naming it is refused before any node is asked.
	if _, err := parseDeleteSpec(json.RawMessage(deleteSpecJSON(other.Name))); err == nil || !strings.Contains(err.Error(), "not of this app") {
		t.Fatalf("parseDeleteSpec(other app's volume) = %v", err)
	}
}

// A node that cannot list its volumes deletes nothing.
func TestDelete_ListingFailsDeletesNothing(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	got := captureStopCmd(t, nc, "n") // answers stops, never the listing
	_, err := deleteStop(store, inv, nc)(newStepCtxNATS(deleteSpecJSON(delVolData.Name), nc))
	if err == nil || !strings.Contains(err.Error(), "could not be listed") {
		t.Fatalf("deleteStop = %v; want a refusal saying the volumes could not be listed", err)
	}
	if got.DeleteVolumes {
		t.Fatal("a stop that deletes volumes was sent without a listing")
	}
}

// The flag is app.delete's alone. A stop or deploy spec carrying it is refused
// outright — it cannot be silently ignored into a plain stop, and it can never
// turn a stop into a `down -v`.
func TestDelete_FlagNeverLeaksIntoOtherKinds(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	got := captureStopCmd(t, nc, "n")

	for _, spec := range []string{`{"appId":"` + delAppID + `","deleteVolumes":true}`, deleteSpecJSON(delVolData.Name)} {
		if _, err := stopPush(store, inv, nc)(newStepCtxNATS(spec, nc)); err == nil {
			t.Fatalf("app.stop must refuse a spec carrying deleteVolumes: %s", spec)
		}
	}
	if got.DeleteVolumes {
		t.Fatal("app.stop sent deleteVolumes to the agent")
	}
	if _, err := parseSpec(json.RawMessage(deleteSpecJSON(delVolData.Name))); err == nil {
		t.Fatal("parseSpec (deploy/stop) must refuse deleteVolumes")
	}
	// A plain stop never sends the flag at all.
	if _, err := stopPush(store, inv, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc)); err != nil {
		t.Fatalf("stopPush: %v", err)
	}
	if got.DeleteVolumes {
		t.Fatal("a plain app.stop must send deleteVolumes:false")
	}
}

// A misspelling of the one field that destroys data is a refusal, not a
// silent keep; so is the boolean the field used to be, a malformed name,
// another app's volume and a name given twice.
func TestDelete_SpecIsStrict(t *testing.T) {
	refused := map[string]string{
		"misspelled": `{"appId":"` + delAppID + `","deleteVolume":["` + delVolData.Name + `"]}`,
		"boolean":    `{"appId":"` + delAppID + `","deleteVolumes":true}`,
		"malformed":  deleteSpecJSON("data"),
		"other app":  deleteSpecJSON(proto.AppVolumeName(missingAppID, "data")),
		"twice":      deleteSpecJSON(delVolData.Name, delVolData.Name),
	}
	for name, raw := range refused {
		if _, err := parseDeleteSpec(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: parseDeleteSpec(%s) accepted", name, raw)
		}
	}
	spec, err := parseDeleteSpec(json.RawMessage(deleteSpecJSON(delVolData.Name, delVolAnon.Name)))
	if err != nil || len(spec.DeleteVolumes) != 2 {
		t.Fatalf("parseDeleteSpec: %v %+v", err, spec)
	}
}

// Delete-with-volumes on an offline node is REFUSED, naming the node, and the
// row stays. Removing the row would leave the data behind as an orphan the
// operator believes is gone — the failure #399 exists to prevent.
func TestDelete_DeleteVolumesOnOfflineNodeRefuses(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	stale := time.Now().Add(-5 * time.Minute).UTC()
	if err := inv.Insert(ctx, &proto.Node{
		ID: "n", Role: proto.RoleCompute, Hostname: "n.test", FirstSeen: stale, LastSeen: stale,
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	a := makeApp(delAppID, "immich")
	a.TargetNode = "n"
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("Create app: %v", err)
	}
	_, err := deleteStop(store, inv, nc)(newStepCtxNATS(deleteSpecJSON(delVolData.Name), nc))
	if err == nil {
		t.Fatal("expected a refusal on an offline node")
	}
	if !strings.Contains(err.Error(), `"n"`) || !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("refusal must name the node: %v", err)
	}
	if got, _ := store.Get(ctx, delAppID); got == nil {
		t.Error("the app row must remain when the delete was refused")
	}
	// And the keep path on the same offline node still proceeds, as before.
	if _, err := deleteStop(store, inv, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc)); err != nil {
		t.Errorf("keep-volumes delete on an offline node must still proceed: %v", err)
	}
}

// Delete-with-volumes where the agent removed the containers but could not
// remove every volume the app ever had (#413: one still referenced by a
// container outside the app) fails the step, keeps the row, and carries the
// agent's naming of what stayed — so the operator is never told data is gone
// that is still on the node.
func TestDelete_DeleteVolumesWithVolumesLeftBehindKeepsRow(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	const detail = "containers removed, but 1 of the app's volume(s) were NOT deleted — deadbeef: still referenced by 1 container(s): c1"
	agent := fakeDeleteAgent(t, nc, "n", delVolData)
	agent.deleteAck = proto.AppStopAck{OK: false, Status: proto.AppStatusStopped, Detail: detail}

	_, err := deleteStop(store, inv, nc)(newStepCtxNATS(deleteSpecJSON(delVolData.Name), nc))
	if err == nil || !strings.Contains(err.Error(), "NOT deleted") || !strings.Contains(err.Error(), "deadbeef") {
		t.Fatalf("deleteStop = %v, want the agent's naming of the volume left behind", err)
	}
	got, _ := store.Get(ctx, delAppID)
	if got == nil {
		t.Fatal("app row must remain when a volume the operator asked to delete is still on the node")
	}
	if !strings.Contains(got.LastDetail, "NOT deleted") {
		t.Errorf("lastDetail = %q, want the agent's detail recorded", got.LastDetail)
	}
}

// --- the exact-name list (auth consolidation 1A.12) ---

// The volumes the fake node holds for delAppID in these tests.
var (
	delVolData = proto.AppVolumeInfo{Name: proto.AppVolumeName(delAppID, "data"), AppID: delAppID, Volume: "data"}
	delVolAnon = proto.AppVolumeInfo{Name: strings.Repeat("ab", 32), AppID: delAppID, Anonymous: true, Service: "cache", Path: "/data"}
)

// deleteSpecJSON is an app.delete spec for delAppID naming names.
func deleteSpecJSON(names ...string) string {
	b, _ := json.Marshal(DeleteSpec{AppID: delAppID, DeleteVolumes: names})
	return string(b)
}

// deleteAgent is a fake node agent answering docker.stop and
// docker.volumes.list, recording what it was asked in order.
type deleteAgent struct {
	mu        sync.Mutex
	stopCmds  []bool
	listCalls int
	deleteAck proto.AppStopAck
}

func (a *deleteAgent) stops() []bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]bool(nil), a.stopCmds...)
}

func (a *deleteAgent) lists() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.listCalls
}

func fakeDeleteAgent(t *testing.T, nc *nats.Conn, nodeID string, vols ...proto.AppVolumeInfo) *deleteAgent {
	t.Helper()
	a := &deleteAgent{deleteAck: proto.AppStopAck{OK: true, Status: proto.AppStatusStopped, Detail: "containers and volumes removed"}}
	stop, err := nc.Subscribe(proto.AppStopSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.AppStopCmd
		_ = json.Unmarshal(m.Data, &cmd)
		a.mu.Lock()
		a.stopCmds = append(a.stopCmds, cmd.DeleteVolumes)
		ack := proto.AppStopAck{OK: true, Status: proto.AppStatusStopped}
		if cmd.DeleteVolumes {
			ack = a.deleteAck
		}
		a.mu.Unlock()
		b, _ := json.Marshal(ack)
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatalf("stop sub: %v", err)
	}
	list, err := nc.Subscribe(proto.AppVolumesListSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.AppVolumesListCmd
		_ = json.Unmarshal(m.Data, &cmd)
		a.mu.Lock()
		a.listCalls++
		a.mu.Unlock()
		if !cmd.SkipSizes {
			t.Errorf("the delete's listing must skip sizes")
		}
		b, _ := json.Marshal(proto.AppVolumesListAck{OK: true, Volumes: vols})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatalf("list sub: %v", err)
	}
	t.Cleanup(func() { _ = stop.Unsubscribe(); _ = list.Unsubscribe() })
	return a
}

// CompareDeleteVolumes is exact both ways, and ignores other apps' volumes.
func TestCompareDeleteVolumes(t *testing.T) {
	other := proto.AppVolumeInfo{Name: proto.AppVolumeName(missingAppID, "data"), AppID: missingAppID}
	onNode := []proto.AppVolumeInfo{delVolAnon, other, delVolData}
	if err := CompareDeleteVolumes(delAppID, []string{delVolData.Name, delVolAnon.Name}, onNode); err != nil {
		t.Fatalf("exact set: %v", err)
	}
	var mm *DeleteVolumesMismatch
	err := CompareDeleteVolumes(delAppID, []string{delVolData.Name, other.Name}, onNode)
	if !errors.As(err, &mm) || len(mm.NotOfApp) != 1 || mm.NotOfApp[0] != other.Name ||
		len(mm.Unconfirmed) != 1 || mm.Unconfirmed[0].Name != delVolAnon.Name || len(mm.OnNode) != 2 {
		t.Fatalf("mismatch = %#v (%v)", mm, err)
	}
	if err := CompareDeleteVolumes(delAppID, nil, nil); err != nil {
		t.Fatalf("nothing named, nothing on node: %v", err)
	}
}
