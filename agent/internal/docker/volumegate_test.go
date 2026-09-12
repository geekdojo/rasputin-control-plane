package docker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The dropped-volume gate's node half (geekdojo/geekdojo-brain#412), against
// the stateful fake daemon appvolumes_test.go builds, with `compose config
// --volumes` answered per compose text — what compose itself would print for
// it. The live proof is in compose_docker_test.go.

const (
	gateV1  = "services: {app: {image: x, volumes: [data:/data]}}\n# v1\n"
	gateV2  = "services: {app: {image: x, volumes: [data2:/data]}}\n# v2 renames data\n"
	gateBad = "services: {app: {volumes: [nope:/x]}}\n# undeclared volume\n"
)

// gateNode is a fakeNode plus compose's reading of each compose text.
type gateNode struct {
	*fakeNode
	keys map[string]string // compose text → `config --volumes` output
	// configPaths is every compose file `config` was run against.
	configPaths []string
}

func newGateNode() *gateNode {
	return &gateNode{fakeNode: newFakeNode(), keys: map[string]string{
		gateV1: "data\n",
		// Compose prints keys in map order, and the run merges stderr in.
		gateV2: "time=\"2026-09-12T15:14:10-07:00\" level=warning msg=\"The \\\"TAG\\\" variable is not set.\"\ndata2\ncache\n",
	}}
}

func (g *gateNode) run(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) == 7 && args[0] == "compose" && args[5] == "config" && args[6] == "--volumes" {
		g.calls = append(g.calls, append([]string(nil), args...))
		g.configPaths = append(g.configPaths, args[2])
		b, err := os.ReadFile(args[2])
		if err != nil {
			return []byte("open " + args[2] + ": no such file"), errors.New("exit status 1")
		}
		out, ok := g.keys[string(b)]
		if !ok {
			return []byte(`service "app" refers to undefined volume nope: invalid compose project`), errors.New("exit status 1")
		}
		return []byte(out), nil
	}
	return g.fakeNode.run(ctx, args...)
}

// gateApp is delULID deployed with gateV1 on a node that also holds another
// app's volume, a `name:` volume labelled for the project, and a hand-made
// volume named like the app's but labelled for someone else.
func gateApp(t *testing.T) (*gateNode, *ComposeBackend) {
	t.Helper()
	g := newGateNode()
	g.namedVolume(delULID, "data")
	g.namedVolume(delULID, "cache")
	g.namedVolume(otherULID, "old")
	g.volumes["shared-by-name"] = map[string]string{labelComposeProject: proto.AppProjectName(delULID), labelComposeVolume: "shared"}
	g.volumes[proto.AppVolumeName(delULID, "hand")] = map[string]string{labelComposeProject: "someone-else"}
	b := &ComposeBackend{dir: t.TempDir(), exec: g.run}
	if err := os.MkdirAll(b.appDir(delULID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.composePath(delULID), []byte(gateV1), 0o644); err != nil {
		t.Fatal(err)
	}
	return g, b
}

func droppedNames(d []proto.AppDroppedVolume) []string {
	out := make([]string, 0, len(d))
	for _, v := range d {
		out = append(out, v.Name+"="+v.Volume)
	}
	return out
}

func TestParseVolumeKeys_TakesOnlyWholeKeys(t *testing.T) {
	out := []byte("WARN[0000] /x/docker-compose.yml: the attribute `version` is obsolete\nb.vol\n\n a-vol \nlevel=warning msg=\"x\"\nb.vol\nA_1\n")
	if got := strings.Join(parseVolumeKeys(out), ","); got != "A_1,a-vol,b.vol" {
		t.Errorf("keys = %s", got)
	}
}

// Case 3 of §8a.2: the key renamed. The old volume is dropped, named by its
// full name and its key; the one the compose declares is not; nothing of
// another app's, and no volume the project label and the name disagree on, is
// reported. The staged compose is gone afterwards and the live one untouched.
func TestCheckVolumes_ARenamedKeyIsDropped(t *testing.T) {
	g, b := gateApp(t)
	g.keys[gateV2] = "data2\n"
	declared, dropped, err := b.CheckVolumes(context.Background(), delULID, gateV2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(declared, ",") != "data2" {
		t.Errorf("declared = %v", declared)
	}
	want := []string{proto.AppVolumeName(delULID, "cache") + "=cache", proto.AppVolumeName(delULID, "data") + "=data"}
	if got := droppedNames(dropped); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("dropped = %v, want %v", got, want)
	}
	if len(g.configPaths) != 1 || filepath.Dir(g.configPaths[0]) != b.appDir(delULID) || g.configPaths[0] == b.composePath(delULID) {
		t.Errorf("config ran against %v, want one staged file beside the live compose", g.configPaths)
	}
	if _, err := os.Stat(g.configPaths[0]); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staged compose was left behind (%v)", err)
	}
	if live, _ := os.ReadFile(b.composePath(delULID)); string(live) != gateV1 {
		t.Errorf("the live compose was written: %q", live)
	}
	for _, c := range g.calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, " up") || strings.Contains(j, " pull") || strings.HasPrefix(j, "volume rm") {
			t.Errorf("a check ran %q", j)
		}
	}
}

// Merged stderr is not a key, and a key only added drops nothing.
func TestCheckVolumes_AnAddedVolumeDropsNothing(t *testing.T) {
	g, b := gateApp(t)
	g.keys[gateV2] = "level=warning msg=\"unset\"\ndata\ncache\nextra\n"
	declared, dropped, err := b.CheckVolumes(context.Background(), delULID, gateV2)
	if err != nil || len(dropped) != 0 {
		t.Fatalf("dropped = %v, err %v", dropped, err)
	}
	if strings.Join(declared, ",") != "cache,data,extra" {
		t.Errorf("declared = %v", declared)
	}
}

// A compose that compose cannot read is an error, never an empty declaration — an
// empty one would report every volume dropped, and a check that cannot run
// must not read as an answer.
func TestCheckVolumes_AnUnreadableComposeIsAnError(t *testing.T) {
	_, b := gateApp(t)
	if _, _, err := b.CheckVolumes(context.Background(), delULID, gateBad); err == nil || !strings.Contains(err.Error(), "undefined volume") {
		t.Fatalf("err = %v, want compose's own complaint", err)
	}
	if _, _, err := b.CheckVolumes(context.Background(), "../etc", gateV1); err == nil {
		t.Fatal("a path-like app id was accepted")
	}
}

// The owner's deleteVolumes after a successful `up`: exactly the named
// volumes go, through the shared gates.
func TestDropAppVolumes_RemovesExactlyTheNamedDroppedVolumes(t *testing.T) {
	g, b := gateApp(t)
	g.keys[gateV2] = "data2\n"
	// The `up` wrote v2; the new volume exists.
	if err := os.WriteFile(b.composePath(delULID), []byte(gateV2), 0o644); err != nil {
		t.Fatal(err)
	}
	g.namedVolume(delULID, "data2")
	old := proto.AppVolumeName(delULID, "data")

	ack := b.DropAppVolumes(context.Background(), proto.AppVolumesDropCmd{AppID: delULID, Names: []string{old}})
	if !ack.OK || len(ack.Refused) != 0 || strings.Join(ack.Removed, ",") != old {
		t.Fatalf("ack = %+v", ack)
	}
	for _, keep := range []string{proto.AppVolumeName(delULID, "data2"), proto.AppVolumeName(delULID, "cache"), proto.AppVolumeName(otherULID, "old")} {
		if !g.exists(keep) {
			t.Errorf("%s was removed", keep)
		}
	}
	// A retry finds it gone and says so, without refusing.
	ack = b.DropAppVolumes(context.Background(), proto.AppVolumesDropCmd{AppID: delULID, Names: []string{old}})
	if !ack.OK || len(ack.Refused) != 0 || len(ack.Removed) != 0 || !strings.Contains(ack.Detail, old) {
		t.Fatalf("retry ack = %+v", ack)
	}
}

// Never a volume the live compose still declares, another app's, an anonymous
// one, one docker labels for someone else, or one a container still mounts.
func TestDropAppVolumes_RefusesByName(t *testing.T) {
	g, b := gateApp(t)
	g.keys[gateV1] = "data\n"
	anon := g.anonVolume("a")
	cache := proto.AppVolumeName(delULID, "cache")
	g.container("c-stray", "elsewhere", "x", fakeMount{cache, "/c"})
	names := []string{
		proto.AppVolumeName(delULID, "data"), // still declared
		proto.AppVolumeName(otherULID, "old"),
		anon,
		proto.AppVolumeName(delULID, "hand"),
		cache,
		"shared-by-name",
	}
	ack := b.DropAppVolumes(context.Background(), proto.AppVolumesDropCmd{AppID: delULID, Names: names})
	if len(ack.Removed) != 0 || len(ack.Refused) != len(names) {
		t.Fatalf("ack = %+v", ack)
	}
	reasons := map[string]string{}
	for _, r := range ack.Refused {
		reasons[r.Name] = r.Reason
	}
	for name, want := range map[string]string{
		names[0]: "still declares", names[1]: "not of this app", names[2]: "anonymous",
		names[3]: "not a volume of compose project", names[4]: "still referenced", names[5]: "not a named volume of this app",
	} {
		if !strings.Contains(reasons[name], want) {
			t.Errorf("%s: reason %q, want it to say %q", name, reasons[name], want)
		}
	}
	if got := g.ranVolumeRemoval(); len(got) != 0 {
		t.Errorf("a refused drop ran %v", got)
	}
}

// Without a readable live compose, what it declares cannot be proved, so
// nothing is removed.
func TestDropAppVolumes_RefusesEverythingWithoutALiveCompose(t *testing.T) {
	g, b := gateApp(t)
	old := proto.AppVolumeName(delULID, "data")
	if err := os.WriteFile(b.composePath(delULID), []byte(gateBad), 0o644); err != nil {
		t.Fatal(err)
	}
	if ack := b.DropAppVolumes(context.Background(), proto.AppVolumesDropCmd{AppID: delULID, Names: []string{old}}); len(ack.Removed) != 0 || len(ack.Refused) != 1 {
		t.Fatalf("unreadable compose: %+v", ack)
	}
	if err := os.Remove(b.composePath(delULID)); err != nil {
		t.Fatal(err)
	}
	if ack := b.DropAppVolumes(context.Background(), proto.AppVolumesDropCmd{AppID: delULID, Names: []string{old}}); len(ack.Removed) != 0 || len(ack.Refused) != 1 || !strings.Contains(ack.Refused[0].Reason, "no compose file") {
		t.Fatalf("missing compose: %+v", ack)
	}
	if !g.exists(old) || len(g.ranVolumeRemoval()) != 0 {
		t.Error("a volume was removed without the live compose")
	}
}

// Both verbs answer on the bus; the check answers for the mock too, which has
// no volumes and so drops nothing, while drop stays a compose-backend verb.
func TestRegisterHandlers_VolumeGateVerbs(t *testing.T) {
	nc, _ := newRegistered(t)
	var mock proto.AppVolumesCheckAck
	request(t, nc, proto.AppVolumesCheckSubject("node-1"), proto.AppVolumesCheckCmd{AppID: delULID, ComposeYAML: gateV1}, &mock)
	if !mock.OK || mock.Dropped == nil || len(mock.Dropped) != 0 {
		t.Fatalf("mock check = %+v", mock)
	}
	if _, err := nc.Request(proto.AppVolumesDropSubject("node-1"), []byte(`{}`), 300*time.Millisecond); err == nil {
		t.Fatal("the mock backend must not answer docker.volumes.drop")
	}

	g, b := gateApp(t)
	g.keys[gateV2] = "data2\n"
	nc2 := startNATS(t)
	subs, err := RegisterHandlers(nc2, "node-2", b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	var check proto.AppVolumesCheckAck
	request(t, nc2, proto.AppVolumesCheckSubject("node-2"), proto.AppVolumesCheckCmd{AppID: delULID, ComposeYAML: gateV2}, &check)
	if !check.OK || len(check.Dropped) != 2 {
		t.Fatalf("check = %+v", check)
	}
	request(t, nc2, proto.AppVolumesCheckSubject("node-2"), proto.AppVolumesCheckCmd{AppID: delULID, ComposeYAML: gateBad}, &check)
	if check.OK || !strings.Contains(check.Detail, "undefined volume") {
		t.Fatalf("bad compose check = %+v", check)
	}
	var drop proto.AppVolumesRemoveAck
	request(t, nc2, proto.AppVolumesDropSubject("node-2"), proto.AppVolumesDropCmd{AppID: delULID, Names: []string{proto.AppVolumeName(delULID, "cache")}}, &drop)
	if len(drop.Removed) != 1 {
		t.Fatalf("drop = %+v", drop)
	}
	for _, subj := range []string{proto.AppVolumesCheckSubject("node-2"), proto.AppVolumesDropSubject("node-2")} {
		msg, err := nc2.Request(subj, []byte("nope"), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(msg.Data), `"ok":false`) {
			t.Errorf("%s: bad JSON answered %s", subj, msg.Data)
		}
	}
}
