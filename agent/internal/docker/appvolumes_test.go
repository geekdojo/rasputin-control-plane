package docker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Every volume an app ever had (geekdojo/geekdojo-brain#413), against a docker
// CLI that keeps state: containers with mounts, volumes with labels, and a
// compose `down` that behaves the way measured case 8 of app-catalog.md §8a.2
// says the real one does — `down -v` removes the volumes the current compose
// declares and nothing else. The live proof is in compose_docker_test.go.

const (
	delULID   = "01J9ZK3Q0M8X7Y6W5V4T3S2R1A" // the app being deleted
	otherULID = "01J9ZK3Q0M8X7Y6W5V4T3S2R1B" // another app on the node
)

// hex64 makes a docker-shaped anonymous volume name from a short tag.
func hex64(tag string) string {
	const digits = "0123456789abcdef"
	b := make([]byte, 64)
	for i := range b {
		b[i] = digits[(int(tag[i%len(tag)])+i)%16]
	}
	return string(b)
}

type fakeMount struct{ name, dest string }

type fakeContainer struct {
	id, project, service string
	mounts               []fakeMount
}

// fakeNode is a docker daemon in miniature.
type fakeNode struct {
	volumes    map[string]map[string]string // name → labels
	containers []*fakeContainer
	// declared is what `down -v` removes for a project: the volumes its
	// CURRENT compose declares.
	declared map[string][]string
	calls    [][]string
	removed  []string
}

func newFakeNode() *fakeNode {
	return &fakeNode{volumes: map[string]map[string]string{}, declared: map[string][]string{}}
}

func (n *fakeNode) namedVolume(appID, key string) string {
	name := proto.AppVolumeName(appID, key)
	n.volumes[name] = map[string]string{labelComposeProject: proto.AppProjectName(appID), labelComposeVolume: key}
	return name
}

func (n *fakeNode) anonVolume(tag string) string {
	name := hex64(tag)
	n.volumes[name] = map[string]string{labelAnonymousVolume: ""}
	return name
}

func (n *fakeNode) container(id, project, service string, mounts ...fakeMount) {
	n.containers = append(n.containers, &fakeContainer{id: id, project: project, service: service, mounts: mounts})
}

func (n *fakeNode) removeContainers(pred func(*fakeContainer) bool) {
	kept := n.containers[:0]
	for _, c := range n.containers {
		if !pred(c) {
			kept = append(kept, c)
		}
	}
	n.containers = kept
}

func (n *fakeNode) exists(name string) bool { _, ok := n.volumes[name]; return ok }

func (n *fakeNode) run(_ context.Context, args ...string) ([]byte, error) {
	n.calls = append(n.calls, append([]string(nil), args...))
	joined := strings.Join(args, " ")
	switch {
	case len(args) > 4 && args[0] == "compose":
		project := args[4]
		switch args[5] {
		case "down":
			n.removeContainers(func(c *fakeContainer) bool { return c.project == project })
			if len(args) > 6 && args[6] == "-v" {
				for _, v := range n.declared[project] {
					delete(n.volumes, v)
				}
			}
			return nil, nil
		case "ps":
			return nil, nil
		}
		return nil, errors.New("unexpected compose invocation: " + joined)
	case strings.HasPrefix(joined, "ps --all --quiet --no-trunc --filter label="+labelComposeProject+"="):
		project := strings.TrimPrefix(args[5], "label="+labelComposeProject+"=")
		var ids []string
		for _, c := range n.containers {
			if c.project == project {
				ids = append(ids, c.id)
			}
		}
		return []byte(strings.Join(ids, "\n")), nil
	case strings.HasPrefix(joined, "container inspect --format {{json .}} --"):
		var out strings.Builder
		for _, id := range args[4:] {
			for _, c := range n.containers {
				if c.id != id {
					continue
				}
				ci := containerInspect{Name: "/" + c.id}
				ci.Config.Labels = map[string]string{labelComposeProject: c.project, labelComposeService: c.service}
				for _, m := range c.mounts {
					ci.Mounts = append(ci.Mounts, struct {
						Type        string `json:"Type"`
						Name        string `json:"Name"`
						Destination string `json:"Destination"`
					}{"volume", m.name, m.dest})
				}
				b, _ := json.Marshal(ci)
				out.Write(b)
				out.WriteString("\n")
			}
		}
		return []byte(out.String()), nil
	case strings.HasPrefix(joined, "volume ls --quiet --filter label="):
		filter := strings.TrimPrefix(args[4], "label=")
		key, want, exact := strings.Cut(filter, "=")
		var names []string
		for name, labels := range n.volumes {
			got, ok := labels[key]
			if ok && (!exact || got == want) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		return []byte(strings.Join(names, "\n")), nil
	case strings.HasPrefix(joined, "volume inspect --format {{json .}} --"):
		var out strings.Builder
		for _, name := range args[5:] {
			labels, ok := n.volumes[name]
			if !ok {
				return []byte("Error response from daemon: get " + name + ": no such volume"), errors.New("exit status 1")
			}
			b, _ := json.Marshal(volumeInspect{Name: name, CreatedAt: "2026-09-12T10:00:00Z", Labels: labels, Mountpoint: "/var/lib/docker/volumes/" + name + "/_data"})
			out.Write(b)
			out.WriteString("\n")
		}
		return []byte(out.String()), nil
	case strings.HasPrefix(joined, "ps --all --quiet --filter volume="):
		name := strings.TrimPrefix(args[4], "volume=")
		var ids []string
		for _, c := range n.containers {
			for _, m := range c.mounts {
				if m.name == name {
					ids = append(ids, c.id)
				}
			}
		}
		return []byte(strings.Join(ids, "\n")), nil
	case strings.HasPrefix(joined, "volume rm -- "):
		name := args[3]
		if _, ok := n.volumes[name]; !ok {
			return []byte("Error: No such volume: " + name), errors.New("exit status 1")
		}
		delete(n.volumes, name)
		n.removed = append(n.removed, name)
		return nil, nil
	}
	return nil, errors.New("unexpected docker invocation: " + joined)
}

// ranVolumeRm reports whether any `docker volume rm`, or a `down -v`, was run.
func (n *fakeNode) ranVolumeRemoval() []string {
	var got []string
	for _, c := range n.calls {
		j := strings.Join(c, " ")
		if strings.HasPrefix(j, "volume rm") || strings.HasSuffix(j, " down -v") || strings.Contains(j, "volume prune") {
			got = append(got, j)
		}
	}
	return got
}

// upgradedApp is the node after an app has lived through every leak class:
//
//   - db: a named volume the current compose still declares;
//   - old-key: the volume a renamed key left behind;
//   - cache: the volume of a service the upgrade dropped (its container gone);
//   - anon: an anonymous volume the running `valkey` container mounts;
//
// plus, for the delete to leave alone, another app's named and anonymous
// volumes, an unrecorded anonymous volume nothing claims, a hand-made volume
// named like the app's but not labelled for it, and a compose `name:` volume.
type upgradedApp struct {
	node                                *fakeNode
	b                                   *ComposeBackend
	db, oldKey, cache, anon             string
	otherDB, otherAnon, stray, handMade string
	explicitName                        string
}

func newUpgradedApp(t *testing.T) *upgradedApp {
	t.Helper()
	n := newFakeNode()
	u := &upgradedApp{node: n}
	project := proto.AppProjectName(delULID)
	u.db = n.namedVolume(delULID, "db")
	u.oldKey = n.namedVolume(delULID, "old-key")
	u.cache = n.namedVolume(delULID, "cache")
	u.anon = n.anonVolume("valkey")
	n.declared[project] = []string{u.db}
	n.container("c-app", project, "app", fakeMount{u.db, "/var/lib/db"})
	n.container("c-valkey", project, "valkey", fakeMount{u.anon, "/data"})

	u.otherDB = n.namedVolume(otherULID, "db")
	u.otherAnon = n.anonVolume("other")
	n.container("c-other", proto.AppProjectName(otherULID), "web", fakeMount{u.otherDB, "/db"}, fakeMount{u.otherAnon, "/tmp"})
	u.stray = n.anonVolume("stray")
	u.handMade = proto.AppVolumeName(delULID, "hand")
	n.volumes[u.handMade] = map[string]string{labelComposeProject: "someone-else"}
	u.explicitName = "shared-by-name"
	n.volumes[u.explicitName] = map[string]string{labelComposeProject: project, labelComposeVolume: "shared"}

	u.b = &ComposeBackend{dir: t.TempDir(), exec: n.run, sizeOf: func(string) (uint64, error) { return 42, nil }}
	if err := os.MkdirAll(u.b.appDir(delULID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(u.b.composePath(delULID), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return u
}

func (u *upgradedApp) all() []string {
	return []string{u.db, u.oldKey, u.cache, u.anon, u.otherDB, u.otherAnon, u.stray, u.handMade, u.explicitName}
}

// The owner's checkbox left unticked: the uninstall removes NO volume of any
// class — not the declared one, not the renamed-away or dropped ones, and not
// the anonymous one — and runs nothing that could.
func TestStopKeepingData_RemovesNoVolumeOfAnyClass(t *testing.T) {
	u := newUpgradedApp(t)
	status, detail, err := u.b.Stop(context.Background(), delULID, false)
	if err != nil || status != proto.AppStatusStopped {
		t.Fatalf("Stop = %s %q %v", status, detail, err)
	}
	if got := u.node.ranVolumeRemoval(); len(got) != 0 {
		t.Fatalf("a keep-data stop ran a volume removal: %v", got)
	}
	for _, v := range u.all() {
		if !u.node.exists(v) {
			t.Errorf("volume %s is gone after a keep-data stop", v)
		}
	}
	// And it kept the record the reaper will need for the anonymous one.
	rec, err := u.b.loadRecord(delULID)
	if err != nil || len(rec.Anonymous) != 1 || rec.Anonymous[0].Name != u.anon ||
		rec.Anonymous[0].Service != "valkey" || rec.Anonymous[0].Path != "/data" {
		t.Fatalf("record after keep-data stop: %+v %v", rec, err)
	}
}

// The checkbox ticked: every volume the app ever had goes — declared,
// renamed-away, dropped and anonymous — and nothing that is not the app's.
func TestStopDeletingData_RemovesEveryVolumeTheAppEverHad(t *testing.T) {
	u := newUpgradedApp(t)
	status, detail, err := u.b.Stop(context.Background(), delULID, true)
	if err != nil || status != proto.AppStatusStopped {
		t.Fatalf("Stop = %s %q %v", status, detail, err)
	}
	for _, gone := range []string{u.db, u.oldKey, u.cache, u.anon} {
		if u.node.exists(gone) {
			t.Errorf("%s survived a delete with data", gone)
		}
	}
	for _, kept := range []string{u.otherDB, u.otherAnon, u.stray, u.handMade, u.explicitName} {
		if !u.node.exists(kept) {
			t.Errorf("%s is not this app's and was removed", kept)
		}
	}
	for _, name := range []string{u.oldKey, u.cache, u.anon} {
		if !strings.Contains(detail, name) {
			t.Errorf("detail %q does not name %s, which down -v could not see", detail, name)
		}
	}
	if _, err := os.Stat(u.b.appDir(delULID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the app's state directory survived a clean delete (stat err %v)", err)
	}
}

// The hazard #413 was redesigned around: app.stop runs `down`, so by the time
// app.delete runs, no container names the anonymous volume. It must still go.
func TestStopThenDeleteWithData_AnonymousVolumeStillRemoved(t *testing.T) {
	u := newUpgradedApp(t)
	if _, _, err := u.b.Stop(context.Background(), delULID, false); err != nil {
		t.Fatal(err)
	}
	if !u.node.exists(u.anon) {
		t.Fatal("a plain stop removed the anonymous volume")
	}
	if _, detail, err := u.b.Stop(context.Background(), delULID, true); err != nil {
		t.Fatalf("delete after stop: %q %v", detail, err)
	}
	for _, gone := range []string{u.db, u.oldKey, u.cache, u.anon} {
		if u.node.exists(gone) {
			t.Errorf("%s survived stop-then-delete", gone)
		}
	}
	if !u.node.exists(u.stray) || !u.node.exists(u.otherAnon) {
		t.Error("an anonymous volume that is not this app's was removed")
	}
}

// A volume of the app that a container OUTSIDE the app still references is
// refused, the stop fails naming it, and the record and state stay so a retry
// or the reaper can still find it.
func TestStopDeletingData_RefusesAVolumeReferencedOutsideTheApp(t *testing.T) {
	u := newUpgradedApp(t)
	u.node.container("c-intruder", "someproj", "x", fakeMount{u.anon, "/stolen"}, fakeMount{u.oldKey, "/old"})
	status, detail, err := u.b.Stop(context.Background(), delULID, true)
	if err == nil {
		t.Fatalf("a delete that left volumes behind reported success: %s %q", status, detail)
	}
	if !u.node.exists(u.anon) || !u.node.exists(u.oldKey) {
		t.Fatal("a volume another container references was removed")
	}
	if u.node.exists(u.cache) {
		t.Error("an unreferenced volume should still have been removed")
	}
	for _, want := range []string{"NOT deleted", u.anon, u.oldKey, "still referenced", "c-intruder"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q does not mention %q", detail, want)
		}
	}
	rec, rerr := u.b.loadRecord(delULID)
	if rerr != nil || len(rec.Anonymous) != 1 || rec.Anonymous[0].Name != u.anon {
		t.Errorf("the refused anonymous volume left the record: %+v %v", rec, rerr)
	}
}

// Two apps' records naming one anonymous volume (a custom compose mounting it
// as external) make it nobody's to delete.
func TestStopDeletingData_RefusesAnAnonymousVolumeTwoAppsRecorded(t *testing.T) {
	u := newUpgradedApp(t)
	if err := u.b.saveRecord(otherULID, &volumeRecord{AppID: otherULID, Anonymous: []recordedVolume{{Name: u.anon}}}); err != nil {
		t.Fatal(err)
	}
	_, detail, err := u.b.Stop(context.Background(), delULID, true)
	if err == nil || !u.node.exists(u.anon) || !strings.Contains(detail, "more than one app") {
		t.Fatalf("Stop = %q %v; anon exists=%v", detail, err, u.node.exists(u.anon))
	}
}

// A retried delete — the state directory already gone — succeeds and removes
// nothing it should not; with the compose missing but the volumes present, the
// labels and record still find them.
func TestStopDeletingData_WithoutComposeFile(t *testing.T) {
	t.Run("nothing left", func(t *testing.T) {
		n := newFakeNode()
		b := &ComposeBackend{dir: t.TempDir(), exec: n.run}
		status, detail, err := b.Stop(context.Background(), delULID, true)
		if err != nil || status != proto.AppStatusStopped {
			t.Fatalf("Stop = %s %q %v", status, detail, err)
		}
		if len(n.removed) != 0 {
			t.Errorf("removed %v", n.removed)
		}
	})
	t.Run("compose gone, volumes and record present", func(t *testing.T) {
		u := newUpgradedApp(t)
		if _, _, err := u.b.Stop(context.Background(), delULID, false); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(u.b.composePath(delULID)); err != nil {
			t.Fatal(err)
		}
		_, detail, err := u.b.Stop(context.Background(), delULID, true)
		if err != nil {
			t.Fatalf("Stop: %q %v", detail, err)
		}
		for _, gone := range []string{u.db, u.oldKey, u.cache, u.anon} {
			if u.node.exists(gone) {
				t.Errorf("%s survived", gone)
			}
		}
		if !strings.Contains(detail, "no compose file") {
			t.Errorf("detail %q should say the compose file was missing", detail)
		}
	})
}

// The id names a directory Stop can now remove, and it arrives off the bus.
func TestStopRefusesAnAppIDThatIsNotOnePathElement(t *testing.T) {
	for _, id := range []string{"", ".", "..", "../escape", "a/b"} {
		n := newFakeNode()
		root := t.TempDir()
		b := &ComposeBackend{dir: root + "/apps", exec: n.run}
		if _, _, err := b.Stop(context.Background(), id, true); err == nil {
			t.Errorf("app id %q: want a refusal", id)
		}
		if len(n.calls) != 0 {
			t.Errorf("app id %q: docker was invoked: %v", id, n.calls)
		}
		if _, err := os.Stat(root); err != nil {
			t.Errorf("app id %q: the state root's parent was touched: %v", id, err)
		}
	}
}

// The record is a union across compose versions: an anonymous volume whose
// service an upgrade dropped stays in it after the container is gone.
func TestDeploy_RecordIsAUnionAcrossComposeVersions(t *testing.T) {
	n := newFakeNode()
	project := proto.AppProjectName(delULID)
	v1Anon := n.anonVolume("v1")
	n.container("c-old", project, "worker", fakeMount{v1Anon, "/scratch"})
	b := &ComposeBackend{dir: t.TempDir(), exec: func(ctx context.Context, args ...string) ([]byte, error) {
		// `up` of v2: the worker service is dropped (--remove-orphans) and
		// a new service mounts a fresh anonymous volume.
		if len(args) > 5 && args[0] == "compose" && args[5] == "up" {
			n.removeContainers(func(c *fakeContainer) bool { return c.id == "c-old" })
			v2Anon := n.anonVolume("v2")
			n.container("c-new", project, "cache", fakeMount{v2Anon, "/data"})
			return nil, nil
		}
		return n.run(ctx, args...)
	}}
	if _, _, err := b.Deploy(context.Background(), delULID, "app", "services: {}\n"); err != nil {
		t.Fatal(err)
	}
	rec, err := b.loadRecord(delULID)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, v := range rec.Anonymous {
		names = append(names, v.Name)
	}
	sort.Strings(names)
	want := []string{v1Anon, hex64("v2")}
	sort.Strings(want)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("record = %v, want both compose versions' anonymous volumes %v", names, want)
	}
	for _, v := range rec.Anonymous {
		if v.FirstSeen.IsZero() {
			t.Errorf("%s has no firstSeen", v.Name)
		}
	}
}

// Only what docker itself calls anonymous is recorded: a named volume, another
// project's volume mounted as external, and a hex-named volume that is not
// labelled anonymous are all left out.
func TestRecord_OnlyDockerAnonymousVolumes(t *testing.T) {
	n := newFakeNode()
	project := proto.AppProjectName(delULID)
	named := n.namedVolume(delULID, "data")
	foreign := n.namedVolume(otherULID, "data")
	hexNotAnon := hex64("labelled")
	n.volumes[hexNotAnon] = map[string]string{labelComposeProject: "elsewhere"}
	anon := n.anonVolume("real")
	n.container("c1", project, "app", fakeMount{named, "/a"}, fakeMount{foreign, "/b"}, fakeMount{hexNotAnon, "/c"}, fakeMount{anon, "/d"})
	b := &ComposeBackend{dir: t.TempDir(), exec: n.run}
	if err := b.recordVolumes(context.Background(), delULID); err != nil {
		t.Fatal(err)
	}
	rec, _ := b.loadRecord(delULID)
	if len(rec.Anonymous) != 1 || rec.Anonymous[0].Name != anon {
		t.Fatalf("record = %+v, want only %s", rec.Anonymous, anon)
	}
}

// After a keep-data delete, every kept volume — anonymous included — is in the
// orphan listing, with an identity the reclaim can act on.
func TestListProjectVolumes_ListsKeptAnonymousVolumes(t *testing.T) {
	u := newUpgradedApp(t)
	if _, _, err := u.b.Stop(context.Background(), delULID, false); err != nil {
		t.Fatal(err)
	}
	vols, err := u.b.ListProjectVolumes(context.Background(), proto.AppVolumesListCmd{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]proto.AppVolumeInfo{}
	for _, v := range vols {
		got[v.Name] = v
	}
	for _, kept := range []string{u.db, u.oldKey, u.cache, u.anon} {
		v, ok := got[kept]
		if !ok {
			t.Errorf("kept volume %s is not listed", kept)
			continue
		}
		if v.AppID != delULID {
			t.Errorf("%s listed for app %q", kept, v.AppID)
		}
	}
	a := got[u.anon]
	if !a.Anonymous || a.Volume != "" || a.Service != "valkey" || a.Path != "/data" || a.SizeBytes != 42 || a.InUse {
		t.Errorf("anonymous listing: %+v", a)
	}
	// Nothing claims the stray, and the other app's anonymous volume was
	// never recorded here (it was never deployed through this agent).
	for _, absent := range []string{u.stray, u.otherAnon, u.handMade, u.explicitName} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s must not be listed", absent)
		}
	}

	// SkipSizes leaves sizes out and changes nothing else.
	quick, err := u.b.ListProjectVolumes(context.Background(), proto.AppVolumesListCmd{SkipSizes: true})
	if err != nil || len(quick) != len(vols) {
		t.Fatalf("SkipSizes listing: %d vs %d, %v", len(quick), len(vols), err)
	}
	for _, v := range quick {
		if v.SizeBytes != 0 {
			t.Errorf("SkipSizes: %s sized %d", v.Name, v.SizeBytes)
		}
	}
}

// A recorded volume two records claim, or one docker no longer labels
// anonymous, or one docker no longer has, is not listed.
func TestListProjectVolumes_AnonymousNeedsOneOwnerAndDockersWord(t *testing.T) {
	n := newFakeNode()
	shared := n.anonVolume("shared")
	relabelled := hex64("relabel")
	n.volumes[relabelled] = map[string]string{labelComposeProject: "x"}
	missing := hex64("missing")
	b := &ComposeBackend{dir: t.TempDir(), exec: n.run, sizeOf: func(string) (uint64, error) { return 0, nil }}
	for _, id := range []string{delULID, otherULID} {
		_ = b.saveRecord(id, &volumeRecord{AppID: id, Anonymous: []recordedVolume{{Name: shared}}})
	}
	third := "01J9ZK3Q0M8X7Y6W5V4T3S2R1C"
	_ = b.saveRecord(third, &volumeRecord{AppID: third, Anonymous: []recordedVolume{{Name: relabelled}, {Name: missing}}})
	// A directory that is not an app id, and a record claiming another app,
	// are not owners.
	_ = b.saveRecord("not-a-ulid", &volumeRecord{AppID: "not-a-ulid", Anonymous: []recordedVolume{{Name: n.anonVolume("dir")}}})
	liar := "01J9ZK3Q0M8X7Y6W5V4T3S2R1D"
	_ = b.saveRecord(liar, &volumeRecord{AppID: delULID, Anonymous: []recordedVolume{{Name: n.anonVolume("liar")}}})

	vols, err := b.ListProjectVolumes(context.Background(), proto.AppVolumesListCmd{})
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 0 {
		t.Fatalf("listed %+v, want nothing", vols)
	}
}

// The reclaim of an anonymous volume: every refusal by name, and the one clean
// case removed and dropped from its app's record.
func TestRemoveProjectVolumes_AnonymousRefusals(t *testing.T) {
	n := newFakeNode()
	b := &ComposeBackend{dir: t.TempDir(), exec: n.run}
	clean := n.anonVolume("clean")
	liveOwned := n.anonVolume("live")
	busy := n.anonVolume("busy")
	n.container("c-busy", "someproj", "x", fakeMount{busy, "/x"})
	unrecorded := n.anonVolume("unrecorded")
	shared := n.anonVolume("shared")
	notAnon := hex64("notanon")
	n.volumes[notAnon] = map[string]string{labelComposeProject: proto.AppProjectName(delULID)}
	gone := hex64("gone")
	const liveApp = "01J9ZK3Q0M8X7Y6W5V4T3S2R1E"
	_ = b.saveRecord(delULID, &volumeRecord{AppID: delULID, Anonymous: []recordedVolume{{Name: clean}, {Name: busy}, {Name: shared}, {Name: notAnon}, {Name: gone}}})
	_ = b.saveRecord(liveApp, &volumeRecord{AppID: liveApp, Anonymous: []recordedVolume{{Name: liveOwned}}})
	_ = b.saveRecord(otherULID, &volumeRecord{AppID: otherULID, Anonymous: []recordedVolume{{Name: shared}}})

	ack := b.RemoveProjectVolumes(context.Background(), proto.AppVolumesRemoveCmd{
		Names:      []string{clean, liveOwned, busy, unrecorded, shared, notAnon, gone},
		LiveAppIDs: []string{strings.ToLower(liveApp)},
	})
	if !ack.OK {
		t.Fatalf("ack not OK: %+v", ack)
	}
	if len(ack.Removed) != 1 || ack.Removed[0] != clean || len(n.removed) != 1 {
		t.Fatalf("removed %v (docker: %v), want only %s", ack.Removed, n.removed, clean)
	}
	reasons := map[string]string{}
	for _, r := range ack.Refused {
		reasons[r.Name] = r.Reason
	}
	expect := map[string]string{
		liveOwned:  "still installed",
		busy:       "still referenced by 1 container",
		unrecorded: "no app's volume record",
		shared:     "more than one app",
		notAnon:    "not an anonymous volume",
		gone:       "no such volume",
	}
	if len(reasons) != len(expect) {
		t.Fatalf("refused %d, want %d: %+v", len(reasons), len(expect), ack.Refused)
	}
	for name, frag := range expect {
		if !strings.Contains(reasons[name], frag) {
			t.Errorf("%s: reason %q, want it to mention %q", name, reasons[name], frag)
		}
	}
	rec, _ := b.loadRecord(delULID)
	for _, v := range rec.Anonymous {
		if v.Name == clean {
			t.Error("the reclaimed volume is still in its app's record")
		}
	}
	if len(rec.Anonymous) != 4 {
		t.Errorf("record = %+v, want the four unremoved volumes kept", rec.Anonymous)
	}
}

// A named volume can never be removed by being passed to the delete sweep as
// if it were anonymous: gateAndRemove checks docker's labels, not the caller.
func TestGateAndRemove_NamedVolumeIsNotAnonymous(t *testing.T) {
	n := newFakeNode()
	b := &ComposeBackend{dir: t.TempDir(), exec: n.run}
	named := n.namedVolume(delULID, "data")
	if res := b.gateAndRemove(context.Background(), n.run, named, delULID, true); res.removed {
		t.Fatal("a named volume passed the anonymous gate")
	}
	if !n.exists(named) {
		t.Fatal("removed")
	}
}

func TestIsDockerAnonymous(t *testing.T) {
	cases := []struct {
		name string
		v    volumeInspect
		want bool
	}{
		{"docker's anonymous volume", volumeInspect{Name: hex64("a"), Labels: map[string]string{labelAnonymousVolume: ""}}, true},
		{"no anonymous label (an engine that does not set it, or made by hand)", volumeInspect{Name: hex64("a"), Labels: map[string]string{}}, false},
		{"labelled for a project too", volumeInspect{Name: hex64("a"), Labels: map[string]string{labelAnonymousVolume: "", labelComposeProject: "p"}}, false},
		{"not hex-shaped", volumeInspect{Name: "rasp_x_data", Labels: map[string]string{labelAnonymousVolume: ""}}, false},
	}
	for _, tc := range cases {
		if got := isDockerAnonymous(tc.v); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
