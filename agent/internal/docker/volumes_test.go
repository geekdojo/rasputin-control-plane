package docker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The orphan-volume verbs, exercised against a scripted docker CLI. What is
// being pinned is the refusal surface: the only volumes that can ever be
// removed through this verb are compose-labelled rasp_<ulid>_<volume> ones
// that no ledger row and no container still claims.

const (
	orphanULID = "01J6ZK3Q9V8XKX2M5TQ7R4A9BE" // no app — reclaimable
	liveULID   = "01J6ZK3Q9V8XKX2M5TQ7R4A9BF" // in the ledger
	handULID   = "01J6ZK3Q9V8XKX2M5TQ7R4A9BG" // named like ours, not labelled like ours
)

var (
	orphanDB     = proto.AppVolumeName(orphanULID, "immich-db")
	orphanUpload = proto.AppVolumeName(orphanULID, "immich-upload")
	liveData     = proto.AppVolumeName(liveULID, "vaultwarden-data")
	handMade     = proto.AppVolumeName(handULID, "data")
	inUseVol     = proto.AppVolumeName(orphanULID, "busy")
)

// fakeDocker scripts the four docker invocations volumes.go makes and records
// every `volume rm` it is asked for.
type fakeDocker struct {
	// labels is the compose project label docker reports for each volume;
	// absent means docker knows no such volume.
	labels map[string]string
	// users is the container ids referencing each volume.
	users map[string][]string
	// lsNames is what `volume ls` prints — includes non-rasp names so the
	// prefix filter is exercised.
	lsNames []string
	removed []string
	rmErr   error
}

func (f *fakeDocker) run(_ context.Context, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	switch {
	case strings.HasPrefix(joined, "volume ls"):
		return []byte(strings.Join(f.lsNames, "\n") + "\n"), nil
	case strings.HasPrefix(joined, "volume inspect"):
		if args[4] != "--" {
			return nil, errors.New("volume inspect: free operands must follow --")
		}
		names := args[5:]
		var out strings.Builder
		for _, n := range names {
			label, ok := f.labels[n]
			if !ok {
				return []byte("Error response from daemon: get " + n + ": no such volume"), errors.New("exit status 1")
			}
			v := volumeInspect{
				Name:       n,
				CreatedAt:  "2026-08-23T10:00:00Z",
				Labels:     map[string]string{labelComposeProject: label, labelComposeVolume: "x"},
				Mountpoint: "/var/lib/docker/volumes/" + n + "/_data",
			}
			b, _ := json.Marshal(v)
			out.Write(b)
			out.WriteString("\n")
		}
		return []byte(out.String()), nil
	case strings.HasPrefix(joined, "ps --all --quiet --filter volume="):
		name := strings.TrimPrefix(args[4], "volume=")
		return []byte(strings.Join(f.users[name], "\n")), nil
	case strings.HasPrefix(joined, "volume rm "):
		if args[2] != "--" {
			return nil, errors.New("volume rm: the name must follow --")
		}
		if f.rmErr != nil {
			return []byte("Error response from daemon: boom"), f.rmErr
		}
		f.removed = append(f.removed, args[3])
		return nil, nil
	}
	return nil, errors.New("unexpected docker invocation: " + joined)
}

func newFakeBackend(t *testing.T, f *fakeDocker) *ComposeBackend {
	t.Helper()
	return &ComposeBackend{
		dir:  t.TempDir(),
		exec: f.run,
		sizeOf: func(mp string) (uint64, error) {
			if strings.Contains(mp, "immich-upload") {
				return 7 << 30, nil
			}
			return 1024, nil
		},
	}
}

func scriptedDocker() *fakeDocker {
	return &fakeDocker{
		lsNames: []string{
			orphanDB, orphanUpload, liveData, handMade, inUseVol,
			"myproj_data",  // another compose project entirely
			"rasp_abc_bad", // our prefix, not a ULID
		},
		labels: map[string]string{
			orphanDB:      proto.AppProjectName(orphanULID),
			orphanUpload:  proto.AppProjectName(orphanULID),
			liveData:      proto.AppProjectName(liveULID),
			inUseVol:      proto.AppProjectName(orphanULID),
			handMade:      "someone-elses-project", // name says ours, label says not
			"myproj_data": "myproj",
		},
		users: map[string][]string{
			inUseVol: {"3f1a9b2c4d5e"},
		},
	}
}

// The enumerator lists ONLY rasp_-prefixed, ULID-shaped, compose-labelled
// project volumes. It does not know the ledger — the api applies that — so a
// live app's volume IS listed; what must never appear is anything outside the
// namespace, or a name that docker's own labels contradict.
func TestListProjectVolumes_OnlyLabelledProjectVolumes(t *testing.T) {
	f := scriptedDocker()
	b := newFakeBackend(t, f)
	vols, err := b.ListProjectVolumes(context.Background())
	if err != nil {
		t.Fatalf("ListProjectVolumes: %v", err)
	}
	got := map[string]proto.AppVolumeInfo{}
	for _, v := range vols {
		got[v.Name] = v
	}
	for _, want := range []string{orphanDB, orphanUpload, liveData, inUseVol} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	for _, absent := range []string{handMade, "myproj_data", "rasp_abc_bad"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s must not be listed", absent)
		}
	}
	if len(vols) != 4 {
		t.Errorf("listed %d volumes, want 4: %+v", len(vols), vols)
	}
	up := got[orphanUpload]
	if up.AppID != orphanULID || up.Volume != "immich-upload" {
		t.Errorf("parsed identity: %+v", up)
	}
	if up.SizeBytes != 7<<30 {
		t.Errorf("size: %d", up.SizeBytes)
	}
	if !up.CreatedAt.Equal(time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("createdAt: %s", up.CreatedAt)
	}
	if up.InUse {
		t.Error("immich-upload has no containers; InUse must be false")
	}
	if !got[inUseVol].InUse {
		t.Error("busy volume has a container; InUse must be true")
	}
}

// The remove verb's refusal rules, one case each. The ack must account for
// every name it was sent, and nothing but the one clean orphan may reach
// `docker volume rm`.
func TestRemoveProjectVolumes_Refusals(t *testing.T) {
	f := scriptedDocker()
	b := newFakeBackend(t, f)
	ack := b.RemoveProjectVolumes(context.Background(), proto.AppVolumesRemoveCmd{
		Names: []string{
			orphanDB,       // clean orphan — removed
			liveData,       // in the ledger — refused
			"myproj_data",  // outside the prefix — refused
			"rasp_abc_bad", // malformed — refused
			handMade,       // label disagrees — refused
			inUseVol,       // container references it — refused
			proto.AppVolumeName(orphanULID, "nothere"), // docker has no such volume — refused
		},
		// Lower-cased on purpose: the ledger holds upper, compose writes
		// lower, and the gate must not care which it is handed.
		LiveAppIDs: []string{strings.ToLower(liveULID)},
	})
	if !ack.OK {
		t.Fatalf("ack not OK: %+v", ack)
	}
	if len(ack.Removed) != 1 || ack.Removed[0] != orphanDB {
		t.Fatalf("removed: %v, want only %s", ack.Removed, orphanDB)
	}
	if len(f.removed) != 1 || f.removed[0] != orphanDB {
		t.Fatalf("docker volume rm was asked for %v, want only %s", f.removed, orphanDB)
	}
	reasons := map[string]string{}
	for _, r := range ack.Refused {
		reasons[r.Name] = r.Reason
	}
	if len(reasons) != 6 {
		t.Fatalf("refused %d, want 6: %+v", len(reasons), ack.Refused)
	}
	expect := map[string]string{
		liveData:       "still installed",
		"myproj_data":  "does not start with",
		"rasp_abc_bad": "not of the form",
		handMade:       "not a volume of compose project",
		inUseVol:       "still referenced by 1 container",
		proto.AppVolumeName(orphanULID, "nothere"): "no such volume",
	}
	for name, frag := range expect {
		if !strings.Contains(reasons[name], frag) {
			t.Errorf("%s: reason %q, want it to mention %q", name, reasons[name], frag)
		}
	}
}

// An empty LiveAppIDs list must not make a live app's volume removable by the
// docker-side rules alone when a container still holds it — but a stopped
// live app has no containers, which is exactly why the ledger gate exists and
// why the api MUST send the list. Pinned so nobody "simplifies" it away.
func TestRemoveProjectVolumes_LedgerGateIsIndependent(t *testing.T) {
	f := scriptedDocker()
	b := newFakeBackend(t, f)
	ack := b.RemoveProjectVolumes(context.Background(), proto.AppVolumesRemoveCmd{
		Names:      []string{liveData},
		LiveAppIDs: []string{liveULID},
	})
	if len(ack.Removed) != 0 || len(f.removed) != 0 {
		t.Fatalf("a ledger-owned volume was removed: %+v", ack)
	}
	if len(ack.Refused) != 1 || !strings.Contains(ack.Refused[0].Reason, liveULID) {
		t.Fatalf("refusal must name the app: %+v", ack.Refused)
	}
}

// A `docker volume rm` failure is reported on that name and flips OK, and the
// remaining names are still processed.
func TestRemoveProjectVolumes_RmFailureIsLoud(t *testing.T) {
	f := scriptedDocker()
	f.rmErr = errors.New("exit status 1")
	b := newFakeBackend(t, f)
	ack := b.RemoveProjectVolumes(context.Background(), proto.AppVolumesRemoveCmd{
		Names: []string{orphanDB, orphanUpload},
	})
	if ack.OK {
		t.Fatal("ack.OK must be false when docker refused an rm")
	}
	if len(ack.Removed) != 0 || len(ack.Refused) != 2 {
		t.Fatalf("ack: %+v", ack)
	}
	for _, r := range ack.Refused {
		if !strings.Contains(r.Reason, "docker volume rm") {
			t.Errorf("%s: %q", r.Name, r.Reason)
		}
	}
}

// dirSize walks real files; a quick sanity check on a temp tree.
func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.bin", 100)
	writeTestFile(t, dir, "sub/b.bin", 250)
	n, err := dirSize(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 350 {
		t.Fatalf("dirSize = %d, want 350", n)
	}
}

func writeTestFile(t *testing.T, dir, rel string, size int) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
}
