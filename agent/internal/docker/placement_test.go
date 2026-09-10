package docker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"gopkg.in/yaml.v3"
)

// design/storage.md §6.3 / §6.4 on the deploy path.
//
// The property every test here defends is the same one: a placed app's data
// goes to the operator's disk or the deploy fails saying why. There is no third
// outcome, and in particular there is no outcome where the deploy succeeds and
// the data is on the boot medium — that is the failure §6.3 exists to design
// out, and it is a failure precisely because it looks like success.

const testPartUUID = "9d0f4a2b-01"

// mountedDisk is a directory standing in for a data disk that mounted: it
// carries the §6.3 marker naming partUUID. Nothing else about it matters,
// which is the point of the marker.
func mountedDisk(t *testing.T, partUUID string) string {
	t.Helper()
	dir := t.TempDir()
	writeTestMarker(t, dir, partUUID)
	return dir
}

func writeTestMarker(t *testing.T, dir, partUUID string) {
	t.Helper()
	set := proto.StorageDataSet{
		MarkerVersion: proto.StorageDataMarkerVersion,
		PartUUID:      partUUID,
		Label:         proto.StorageDataLabel,
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, proto.StorageDataMarkerFile), b, 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
}

// resolverFor is the production resolver's shape over a directory the test
// owns: it applies §6.3's marker check to that directory exactly as
// storage.ResolveDataDisk applies it to /var/lib/rasputin/data/<partUUID>.
func resolverFor(t *testing.T, dir string) DataDiskResolver {
	t.Helper()
	return func(partUUID string) (string, error) {
		b, err := os.ReadFile(filepath.Join(dir, proto.StorageDataMarkerFile))
		if err != nil {
			return "", errNoMarker{dir}
		}
		var set proto.StorageDataSet
		if err := json.Unmarshal(b, &set); err != nil {
			return "", errNoMarker{dir}
		}
		if set.PartUUID != partUUID {
			return "", errWrongDisk{set.PartUUID}
		}
		return dir, nil
	}
}

type errNoMarker struct{ path string }

func (e errNoMarker) Error() string {
	return e.path + " carries no " + proto.StorageDataMarkerFile +
		", so it is either an unmounted mount point on the boot medium or not the disk it claims to be"
}

type errWrongDisk struct{ got string }

func (e errWrongDisk) Error() string { return "the marker names partition " + e.got }

// ---------------------------------------------------------------------------
// The default: an app with no placement is untouched
// ---------------------------------------------------------------------------

// An unplaced app's compose must reach the backend BYTE FOR BYTE. Placement is
// opt-in (§6.4), so every app in every existing cluster takes this path, and
// the moment it renders differently it is a change to every app at once.
func TestDeploy_UnplacedAppComposeIsUnchanged(t *testing.T) {
	// Deliberately not canonical YAML: a comment, four-space indent, a quoted
	// scalar and a trailing blank line. A rewrite would flatten all four, so
	// this compose can tell the difference between "not rewritten" and
	// "rewritten to the same meaning".
	const compose = `# jellyfin, hand-edited
services:
    jellyfin:
        image: "jellyfin/jellyfin:10.9.11"
        volumes:
            - config:/config
volumes:
    config:

`
	nc, b := newRegisteredWithResolver(t, resolverFor(t, mountedDisk(t, testPartUUID)))

	var ack proto.AppDeployAck
	request(t, nc, proto.AppDeploySubject("node-1"), proto.AppDeployCmd{
		AppID:       "app-unplaced",
		Name:        "jellyfin",
		ComposeYAML: compose,
		// No DataDiskPartUUID — the default, and the whole point.
	}, &ack)
	if !ack.OK {
		t.Fatalf("deploy ack: %+v", ack)
	}

	got, err := os.ReadFile(b.composePath("app-unplaced"))
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	if string(got) != compose {
		t.Errorf("an unplaced app's compose was rewritten.\n--- want ---\n%s\n--- got ---\n%s", compose, got)
	}
}

// ---------------------------------------------------------------------------
// §6.3: marker absent means refuse, and create nothing
// ---------------------------------------------------------------------------

func TestDeploy_RefusesWhenTheDataDiskIsNotMounted(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{
			// The mount point exists and is empty: the ordinary "the disk is
			// not there" case.
			name:  "an empty mount point",
			setup: func(t *testing.T, dir string) {},
		},
		{
			// THE case §6.3 names. A previous deploy already filled the
			// unmounted mount point, so it is NOT empty — a non-emptiness
			// check passes hardest exactly when the boot medium is being
			// refilled.
			name: "a NON-EMPTY mount point with no marker",
			setup: func(t *testing.T, dir string) {
				if err := os.MkdirAll(filepath.Join(dir, "apps", "app-1", "config"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "apps", "app-1", "config", "db.sqlite"), []byte("a previous deploy's data"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// Mounted, marked, and it is somebody else's disk.
			name: "a marker naming another partition",
			setup: func(t *testing.T, dir string) {
				writeTestMarker(t, dir, "somebody-elses-uuid")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			nc, b := newRegisteredWithResolver(t, resolverFor(t, dir))

			var ack proto.AppDeployAck
			request(t, nc, proto.AppDeploySubject("node-1"), proto.AppDeployCmd{
				AppID:            "app-1",
				Name:             "jellyfin",
				ComposeYAML:      "services:\n  jellyfin:\n    image: jellyfin\nvolumes:\n  config:\n",
				DataDiskPartUUID: testPartUUID,
			}, &ack)

			if ack.OK || ack.Status != proto.AppStatusFailed {
				t.Fatalf("a deploy onto an unmounted data disk was accepted: %+v", ack)
			}
			// The operator has to be able to act on this: which disk, and
			// what is wrong with it.
			if !strings.Contains(ack.Detail, testPartUUID) {
				t.Errorf("the refusal does not name the disk: %q", ack.Detail)
			}
			// REFUSE, NEVER CREATE. Nothing about this deploy may exist: no
			// compose file for the project, and nothing new under the mount
			// point — anything created here is created on the boot medium.
			if _, err := os.Stat(b.composePath("app-1")); err == nil {
				t.Error("a refused deploy wrote a compose file")
			}
			if _, err := os.Stat(filepath.Join(dir, "apps", "app-1", "config")); err == nil && tc.name != "a NON-EMPTY mount point with no marker" {
				t.Error("a refused deploy created a volume directory")
			}
		})
	}
}

// A node with no resolver wired refuses rather than deploying to the boot
// medium. "This agent cannot place anything" and "the disk is missing" have the
// same consequence for the app's data, so they get the same answer.
func TestDeploy_RefusesAPlacementWithNoResolver(t *testing.T) {
	nc, b := newRegisteredWithResolver(t, nil)
	var ack proto.AppDeployAck
	request(t, nc, proto.AppDeploySubject("node-1"), proto.AppDeployCmd{
		AppID:            "app-1",
		Name:             "jellyfin",
		ComposeYAML:      "services: {}\nvolumes:\n  config:\n",
		DataDiskPartUUID: testPartUUID,
	}, &ack)
	if ack.OK {
		t.Fatalf("a placement was accepted with no resolver: %+v", ack)
	}
	if _, err := os.Stat(b.composePath("app-1")); err == nil {
		t.Error("a refused deploy wrote a compose file")
	}
}

// ---------------------------------------------------------------------------
// The rewrite itself
// ---------------------------------------------------------------------------

func TestDeploy_PlacedVolumesBindOntoTheDataDisk(t *testing.T) {
	disk := mountedDisk(t, testPartUUID)
	nc, b := newRegisteredWithResolver(t, resolverFor(t, disk))

	var ack proto.AppDeployAck
	request(t, nc, proto.AppDeploySubject("node-1"), proto.AppDeployCmd{
		AppID: "app-1",
		Name:  "immich",
		ComposeYAML: `services:
  immich:
    image: immich/server
    volumes:
      - config:/config
      - library:/library
volumes:
  config:
  library: {}
`,
		DataDiskPartUUID: testPartUUID,
	}, &ack)
	if !ack.OK {
		t.Fatalf("deploy ack: %+v", ack)
	}

	raw, err := os.ReadFile(b.composePath("app-1"))
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	var got struct {
		Services map[string]struct {
			Image   string   `yaml:"image"`
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
		Volumes map[string]struct {
			Driver     string            `yaml:"driver"`
			DriverOpts map[string]string `yaml:"driver_opts"`
		} `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the placed compose is not valid YAML: %v\n%s", err, raw)
	}

	for _, name := range []string{"config", "library"} {
		v, ok := got.Volumes[name]
		if !ok {
			t.Fatalf("volume %q is missing from the placed compose:\n%s", name, raw)
		}
		if v.Driver != "local" {
			t.Errorf("volume %q driver = %q, want local", name, v.Driver)
		}
		want := filepath.Join(disk, "apps", "app-1", name)
		if v.DriverOpts["device"] != want {
			t.Errorf("volume %q device = %q, want %q", name, v.DriverOpts["device"], want)
		}
		if v.DriverOpts["type"] != "none" || v.DriverOpts["o"] != "bind" {
			t.Errorf("volume %q driver_opts = %v, want the local driver's bind form", name, v.DriverOpts)
		}
		// The bind form does not create its device path; docker fails the
		// volume when it is missing. Creating it is part of placing.
		st, err := os.Stat(want)
		if err != nil || !st.IsDir() {
			t.Errorf("volume %q device directory was not created at %s (%v)", name, want, err)
		}
	}

	// The rest of the file has to survive: placement decides where volumes
	// live and nothing else about the app.
	svc, ok := got.Services["immich"]
	if !ok || svc.Image != "immich/server" || len(svc.Volumes) != 2 {
		t.Errorf("the services section did not survive placement: %+v\n%s", got.Services, raw)
	}
}

// ---------------------------------------------------------------------------
// Volumes somebody else already placed
// ---------------------------------------------------------------------------

// A compose that already decides where a volume is stored is refused WHOLE, not
// placed in part. Overriding the declaration would move data an operator put
// somewhere deliberately; skipping it would leave that volume on the boot
// medium under a deploy that reported success.
func TestPlaceOnDataDisk_RefusesVolumesSomebodyElseAlreadyPlaced(t *testing.T) {
	for _, tc := range []struct {
		name    string
		volumes string
		wantIn  string
	}{
		{
			name:    "external",
			volumes: "volumes:\n  config:\n    external: true\n",
			wantIn:  "external",
		},
		{
			name:    "another driver",
			volumes: "volumes:\n  config:\n    driver: rexray\n",
			wantIn:  "volume driver",
		},
		{
			name:    "driver_opts already set",
			volumes: "volumes:\n  config:\n    driver: local\n    driver_opts:\n      type: nfs\n      device: \":/exports\"\n",
			wantIn:  "already carries driver_opts",
		},
		{
			name:    "no named volumes at all",
			volumes: "",
			wantIn:  "declares no named volumes",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disk := mountedDisk(t, testPartUUID)
			_, err := placeOnDataDisk("app1", "services:\n  a:\n    image: x\n"+tc.volumes, testPartUUID, resolverFor(t, disk))
			if err == nil {
				t.Fatalf("placement was accepted for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("refusal %q should say %q", err, tc.wantIn)
			}
			// Refused whole: no directory was created for any volume.
			if _, statErr := os.Stat(filepath.Join(disk, "apps")); statErr == nil {
				t.Error("a refused placement created directories on the data disk")
			}
		})
	}
}

// The path segments are checked because they are path segments. A compose file
// is operator-supplied input and the agent does not get to assume the api
// validated it.
func TestPlaceOnDataDisk_RefusesUnusableNames(t *testing.T) {
	disk := mountedDisk(t, testPartUUID)
	if _, err := placeOnDataDisk("app1", "volumes:\n  \"../../etc\":\n", testPartUUID, resolverFor(t, disk)); err == nil {
		t.Error("a volume name that is a path traversal was accepted")
	}
	if _, err := placeOnDataDisk("../../etc", "volumes:\n  config:\n", testPartUUID, resolverFor(t, disk)); err == nil {
		t.Error("an app id that is a path traversal was accepted")
	}
}
