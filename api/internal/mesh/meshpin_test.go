package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The embedded pin is read by two repositories: this one at run time, and the
// OS build at image-build time. A malformed field here is a build that bakes
// the wrong thing, or nothing.
func TestEmbeddedPinIsWellFormed(t *testing.T) {
	var p meshImagePin
	if err := json.Unmarshal(meshImagesJSON, &p); err != nil {
		t.Fatalf("mesh-images.json: %v", err)
	}
	if p.Schema != 1 {
		t.Errorf("schema = %d, want 1", p.Schema)
	}
	if _, ok := p.Images["headscale"]; !ok {
		t.Fatalf(`no "headscale" image; present: %s`, strings.Join(bakedImageNames(), ", "))
	}
	for name, img := range p.Images {
		if err := tileschema.ValidateImagePin(img.Ref); err != nil {
			t.Errorf("%s ref %q: %v", name, img.Ref, err)
		}
		// Both architectures the OS builds for. A pin missing one is a build
		// that cannot assert what it pulled for that SKU.
		for _, plat := range []string{"linux/amd64", "linux/arm64"} {
			d, ok := img.Platforms[plat]
			if !ok {
				t.Errorf("%s: no digest for %s", name, plat)
				continue
			}
			if !strings.HasPrefix(d, "sha256:") || len(strings.TrimPrefix(d, "sha256:")) != 64 {
				t.Errorf("%s %s digest = %q, want sha256: plus 64 hex", name, plat, d)
			}
		}
	}
}

// defaultImage is derived from the pin rather than written a second time, so
// the two cannot disagree. This is the assertion that the derivation happened.
func TestDefaultImageComesFromThePin(t *testing.T) {
	ref, ok := BakedImageRef("headscale")
	if !ok {
		t.Fatal("the pin has no headscale entry")
	}
	if defaultImage != ref {
		t.Errorf("defaultImage = %q, pin says %q", defaultImage, ref)
	}
	if err := tileschema.ValidateImagePin(defaultImage); err != nil {
		t.Errorf("defaultImage: %v", err)
	}
}

func TestUnpinnedImageRefusesConstruction(t *testing.T) {
	for _, ref := range []string{
		"headscale/headscale:0.28.0",
		"headscale/headscale:latest",
		"headscale/headscale:0.28.0@sha1:abc",
		"headscale/headscale:0.28.0@sha256:tooshort",
	} {
		_, err := NewDockerSupervisor(DockerSupervisorConfig{StateDir: t.TempDir(), Image: ref})
		if err == nil {
			t.Errorf("image %q was accepted", ref)
			continue
		}
		if !strings.Contains(err.Error(), "RASPUTIN_HEADSCALE_IMAGE") {
			t.Errorf("image %q: error %v does not name the override that sets it", ref, err)
		}
	}
}

func TestReadBakedImageID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loaded-ids.tsv")
	body := "# written by the OS build\n" +
		"\n" +
		"headscale/headscale:0.28.0@sha256:aaaa\tsha256:1111\n" +
		"other/image:1@sha256:bbbb\tsha256:2222\n" +
		"malformed-line-with-no-tab\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if id, ok := readBakedImageID(path, "headscale/headscale:0.28.0@sha256:aaaa"); !ok || id != "sha256:1111" {
		t.Errorf("got %q/%v, want sha256:1111/true", id, ok)
	}
	if _, ok := readBakedImageID(path, "not/in:the@sha256:file"); ok {
		t.Error("a reference the build did not bake reported an ID")
	}
	// A dev build bakes nothing and must still start, so an absent file is not
	// an error — it is "no record", and the digest pin still governs a pull.
	if _, ok := readBakedImageID(filepath.Join(dir, "absent.tsv"), "anything"); ok {
		t.Error("an absent record file reported an ID")
	}
}

// idDocker answers `docker image inspect` only for references it has been told
// the node holds, and records what it was asked. Deliberately NOT
// supervisor_docker_test.go's fakeDocker, which models container lifecycle:
// these cases turn on which image the node has, and a smaller fake makes that
// readable.
type idDocker struct {
	knownIDs map[string]bool
	calls    [][]string
}

func (f *idDocker) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if len(args) >= 2 && args[0] == "image" && args[1] == "inspect" {
		ref := args[len(args)-1]
		if !f.knownIDs[ref] {
			return nil, errors.New("No such image: " + ref)
		}
		return []byte(ref + "\n"), nil
	}
	return []byte("ok"), nil
}

func newPinnedSupervisor(t *testing.T, runner CmdRunner) *DockerSupervisor {
	t.Helper()
	s, err := NewDockerSupervisor(DockerSupervisorConfig{StateDir: t.TempDir(), Runner: runner})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	return s
}

// The case the image-ID record exists for. `docker save` of a digest-pinned
// reference writes a tarball with RepoTags null, and `docker load` records no
// RepoDigest in the classic image store — so on an appliance the reference
// cannot be resolved locally at all, and the image is addressed by the ID the
// build recorded. Running it by that ID is a stronger pin than any name: a
// name is a local label anyone with the daemon can move; an ID is the content.
func TestEnsureImage_RunsTheBakedImageByID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loaded-ids.tsv")
	fd := &idDocker{knownIDs: map[string]bool{"sha256:thebakedone": true}}
	sup := newPinnedSupervisor(t, fd.run)
	if err := os.WriteFile(path, []byte(sup.cfg.Image+"\tsha256:thebakedone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(BakedImageIDsEnv, path)

	if err := sup.ensureImage(context.Background()); err != nil {
		t.Fatalf("ensureImage: %v", err)
	}
	if sup.runImage != "sha256:thebakedone" {
		t.Fatalf("runImage = %q, want the baked image ID", sup.runImage)
	}
	for _, c := range fd.calls {
		if len(c) > 1 && c[1] == "pull" {
			t.Error("the mesh server went to the network with the baked image present")
		}
	}
}

// The record names an image this node does not hold — the normal state when
// rasputin-mesh-images.service did not load (it is ordering-only and a failed
// load does not block the api). The pull is still digest-verified, so it is a
// fallback and not a hole; it must not be a SILENT one, because "it quietly
// went to the network" is the failure baking the image exists to prevent.
func TestEnsureImage_FallsBackToThePullWhenTheBakedImageIsAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loaded-ids.tsv")
	fd := &idDocker{} // nothing known locally
	sup := newPinnedSupervisor(t, fd.run)
	if err := os.WriteFile(path, []byte(sup.cfg.Image+"\tsha256:neverloaded\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(BakedImageIDsEnv, path)

	if err := sup.ensureImage(context.Background()); err != nil {
		t.Fatalf("ensureImage: %v", err)
	}
	if sup.runImage != sup.cfg.Image {
		t.Fatalf("runImage = %q, want the digest-pinned reference %q", sup.runImage, sup.cfg.Image)
	}
	pulled := false
	for _, c := range fd.calls {
		if len(c) > 1 && c[1] == "pull" {
			pulled = true
			if c[len(c)-1] != sup.cfg.Image {
				t.Errorf("pulled %q, want the pinned reference", c[len(c)-1])
			}
		}
	}
	if !pulled {
		t.Error("the fallback never pulled")
	}
}

// A dev build, or an OS image predating the record: no file, no baked image,
// and the digest-pinned reference governs.
func TestEnsureImage_NoRecordRunsThePinnedReference(t *testing.T) {
	fd := &idDocker{knownIDs: map[string]bool{}}
	sup := newPinnedSupervisor(t, fd.run)
	t.Setenv(BakedImageIDsEnv, filepath.Join(t.TempDir(), "absent.tsv"))
	if err := sup.ensureImage(context.Background()); err != nil {
		t.Fatalf("ensureImage: %v", err)
	}
	if sup.runImage != sup.cfg.Image {
		t.Fatalf("runImage = %q, want the digest-pinned reference", sup.runImage)
	}
}

// createAndStart must never run before ensureImage settled an image: it would
// otherwise `docker run ""` and the daemon's error would say nothing useful.
func TestCreateAndStart_RefusesBeforeEnsureImage(t *testing.T) {
	sup := newPinnedSupervisor(t, (&idDocker{}).run)
	err := sup.createAndStart(context.Background())
	if err == nil || !strings.Contains(err.Error(), "before ensureImage") {
		t.Fatalf("err = %v, want a refusal naming the missing step", err)
	}
}
