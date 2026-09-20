package mesh

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// mesh-images.json is the SINGLE SOURCE for the container images an OS image
// bakes so a controlplane forms its mesh on first boot with no internet.
//
// It used to be two sources. rasputin-os carried
// board/rasputin/common/mesh-images.list, whose comment said in capitals that
// the ref "MUST match defaultImage" here — a sync contract enforced by nobody.
// When the two drifted, the baked tarball simply was not matched by the
// supervisor and it fell back to pulling at runtime: no error, no alert, just a
// controlplane that silently needs internet on its first boot, which is the one
// thing baking the image exists to prevent (geekdojo/geekdojo-brain#210, #211).
//
// The control-plane release publishes this file verbatim as an asset, and the
// OS build reads it. Neither side can drift from a file only one of them owns.
//
//go:embed mesh-images.json
var meshImagesJSON []byte

// BakedImage is one image in the pin.
type BakedImage struct {
	// Ref is the full reference the api runs and the OS build pulls, in
	// name:tag@sha256:... form. The tag is cosmetic — the digest is what
	// resolves — but it is kept because an operator reading `docker ps` or a
	// compose file should not have to look a digest up to learn the version.
	Ref string `json:"ref"`
	// Platforms maps "linux/<arch>" to that architecture's MANIFEST digest
	// within the index Ref names. The OS build asserts the image it pulled for
	// its target arch is the one named here, so a `--platform` pull that
	// silently resolved to something else is caught at build time rather than
	// at a node's first boot.
	Platforms map[string]string `json:"platforms"`
}

type meshImagePin struct {
	Schema int                   `json:"schema"`
	Note   string                `json:"note"`
	Images map[string]BakedImage `json:"images"`
}

var bakedImages = mustLoadPin()

func mustLoadPin() map[string]BakedImage {
	var p meshImagePin
	if err := json.Unmarshal(meshImagesJSON, &p); err != nil {
		// Unreachable outside a bad edit to the embedded file, and a panic at
		// init is the right outcome for one: the alternative is an api that
		// starts and then cannot name the image it is supposed to run.
		panic(fmt.Sprintf("mesh: mesh-images.json is not valid JSON: %v", err))
	}
	if p.Schema != 1 {
		panic(fmt.Sprintf("mesh: mesh-images.json schema %d, want 1", p.Schema))
	}
	if len(p.Images) == 0 {
		panic("mesh: mesh-images.json names no images")
	}
	for name, img := range p.Images {
		if err := tileschema.ValidateImagePin(img.Ref); err != nil {
			panic(fmt.Sprintf("mesh: mesh-images.json image %q: %v", name, err))
		}
	}
	return p.Images
}

// BakedImageRef returns the pinned reference for a named baked image.
func BakedImageRef(name string) (string, bool) {
	img, ok := bakedImages[name]
	return img.Ref, ok
}

// MeshImagesJSON returns the pin exactly as published, for a caller that has to
// hand the bytes on rather than interpret them.
func MeshImagesJSON() []byte { return append([]byte(nil), meshImagesJSON...) }

// BakedImageIDsEnv names the file the OS build writes recording the image ID of
// each tarball it baked. Overridable so a dev box can point at one.
const BakedImageIDsEnv = "RASPUTIN_MESH_IMAGE_IDS"

// DefaultBakedImageIDsPath is where the OS image puts that file, beside the
// tarballs rasputin-mesh-images.service loads.
const DefaultBakedImageIDsPath = "/usr/share/rasputin/mesh-images/loaded-ids.tsv"

// bakedImageIDsPath returns the file to read, env first.
func bakedImageIDsPath() string {
	if p := strings.TrimSpace(os.Getenv(BakedImageIDsEnv)); p != "" {
		return p
	}
	return DefaultBakedImageIDsPath
}

// readBakedImageID returns the image ID the OS build recorded for ref, and
// whether the build recorded one at all.
//
// WHY AN IMAGE ID AND NOT A DIGEST. `docker load` of a `docker save` tarball
// does not record a RepoDigest in the classic image store — there was no
// registry pull, so there is no manifest digest to record. `docker image
// inspect` on the loaded image therefore reports RepoDigests as empty, and a
// digest-pinned reference cannot be checked against it. The image ID (the
// config digest) IS recorded, is derived from the image's content, and is what
// `docker save`/`docker load` preserves. So the OS build resolves the ID at
// pull time, when the digest pin was still checkable, and writes it down; the
// api checks the loaded image against that record.
//
// Format, one image per line, tab separated: <ref>\t<image id>. Blank lines and
// "#" comments ignored. A file that cannot be read is treated as absent — a dev
// build bakes nothing and must still start.
func readBakedImageID(path, ref string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, id, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		if strings.TrimSpace(name) == ref {
			id = strings.TrimSpace(id)
			if id == "" {
				return "", false
			}
			return id, true
		}
	}
	return "", false
}

// bakedImageNames returns the pin's keys in a stable order, for messages.
func bakedImageNames() []string {
	out := make([]string, 0, len(bakedImages))
	for k := range bakedImages {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
