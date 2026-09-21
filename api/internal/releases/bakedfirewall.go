package releases

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// A control plane on the no-DHCP bootstrap address has NO default gateway --
// deliberate, rasputin-os#53 -- because that address exists for exactly the
// case where the Rasputin firewall is not up yet and nothing is serving DHCP.
// On that path GET /api/cluster/firewall-image cannot reach api.github.com to
// resolve a release, so flash.sh dies before it downloads anything and the
// operator cannot flash the firewall that would restore internet. The control
// plane's only job there is NAMING the release: the laptop does the download
// itself, and verifies against a root CA pinned inside flash.sh.
//
// So rasputin-os bakes a PINNED firewall release manifest into the image at
// build time (board/rasputin/common/firewall-pin.txt), and this reads it back.
// The pin is deliberate, not "whatever was latest at build time": following a
// rolling upstream is what burned 2026.09.2 when Talos republished the Snort3
// rules between a green pre-flight and the tag build, and release tags are
// immutable. It also doubles as a compatibility statement -- this OS release
// was built against this firewall release.
//
// geekdojo/geekdojo-brain#595.

// BakedFirewallManifestDir is where rasputin-os installs the pinned firewall
// manifest and its detached signature. A package var so tests can point it at
// a temp dir; RASPUTIN_BAKED_FIREWALL_DIR overrides it for a dev box, which has
// no baked copy at all.
var BakedFirewallManifestDir = "/usr/share/rasputin/firewall"

// ErrNoBakedManifest means this image carries no pinned firewall manifest --
// a dev build, or an older image. Callers fall back to their online path and
// must not treat it as a verification failure.
var ErrNoBakedManifest = errors.New("no baked firewall manifest on this image")

// maxBakedManifestBytes bounds what is read off the local filesystem. The real
// pair is ~2.7 KB. This is not a hostile-input bound -- the file shipped inside
// the signed image -- but an unbounded ReadFile on a path is still a habit
// worth not having.
const maxBakedManifestBytes = 1 << 20

// BakedFirewallImage builds a firewall image descriptor from the manifest this
// OS image was built against, with no network access at all.
//
// It verifies the baked signature exactly as the online path does -- same
// verifier, same component floor -- so an offline descriptor carries the same
// guarantee as an online one, and the manifest and signature travel on to
// flash.sh so the laptop repeats the check for itself. A baked manifest is NOT
// trusted for being local: it is trusted for being signed.
//
// downloadBase is the asset host the URL is built against (https://github.com).
// The laptop, not this control plane, fetches that URL.
func BakedFirewallImage(v ManifestVerifier, downloadBase string, comp Component) (*NodeImageDescriptor, error) {
	dir := strings.TrimSpace(os.Getenv("RASPUTIN_BAKED_FIREWALL_DIR"))
	if dir == "" {
		dir = BakedFirewallManifestDir
	}
	manifestRaw, err := readBakedFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	// Unlike the online path, a missing signature here is NOT excusable. Online,
	// an absent .sig can be an asset-host hiccup and the floor decides. This
	// file was installed beside the manifest by the image build, which fails if
	// it cannot fetch both -- so a missing one means the pair was tampered with
	// or truncated, and there is no hiccup to forgive.
	sigDER, err := readBakedFile(filepath.Join(dir, "manifest.json.sig"))
	if err != nil {
		if errors.Is(err, ErrNoBakedManifest) {
			return nil, fmt.Errorf("baked firewall manifest has no signature beside it in %s: %w", dir, os.ErrNotExist)
		}
		return nil, err
	}

	var m Manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return nil, fmt.Errorf("parse baked firewall manifest: %w", err)
	}
	version := strings.TrimSpace(m.Version)
	if !ValidReleaseVersion(version) {
		return nil, fmt.Errorf("baked firewall manifest: %w %q", ErrInvalidVersion, version)
	}

	res, err := VerifyManifest(v, comp, version, manifestRaw, sigDER)
	if err != nil {
		return nil, fmt.Errorf("baked firewall manifest for %s: %w", version, err)
	}

	tagBase := fmt.Sprintf("%s/%s/releases/download/%s",
		strings.TrimRight(downloadBase, "/"), comp.Repo, url.PathEscape(version))

	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		if comp.Compatible != "" && a.Compatible != comp.Compatible {
			continue
		}
		// The firewall's flashable artifact is `image` (*-ab.img.gz) and its
		// checksum is `sha256` -- distinct from the OS, whose `sha256` covers
		// the RAUC bundle and whose image sha is `imageSha256`.
		if a.Image == "" || a.SHA256 == "" {
			continue
		}
		if !validPathSegment(a.Image) {
			return nil, fmt.Errorf("baked firewall manifest for %s: %w %q", version, ErrInvalidAssetName, a.Image)
		}
		d := &NodeImageDescriptor{
			Version:      version,
			Architecture: a.Architecture,
			URL:          tagBase + "/" + url.PathEscape(a.Image),
			SHA256:       a.SHA256,
			Image:        a.Image,
		}
		if res != nil {
			d.ManifestB64 = base64.StdEncoding.EncodeToString(manifestRaw)
			d.ManifestSigB64 = base64.StdEncoding.EncodeToString(sigDER)
			d.Signer = res.Signer
		}
		return d, nil
	}
	return nil, fmt.Errorf("no flashable %q image in the baked firewall manifest for %s", comp.Compatible, version)
}

func readBakedFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w (%s)", ErrNoBakedManifest, path)
		}
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > maxBakedManifestBytes {
		return nil, fmt.Errorf("baked file %s is %d bytes, over the %d cap", path, st.Size(), maxBakedManifestBytes)
	}
	b := make([]byte, st.Size())
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, err
	}
	return b, nil
}
