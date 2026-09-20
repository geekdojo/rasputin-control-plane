package releases

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/artifactsig"
)

// ErrInvalidVersion is returned (wrapped) when a version is not usable as a
// single release-tag path segment.
var ErrInvalidVersion = errors.New("invalid release version")

// ErrInvalidAssetName is returned (wrapped) when a manifest names an image
// that is not a single file name.
var ErrInvalidAssetName = errors.New("invalid release asset name")

// maxPathSegment bounds a version or asset name. Real values are ~40 bytes
// ("rasputin-os-n100-2026.09.2-dev.214.img.xz").
const maxPathSegment = 128

// validPathSegment reports whether s is safe to splice into a release download
// URL as exactly one path segment: 1-128 bytes of ASCII letters, digits, '.',
// '_', '+' and '-', starting with a letter or digit, and never containing "..".
// That admits every tag and asset name the release pipelines publish (CalVer
// "2026.09.1", "2026.09.2-dev.214", semver "v0.8.7-dev.2", image files like
// "rasputin-os-n100-2026.09.1.img.xz") and excludes path separators, dot
// segments, query/fragment/percent characters, whitespace and control bytes.
func validPathSegment(s string) bool {
	if len(s) == 0 || len(s) > maxPathSegment || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '+' || c == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ValidReleaseVersion reports whether version can name a release tag in a
// download URL. It is deliberately a shape check, not a CalVer parse: it
// rejects only values that could change the URL's structure.
func ValidReleaseVersion(version string) bool {
	return validPathSegment(version)
}

// NodeImageDescriptor is the public flashable OS image for an exact version:
// the anonymous download URL plus the checksum to verify it against. It backs
// the one-command node flasher (GET /api/cluster/node-image → flash.sh).
type NodeImageDescriptor struct {
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	Image        string `json:"image"`

	// ManifestB64 and ManifestSigB64 carry the SIGNED release manifest to the
	// flasher, so the laptop can check for itself that the sha256 above is the
	// one the publisher signed rather than one this control plane asserted
	// (geekdojo/geekdojo-brain#527). Both are base64 — the signature because it
	// is DER, and the manifest because flash.sh reads this descriptor with a
	// sed one-liner, and a JSON string carrying escaped JSON would need a real
	// parser the laptop is not guaranteed to have.
	//
	// Both are empty when the release publishes no signature this api accepts
	// (below the component's SignedManifestFrom floor). flash.sh then falls
	// back to the bare sha256, which is what an older control plane serves in
	// every case — see the flasher's own note on what that does and does not
	// cover.
	//
	// About 3 KB together, next to a descriptor of ~300 bytes and an image of
	// ~350 MB.
	ManifestB64    string `json:"manifestB64,omitempty"`
	ManifestSigB64 string `json:"manifestSigB64,omitempty"`

	// Signer is the signing leaf's common name when the manifest was verified,
	// for the UI and the flasher to show. Empty when unverified.
	Signer string `json:"signer,omitempty"`
}

// maxManifestBytes caps a fetched manifest. A real one is ~1.2 KiB; this is
// three orders of magnitude of headroom and still refuses to buffer whatever a
// hostile asset host feels like sending.
const maxManifestBytes = 1 << 20

// PublicNodeImage resolves the flashable node image for an EXACT OS version
// from the OS source repo's public releases — not "latest": a new node must
// match the version the cluster currently runs. downloadBase is the asset host
// (https://github.com), comp is the component registry entry (its Repo is the
// source repo, its SignedManifestFrom the signing floor), compatible is the
// artifact SKU for the requested arch ("rasputin-n100"), and v verifies the
// manifest's signature. The release is tagged with the bare version (ADR-0002 —
// no channel-mirror prefix).
//
// It fetches the release's manifest.json AND its detached signature over
// anonymous HTTPS, verifies the signature when the component's floor requires
// one, and returns the image asset URL plus the imageSha256 read out of the
// manifest it verified. The verified manifest and its signature travel on in
// the descriptor so the flasher can repeat the check on the laptop
// (geekdojo/geekdojo-brain#527).
func PublicNodeImage(ctx context.Context, hc *http.Client, v ManifestVerifier, downloadBase string, comp Component, version, compatible string) (*NodeImageDescriptor, error) {
	if !ValidReleaseVersion(version) {
		return nil, fmt.Errorf("%w %q", ErrInvalidVersion, version)
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	// Validated above, and escaped anyway so the tag can only ever be one
	// path segment.
	tagBase := fmt.Sprintf("%s/%s/releases/download/%s", strings.TrimRight(downloadBase, "/"), comp.Repo, url.PathEscape(version))
	manifestURL := tagBase + "/manifest.json"

	manifestRaw, err := fetchBytes(ctx, hc, manifestURL)
	if err != nil {
		return nil, err
	}
	// A missing signature is not an error HERE: whether it is one at all is
	// VerifyManifest's decision, which is where the floor lives. Any other
	// failure to fetch it is swallowed for the same reason — an asset host
	// hiccup on the .sig must not read differently from an absent .sig, since
	// the required case refuses both.
	sigDER, _ := fetchBytes(ctx, hc, artifactsig.SigPathFor(manifestURL))

	res, err := VerifyManifest(v, comp, version, manifestRaw, sigDER)
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		if compatible != "" && a.Compatible != compatible {
			continue
		}
		if a.Image == "" || a.ImageSha256 == "" {
			continue
		}
		if !validPathSegment(a.Image) {
			return nil, fmt.Errorf("manifest for %s: %w %q", version, ErrInvalidAssetName, a.Image)
		}
		d := &NodeImageDescriptor{
			Version:      version,
			Architecture: a.Architecture,
			URL:          tagBase + "/" + url.PathEscape(a.Image),
			SHA256:       a.ImageSha256,
			Image:        a.Image,
		}
		// Only ever attached together with the signature that makes them worth
		// having, and only when that signature was actually checked here.
		if res != nil {
			d.ManifestB64 = base64.StdEncoding.EncodeToString(manifestRaw)
			d.ManifestSigB64 = base64.StdEncoding.EncodeToString(sigDER)
			d.Signer = res.Signer
		}
		return d, nil
	}
	return nil, fmt.Errorf("no flashable %q image in manifest for %s", compatible, version)
}

// fetchBytes GETs url and returns its body, bounded. Used for the small JSON
// and DER assets; the image itself is never read by the api.
func fetchBytes(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rasputin-control-plane")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if len(b) > maxManifestBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", url, maxManifestBytes)
	}
	return b, nil
}
