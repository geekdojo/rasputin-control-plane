package releases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
}

// PublicNodeImage resolves the flashable node image for an EXACT OS version
// from the OS source repo's public releases — not "latest": a new node must
// match the version the cluster currently runs. downloadBase is the asset host
// (https://github.com), repo is the OS source repo "owner/name"
// (geekdojo/rasputin-os), compatible is the artifact SKU ("rasputin-n100"). The
// release is tagged with the bare version (ADR-0002 — no channel-mirror
// prefix). It fetches the release's manifest.json over anonymous HTTPS and
// returns the image asset URL + its imageSha256.
func PublicNodeImage(ctx context.Context, hc *http.Client, downloadBase, repo, version, compatible string) (*NodeImageDescriptor, error) {
	if !ValidReleaseVersion(version) {
		return nil, fmt.Errorf("%w %q", ErrInvalidVersion, version)
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	// Validated above, and escaped anyway so the tag can only ever be one
	// path segment.
	tagBase := fmt.Sprintf("%s/%s/releases/download/%s", strings.TrimRight(downloadBase, "/"), repo, url.PathEscape(version))
	manifestURL := tagBase + "/manifest.json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", manifestURL, resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
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
		return &NodeImageDescriptor{
			Version:      version,
			Architecture: a.Architecture,
			URL:          tagBase + "/" + url.PathEscape(a.Image),
			SHA256:       a.ImageSha256,
			Image:        a.Image,
		}, nil
	}
	return nil, fmt.Errorf("no flashable %q image in manifest for %s", compatible, version)
}
