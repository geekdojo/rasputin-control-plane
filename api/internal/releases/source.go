package releases

import (
	"context"
	"io"
)

// Manifest mirrors the `manifest.json` asset published on every Rasputin OS
// and firewall release. Only the fields the control plane needs are modeled.
type Manifest struct {
	Version   string             `json:"version"`
	Channel   string             `json:"channel"` // "stable" | "dev"
	Artifacts []ManifestArtifact `json:"artifacts"`
}

// ManifestArtifact is one buildable artifact within a release. The OS uses
// `raucb` (the deployable bundle) + `image` (full flash image); the firewall
// uses `image` (+ `sig`). We carry both names and pick by Kind.
type ManifestArtifact struct {
	SKU          string `json:"sku"`
	Architecture string `json:"architecture"`
	Compatible   string `json:"compatible"`
	Kind         string `json:"kind,omitempty"`
	Raucb        string `json:"raucb,omitempty"`
	Image        string `json:"image,omitempty"`
	SHA256       string `json:"sha256"`
	// ImageSha256 checksums the flashable `image` (the .img.xz), distinct from
	// SHA256 which checksums the OTA `raucb`. Used by the node flasher to verify
	// the downloaded image (GET /api/cluster/node-image).
	ImageSha256 string `json:"imageSha256,omitempty"`
	SizeBytes   int64  `json:"sizeBytes"`
	Sig         string `json:"sig,omitempty"`
	SignedBy    string `json:"signedBy,omitempty"`
	BuildDate   string `json:"buildDate,omitempty"`

	// Firewall A/B (KindRootfsAB): the deployable OTA artifact is the bare
	// rootfs squashfs, distinct from `image` (which carries the full-disk
	// initial-flash .img.gz for humans). The agent's OpenWrtABBackend dd's this
	// into the inactive slot. Emitted by the firewall release pipeline.
	Rootfs          string `json:"rootfs,omitempty"`
	RootfsSha256    string `json:"rootfsSha256,omitempty"`
	RootfsSizeBytes int64  `json:"rootfsSizeBytes,omitempty"`
	RootfsSig       string `json:"rootfsSig,omitempty"`
}

// OTAAsset returns the deployable OTA artifact (asset filename, sha256,
// sizeBytes) for the given component kind — the RAUC bundle for KindRAUC, the
// rootfs squashfs for KindRootfsAB. ok=false when the artifact lacks that
// kind's fields (so the caller can skip a non-matching arch/artifact). This is
// the single place the kind→asset mapping lives.
func (a *ManifestArtifact) OTAAsset(kind Kind) (name, sha256 string, size int64, ok bool) {
	switch kind {
	case KindRAUC:
		if a.Raucb != "" && a.SHA256 != "" {
			return a.Raucb, a.SHA256, a.SizeBytes, true
		}
	case KindRootfsAB:
		if a.Rootfs != "" && a.RootfsSha256 != "" {
			return a.Rootfs, a.RootfsSha256, a.RootfsSizeBytes, true
		}
	}
	return "", "", 0, false
}

// ReleaseInfo is the resolved latest release for a component on a channel,
// with the asset download URLs needed to pull the deployable bytes.
type ReleaseInfo struct {
	Component string
	Version   string
	Channel   string
	Tag       string
	Manifest  Manifest
	// assetURLs maps asset filename → download URL (public, anonymous).
	assetURLs map[string]string
}

// Artifact returns the manifest artifact matching the given compatible string
// (the component's hardware SKU). If compatible is empty, the first artifact
// is returned (used by informational components with no hardware match).
func (r *ReleaseInfo) Artifact(compatible string) (*ManifestArtifact, bool) {
	for i := range r.Manifest.Artifacts {
		a := &r.Manifest.Artifacts[i]
		if compatible == "" || a.Compatible == compatible {
			return a, true
		}
	}
	return nil, false
}

// AssetURL resolves the download URL for an asset filename.
func (r *ReleaseInfo) AssetURL(name string) (string, bool) {
	u, ok := r.assetURLs[name]
	return u, ok
}

// Source discovers the latest release for a component on a channel and can
// open an asset's bytes for download. One implementation today
// (githubPublicSource); the interface keeps it swappable to an R2/S3/own-CDN
// source without touching the handlers.
type Source interface {
	// LatestFor returns the newest release for comp on the given channel, or
	// (nil, nil) when no matching release exists.
	LatestFor(ctx context.Context, comp Component, channel string) (*ReleaseInfo, error)
	// Open streams the bytes at a download URL previously returned via
	// ReleaseInfo.AssetURL.
	Open(ctx context.Context, url string) (io.ReadCloser, error)
}
