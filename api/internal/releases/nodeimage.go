package releases

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// NodeImageDescriptor is the public flashable OS image for an exact version:
// the anonymous download URL plus the checksum to verify it against. It backs
// the one-command node flasher (GET /api/cluster/node-image → flash.sh).
type NodeImageDescriptor struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Image   string `json:"image"`
}

// PublicNodeImage resolves the flashable node image for an EXACT OS version
// from the public release channel — not "latest": a new node must match the
// version the cluster currently runs. downloadBase is the asset host
// (https://github.com), repo is "owner/name", compatible is the artifact SKU
// ("rasputin-n100"). It fetches the release's manifest.json over anonymous
// HTTPS and returns the image asset URL + its imageSha256.
func PublicNodeImage(ctx context.Context, hc *http.Client, downloadBase, repo, version, compatible string) (*NodeImageDescriptor, error) {
	if version == "" {
		return nil, fmt.Errorf("no version given")
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	tagBase := fmt.Sprintf("%s/%s/releases/download/os-%s", strings.TrimRight(downloadBase, "/"), repo, version)
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
		return &NodeImageDescriptor{
			Version: version,
			URL:     tagBase + "/" + a.Image,
			SHA256:  a.ImageSha256,
			Image:   a.Image,
		}, nil
	}
	return nil, fmt.Errorf("no flashable %q image in manifest for os-%s", compatible, version)
}
