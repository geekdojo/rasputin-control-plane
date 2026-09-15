package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func TestGetFlashScript(t *testing.T) {
	f := newAPIFixture(t)
	rec := f.do(t, http.MethodGet, "/flash.sh", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Errorf("content-type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"rasputin flash.sh", "RASPUTIN_SEED_B64", "read-back"} {
		if !strings.Contains(body, want) {
			t.Errorf("flash.sh missing %q", want)
		}
	}
}

func TestClusterNodeImage(t *testing.T) {
	const version = "2026.06.0-dev.31"
	const img = "rasputin-os-n100-2026.06.0-dev.31.img.xz"
	const sha = "6b88e011deadbeef"
	const armImg = "rasputin-os-rpi-2026.06.0-dev.31.img.xz"
	const armSha = "abcdef0123456789"

	mux := http.NewServeMux()
	mux.HandleFunc("/geekdojo/rasputin-os/releases/download/"+version+"/manifest.json",
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(releases.Manifest{
				Version: version,
				Artifacts: []releases.ManifestArtifact{
					{Compatible: "rasputin-n100", Architecture: "amd64", Image: img, ImageSha256: sha},
					{Compatible: "rasputin-rpi-arm64", Architecture: "arm64", Image: armImg, ImageSha256: armSha},
				},
			})
		})
	rel := httptest.NewServer(mux)
	defer rel.Close()

	f := newAPIFixture(t)
	f.srv.SetReleaseDownloadBase(rel.URL)

	// 503 until a controlplane node has reported its OS version.
	if rec := f.do(t, http.MethodGet, "/api/cluster/node-image", "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before cp version known, got %d", rec.Code)
	}

	if err := f.inv.Insert(f.ctx, &proto.Node{ID: "x", Role: proto.RoleControlPlane, ImageVersion: version}); err != nil {
		t.Fatalf("seed cp node: %v", err)
	}

	// Default (no arch) resolves the amd64/n100 image.
	rec := f.do(t, http.MethodGet, "/api/cluster/node-image", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var desc releases.NodeImageDescriptor
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if desc.Version != version || desc.SHA256 != sha || desc.Architecture != "amd64" {
		t.Fatalf("descriptor = %+v", desc)
	}
	if !strings.HasSuffix(desc.URL, "/"+version+"/"+img) {
		t.Fatalf("url = %q", desc.URL)
	}

	// ?arch=arm64 resolves the rpi (Raspberry Pi) image.
	rec = f.do(t, http.MethodGet, "/api/cluster/node-image?arch=arm64", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("arm64 status %d, body %s", rec.Code, rec.Body.String())
	}
	var armDesc releases.NodeImageDescriptor
	if err := json.Unmarshal(rec.Body.Bytes(), &armDesc); err != nil {
		t.Fatalf("decode arm64: %v", err)
	}
	if armDesc.SHA256 != armSha || armDesc.Architecture != "arm64" || !strings.HasSuffix(armDesc.URL, "/"+version+"/"+armImg) {
		t.Fatalf("arm64 descriptor = %+v", armDesc)
	}

	// An unrecognized arch is a 400, not a silent fallback.
	if rec := f.do(t, http.MethodGet, "/api/cluster/node-image?arch=mips", "", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad arch, got %d", rec.Code)
	}
}

// A controlplane OS version that is not a plain release tag is refused with a
// clean 503 — no manifest request is made and no internals are returned.
func TestClusterNodeImage_InvalidVersion(t *testing.T) {
	for _, version := range []string{"../../other/repo/releases/download/x", "x/../../y", "x?y", "x#y", "x%2fy", "x y", "x\ny"} {
		t.Run(version, func(t *testing.T) {
			requests := 0
			rel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.WriteHeader(http.StatusNotFound)
			}))
			defer rel.Close()

			f := newAPIFixture(t)
			f.srv.SetReleaseDownloadBase(rel.URL)
			now := time.Now().UTC()
			if err := f.inv.Insert(f.ctx, &proto.Node{
				ID: "x", Role: proto.RoleControlPlane, ImageVersion: version, ImageVersionConfirmedAt: &now,
			}); err != nil {
				t.Fatalf("seed cp node: %v", err)
			}
			rec := f.do(t, http.MethodGet, "/api/cluster/node-image", "", nil)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status %d, want 503; body %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), version) {
				t.Errorf("error body echoes the version: %s", rec.Body.String())
			}
			if requests != 0 {
				t.Errorf("made %d release requests for an invalid version, want 0", requests)
			}
		})
	}
}

func TestClusterFirewallImage(t *testing.T) {
	const version = "2026.07.1-dev.20"
	const img = "rasputin-fw-n100-2026.07.1-dev.20-ab.img.gz"
	const sha = "0badf00ddeadbeef"

	mux := http.NewServeMux()
	// GithubPublicSource lists releases from the firewall source repo, then
	// fetches the picked release's manifest.json from its asset URL.
	mux.HandleFunc("/repos/geekdojo/rasputin-openwrt-firewall/releases", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"tag_name":   version,
			"prerelease": true,
			"assets": []map[string]any{
				{"name": "manifest.json", "browser_download_url": base + "/fw-manifest"},
				{"name": img, "browser_download_url": base + "/dl/" + version + "/" + img},
			},
		}})
	})
	mux.HandleFunc("/fw-manifest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(releases.Manifest{
			Version: version, Channel: "dev",
			Artifacts: []releases.ManifestArtifact{{
				SKU: "fw-n100", Architecture: "amd64", Compatible: releases.FirewallCompatible, Kind: "ab",
				Image: img, SHA256: sha,
			}},
		})
	})
	rel := httptest.NewServer(mux)
	defer rel.Close()

	f := newAPIFixture(t)

	// 503 until an update source is configured.
	if rec := f.do(t, http.MethodGet, "/api/cluster/firewall-image", "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before release source configured, got %d", rec.Code)
	}

	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL), "dev")

	rec := f.do(t, http.MethodGet, "/api/cluster/firewall-image", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var desc releases.NodeImageDescriptor
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if desc.Version != version || desc.SHA256 != sha || desc.Architecture != "amd64" || desc.Image != img {
		t.Fatalf("descriptor = %+v", desc)
	}
	if !strings.HasSuffix(desc.URL, "/"+img) {
		t.Fatalf("url = %q", desc.URL)
	}
}

// channelRecordingSource records the channel every LatestFor call was asked
// for and resolves nothing, so a test can tell which requests reached the
// release source at all.
type channelRecordingSource struct{ channels []string }

func (c *channelRecordingSource) LatestFor(_ context.Context, _ releases.Component, channel string) (*releases.ReleaseInfo, error) {
	c.channels = append(c.channels, channel)
	return nil, nil
}

func (c *channelRecordingSource) Open(context.Context, string) (io.ReadCloser, error) {
	return nil, nil
}

// The firewall-image endpoint is unauthenticated and its channel reaches a log
// line, so a channel that is not a known one is refused before it reaches the
// release source (or the log): an encoded newline would otherwise forge log
// lines (geekdojo/geekdojo-brain#145).
func TestClusterFirewallImage_RejectsUnknownChannel(t *testing.T) {
	f := newAPIFixture(t)
	src := &channelRecordingSource{}
	f.srv.SetReleaseSource(src, releases.ChannelStable)

	for _, q := range []string{"x%0Ay", "nightly", "Dev", "stable%0A"} {
		rec := f.do(t, http.MethodGet, "/api/cluster/firewall-image?channel="+q, "", nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("channel=%s: status %d, want 400 (body %s)", q, rec.Code, rec.Body.String())
		}
	}
	if len(src.channels) != 0 {
		t.Fatalf("LatestFor called for a rejected channel: %q", src.channels)
	}

	// Known channels, and no channel at all (the configured default), still
	// reach the source — with the canonical value.
	for _, tc := range []struct{ query, want string }{
		{"?channel=stable", releases.ChannelStable},
		{"?channel=dev", releases.ChannelDev},
		{"", releases.ChannelStable},
	} {
		src.channels = nil
		rec := f.do(t, http.MethodGet, "/api/cluster/firewall-image"+tc.query, "", nil)
		if rec.Code != http.StatusNotFound { // the recording source resolves no release
			t.Errorf("%q: status %d, want 404 (body %s)", tc.query, rec.Code, rec.Body.String())
		}
		if len(src.channels) != 1 || src.channels[0] != tc.want {
			t.Errorf("%q: LatestFor channels = %q, want [%q]", tc.query, src.channels, tc.want)
		}
	}
}

// clusterOSVersion decides what OS version a NEW node gets flashed with, and
// prefers a CONFIRMED controlplane version over an unconfirmed one (ADR-0005
// Decision 4): an unconfirmed value is one an update outcome told us not to
// trust, and seeding the cluster's newest member from its least reliable fact
// is the wrong default.
func TestClusterOSVersion_PrefersAConfirmedControlPlane(t *testing.T) {
	at := time.Now().UTC()
	nodes := []*proto.Node{
		{ID: "cp-a", Role: proto.RoleControlPlane, ImageVersion: "2026.07.0-dev.104"}, // unconfirmed
		{ID: "cp-b", Role: proto.RoleControlPlane, ImageVersion: "2026.07.0-dev.101", ImageVersionConfirmedAt: &at},
	}
	if got := clusterOSVersion(nodes); got != "2026.07.0-dev.101" {
		t.Errorf("clusterOSVersion = %q, want the CONFIRMED controlplane's version", got)
	}
}

// ...but an unconfirmed version is still used when it is all there is.
// Refusing would mean a cluster whose controlplane update failed to verify
// cannot add nodes at all — turning a stale-version problem into an onboarding
// outage, which is strictly worse than flashing a node one release off and
// fixing it with an ordinary update.
func TestClusterOSVersion_FallsBackToUnconfirmedRatherThanRefusing(t *testing.T) {
	nodes := []*proto.Node{
		{ID: "cp", Role: proto.RoleControlPlane, ImageVersion: "2026.07.0-dev.104"},
	}
	if got := clusterOSVersion(nodes); got != "2026.07.0-dev.104" {
		t.Errorf("clusterOSVersion = %q, want the unconfirmed fallback", got)
	}
}

func TestClusterOSVersion_NoVersionAtAll(t *testing.T) {
	if got := clusterOSVersion([]*proto.Node{{ID: "cp", Role: proto.RoleControlPlane}}); got != "" {
		t.Errorf("clusterOSVersion = %q, want \"\"", got)
	}
}
