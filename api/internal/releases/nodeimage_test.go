package releases

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublicNodeImage(t *testing.T) {
	const version = "2026.06.0-dev.31"
	const img = "rasputin-os-n100-2026.06.0-dev.31.img.xz"
	const sha = "6b88e011e816ae354d62d03957aa55472ccdb2f70c1dd12f31d3ff09e3c2a8c6"

	mux := http.NewServeMux()
	mux.HandleFunc("/geekdojo/rasputin-releases/releases/download/os-"+version+"/manifest.json",
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Manifest{
				Version: version, Channel: "dev",
				Artifacts: []ManifestArtifact{{
					Compatible: "rasputin-n100", Image: img,
					ImageSha256: sha, SHA256: "raucb-sha", SizeBytes: 123,
				}},
			})
		})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	desc, err := PublicNodeImage(context.Background(), srv.Client(), srv.URL, "geekdojo/rasputin-releases", version, "rasputin-n100")
	if err != nil {
		t.Fatalf("PublicNodeImage: %v", err)
	}
	if desc.Version != version {
		t.Errorf("version = %q, want %q", desc.Version, version)
	}
	if desc.SHA256 != sha {
		t.Errorf("sha256 = %q, want %q", desc.SHA256, sha)
	}
	wantURL := srv.URL + "/geekdojo/rasputin-releases/releases/download/os-" + version + "/" + img
	if desc.URL != wantURL {
		t.Errorf("url = %q, want %q", desc.URL, wantURL)
	}
}

func TestPublicNodeImage_ManifestMissing(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := PublicNodeImage(context.Background(), srv.Client(), srv.URL, "geekdojo/rasputin-releases", "2026.06.0-dev.31", "rasputin-n100"); err == nil {
		t.Fatal("expected error when the manifest 404s")
	}
}

func TestPublicNodeImage_NoMatchingArtifact(t *testing.T) {
	const version = "2026.06.0-dev.31"
	mux := http.NewServeMux()
	mux.HandleFunc("/r/releases/download/os-"+version+"/manifest.json",
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Manifest{
				Version: version,
				// Wrong SKU + missing imageSha256: neither is a usable node image.
				Artifacts: []ManifestArtifact{{Compatible: "rasputin-fw-n100", Image: "fw.img.gz"}},
			})
		})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if _, err := PublicNodeImage(context.Background(), srv.Client(), srv.URL, "r", version, "rasputin-n100"); err == nil {
		t.Fatal("expected error when no rasputin-n100 image is present")
	}
}
