package releases

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
)

func TestPublicNodeImage(t *testing.T) {
	const version = "2026.06.0-dev.31"
	const img = "rasputin-os-n100-2026.06.0-dev.31.img.xz"
	const sha = "6b88e011e816ae354d62d03957aa55472ccdb2f70c1dd12f31d3ff09e3c2a8c6"

	mux := http.NewServeMux()
	mux.HandleFunc("/geekdojo/rasputin-os/releases/download/"+version+"/manifest.json",
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

	desc, err := PublicNodeImage(context.Background(), srv.Client(), nil, srv.URL, testComponent("geekdojo/rasputin-os"), version, "rasputin-n100")
	if err != nil {
		t.Fatalf("PublicNodeImage: %v", err)
	}
	if desc.Version != version {
		t.Errorf("version = %q, want %q", desc.Version, version)
	}
	if desc.SHA256 != sha {
		t.Errorf("sha256 = %q, want %q", desc.SHA256, sha)
	}
	wantURL := srv.URL + "/geekdojo/rasputin-os/releases/download/" + version + "/" + img
	if desc.URL != wantURL {
		t.Errorf("url = %q, want %q", desc.URL, wantURL)
	}
}

func TestPublicNodeImage_ManifestMissing(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := PublicNodeImage(context.Background(), srv.Client(), nil, srv.URL, testComponent("geekdojo/rasputin-os"), "2026.06.0-dev.31", "rasputin-n100"); err == nil {
		t.Fatal("expected error when the manifest 404s")
	}
}

func TestPublicNodeImage_NoMatchingArtifact(t *testing.T) {
	const version = "2026.06.0-dev.31"
	mux := http.NewServeMux()
	mux.HandleFunc("/r/releases/download/"+version+"/manifest.json",
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Manifest{
				Version: version,
				// Wrong SKU + missing imageSha256: neither is a usable node image.
				Artifacts: []ManifestArtifact{{Compatible: "rasputin-fw-n100", Image: "fw.img.gz"}},
			})
		})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if _, err := PublicNodeImage(context.Background(), srv.Client(), nil, srv.URL, testComponent("r"), version, "rasputin-n100"); err == nil {
		t.Fatal("expected error when no rasputin-n100 image is present")
	}
}

func TestArchCompatible(t *testing.T) {
	cases := []struct {
		arch string
		want string
		ok   bool
	}{
		// Empty is UNDETERMINABLE, not amd64. A node that never said which
		// arch it is must not be planned into an amd64 cascade with full
		// confidence — it fails at install and burns the maxFailures budget
		// for a node that was never a valid target (#67). The flasher's
		// amd64 default lives in handleClusterNodeImage, where a human chose
		// it, not here where it becomes a guess about a fact.
		{"", "", false},
		{"amd64", "rasputin-n100", true},      // N100 / Intel
		{"arm64", "rasputin-rpi-arm64", true}, // rpi: Pi 4 / Pi 5 / CM5
		{"mips", "", false},                   // unsupported
		{"x86_64", "", false},                 // not the canonical name
	}
	for _, c := range cases {
		got, ok := ArchCompatible(c.arch)
		if got != c.want || ok != c.ok {
			t.Errorf("ArchCompatible(%q) = (%q, %v), want (%q, %v)", c.arch, got, ok, c.want, c.ok)
		}
	}
}

// TestPublicNodeImage_VersionCannotTraverse: the version is spliced into a
// request path and the returned URL, and Go's http client does not clean ".."
// out of a request path. A version that is not a single release-tag segment
// must never produce a request or a URL outside
// <downloadBase>/<repo>/releases/download/. The test records the raw request
// path a local httptest server receives; it makes no request to github.com.
func TestPublicNodeImage_VersionCannotTraverse(t *testing.T) {
	const repo = "geekdojo/rasputin-os"
	wantPrefix := "/" + repo + "/releases/download/"

	var gotPaths []string
	mux := http.NewServeMux()
	// Answer any manifest request with a usable manifest, and record the raw
	// request path (RequestURI preserves ".." and the query string).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.RequestURI)
		if strings.HasSuffix(r.URL.Path, "/manifest.json") {
			_ = json.NewEncoder(w).Encode(Manifest{
				Artifacts: []ManifestArtifact{{
					Compatible: "rasputin-n100", Image: "os.img.xz", ImageSha256: "deadbeef",
				}},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	versions := []string{
		"../../../other/repo/releases/download/x",
		"x?y",
		"x#y",
		"x/../../y",
	}
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			gotPaths = nil
			desc, err := PublicNodeImage(context.Background(), srv.Client(), nil, srv.URL, testComponent(repo), v, "rasputin-n100")
			for _, p := range gotPaths {
				// Compare against the cleaned path: if cleaning changes it, the
				// request left the download prefix.
				clean := path.Clean(strings.SplitN(strings.SplitN(p, "?", 2)[0], "#", 2)[0])
				if !strings.HasPrefix(clean, wantPrefix) {
					t.Errorf("version %q made a request to %q (cleaned %q) — outside %q",
						v, p, clean, wantPrefix)
				}
			}
			if err == nil && desc != nil {
				u, perr := url.Parse(desc.URL)
				if perr == nil {
					clean := path.Clean(u.Path)
					if !strings.HasPrefix(clean, wantPrefix) {
						t.Errorf("version %q returned descriptor URL %q (path %q) — outside %q",
							v, desc.URL, clean, wantPrefix)
					}
				}
			}
		})
	}
}

func TestValidReleaseVersion(t *testing.T) {
	accept := []string{
		// Tags the OS / firewall / control-plane release pipelines publish.
		"2026.09.1",
		"2026.09.2-dev.214",
		"2026.08.5-dev.187",
		"2026.06.0-dev.31",
		"2026.7.0",
		"v0.8.5",
		"v0.8.7-dev.2",
		"0.0.0-dev",
		"1.2.3+build.5",
		"dev",
	}
	for _, v := range accept {
		if !ValidReleaseVersion(v) {
			t.Errorf("ValidReleaseVersion(%q) = false, want true", v)
		}
	}
	reject := []string{
		"",
		".",
		"..",
		".hidden",
		"-dev.1",
		"x/y",
		"../x",
		"x/../../y",
		"x..y",
		`x\y`,
		"x?y",
		"x#y",
		"x%2fy",
		"x y",
		" 2026.09.1",
		"2026.09.1\n",
		"x\ty",
		"x\x00y",
		"x\x7fy",
		"2026.09.1:x",
		"2026.09.1;x",
		"x@y",
		"x~y",
		"é",
		strings.Repeat("1", maxPathSegment+1),
	}
	for _, v := range reject {
		if ValidReleaseVersion(v) {
			t.Errorf("ValidReleaseVersion(%q) = true, want false", v)
		}
	}
	if !ValidReleaseVersion(strings.Repeat("1", maxPathSegment)) {
		t.Errorf("a %d-byte version must be accepted", maxPathSegment)
	}
}

func TestPublicNodeImage_InvalidVersionMakesNoRequest(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	for _, v := range []string{"", "x/y", "../x", "x?y", "x#y", "x%2fy", "x y"} {
		_, err := PublicNodeImage(context.Background(), srv.Client(), nil, srv.URL, testComponent("geekdojo/rasputin-os"), v, "rasputin-n100")
		if !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("version %q: err = %v, want ErrInvalidVersion", v, err)
		}
	}
	if requests != 0 {
		t.Errorf("made %d requests for invalid versions, want 0", requests)
	}
}

func TestPublicNodeImage_ManifestImageName(t *testing.T) {
	const version = "2026.09.2-dev.214"
	cases := []struct {
		image   string
		wantErr bool
	}{
		{"rasputin-os-n100-2026.09.2-dev.214.img.xz", false},
		{"rasputin-os-rpi-2026.09.1.img.xz", false},
		{"../../other/repo/releases/download/x/os.img.xz", true},
		{"sub/os.img.xz", true},
		{"os.img.xz?x=y", true},
		{"os.img.xz#x", true},
		{"os%2fimg.xz", true},
		{"..", true},
		{"os img.xz", true},
	}
	for _, tc := range cases {
		t.Run(tc.image, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/geekdojo/rasputin-os/releases/download/"+version+"/manifest.json",
				func(w http.ResponseWriter, r *http.Request) {
					_ = json.NewEncoder(w).Encode(Manifest{
						Artifacts: []ManifestArtifact{{
							Compatible: "rasputin-n100", Image: tc.image, ImageSha256: "deadbeef",
						}},
					})
				})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			desc, err := PublicNodeImage(context.Background(), srv.Client(), nil, srv.URL, testComponent("geekdojo/rasputin-os"), version, "rasputin-n100")
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidAssetName) {
					t.Fatalf("err = %v (desc %+v), want ErrInvalidAssetName", err, desc)
				}
				return
			}
			if err != nil {
				t.Fatalf("PublicNodeImage: %v", err)
			}
			want := srv.URL + "/geekdojo/rasputin-os/releases/download/" + version + "/" + tc.image
			if desc.URL != want {
				t.Fatalf("url = %q, want %q", desc.URL, want)
			}
		})
	}
}

// testComponent is an OS-shaped component with NO signing floor, for the cases
// that predate manifest signatures and are about URL and manifest handling
// rather than about signatures. The floor's own behaviour is covered in
// manifestsig_test.go, where it is set deliberately.
func testComponent(repo string) Component {
	return Component{ID: "os", Repo: repo, Scheme: SchemeCalVer}
}
