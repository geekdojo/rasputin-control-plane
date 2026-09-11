package catalogsync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeHub is a stand-in GitHub: a release list plus asset bytes.
type fakeHub struct {
	releases []map[string]any
	assets   map[string][]byte
	hits     map[string]int
	srv      *httptest.Server
}

func newHub(t *testing.T) *fakeHub {
	t.Helper()
	h := &fakeHub{assets: map[string][]byte{}, hits: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		h.hits["list"]++
		_ = json.NewEncoder(w).Encode(h.releases)
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		h.hits[r.URL.Path]++
		b, ok := h.assets[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

// release registers a catalog release with both assets present.
func (h *fakeHub) release(version int, prerelease bool, bundle, sig []byte) {
	bp := fmt.Sprintf("/dl/catalog-v%d/catalog.json", version)
	sp := bp + ".sig"
	h.assets[bp], h.assets[sp] = bundle, sig
	h.releases = append(h.releases, map[string]any{
		"tag_name": fmt.Sprintf("catalog-v%d", version), "prerelease": prerelease,
		"assets": []map[string]any{
			{"name": assetBundle, "browser_download_url": h.srv.URL + bp},
			{"name": assetSig, "browser_download_url": h.srv.URL + sp},
		},
	})
}

// unsigned registers a catalog release that carries catalog.json but no .sig —
// a publish that failed halfway.
func (h *fakeHub) unsigned(version int, prerelease bool) {
	h.releases = append(h.releases, map[string]any{
		"tag_name": fmt.Sprintf("catalog-v%d", version), "prerelease": prerelease,
		"assets": []map[string]any{{"name": assetBundle, "browser_download_url": "http://x/b"}},
	})
}

// promote does what the catalog repo does to promote a version to stable:
// turn the prerelease flag off on the release that already exists.
func (h *fakeHub) promote(t *testing.T, version int) {
	t.Helper()
	tag := fmt.Sprintf("catalog-v%d", version)
	for _, r := range h.releases {
		if r["tag_name"] == tag {
			r["prerelease"] = false
			return
		}
	}
	t.Fatalf("no release %s to promote", tag)
}

func (h *fakeHub) fetcher(channel string) *Fetcher {
	f := NewFetcher("geekdojo/rasputin-app-catalog", h.srv.URL, channel)
	return f
}

func mustBundle(t *testing.T, version int) []byte {
	t.Helper()
	raw, err := marshal(bundle(version, "tile"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAvailable_PicksTheHighestOnTheChannel(t *testing.T) {
	cases := map[string]struct {
		channel    string
		prerelease bool
	}{
		// Dev takes prereleases (among everything else).
		"dev": {channel: "dev", prerelease: true},
		// Stable takes full releases, and the prerelease v99 added below is on
		// the wrong channel for it.
		"stable": {channel: "stable", prerelease: false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHub(t)
			h.release(2, c.prerelease, mustBundle(t, 2), []byte("s"))
			h.release(11, c.prerelease, mustBundle(t, 11), []byte("s")) // lexically < "2"
			h.release(7, c.prerelease, mustBundle(t, 7), []byte("s"))
			if c.channel == "stable" {
				h.release(99, true, mustBundle(t, 99), []byte("s")) // prerelease, wrong channel
			}

			v, bURL, sURL, err := h.fetcher(c.channel).Available(context.Background())
			if err != nil {
				t.Fatalf("Available: %v", err)
			}
			if v != 11 {
				t.Fatalf("got v%d, want v11 — versions must order numerically, not lexically, and stable must skip prereleases", v)
			}
			if !strings.Contains(bURL, "catalog-v11") || !strings.Contains(sURL, "catalog-v11") {
				t.Errorf("asset URLs point at the wrong release: %s %s", bURL, sURL)
			}
		})
	}
}

// Dev is a superset of stable: it considers every catalog release, prerelease
// or not, and takes the highest. Stable takes full releases only. The catalog
// repo promotes a version by flipping the prerelease flag on the existing
// release (ADR-0006 Decision 9, 2026-09-11 note); an either/or filter made
// that promotion drop the version out of dev, so a freshly provisioned dev
// cluster adopted an older prerelease than stable clusters were running.
func TestAvailable_DevIsASupersetOfStable(t *testing.T) {
	cases := map[string]struct {
		setup func(h *fakeHub)
		want  map[string]int // channel -> version Available must report
	}{
		// The 2026-09-11 state: v18 and v19 promoted, v17 still a prerelease.
		// Under the old filter dev resolved to v17.
		"prerelease under two full releases": {
			setup: func(h *fakeHub) {
				h.release(17, true, mustBundle(t, 17), []byte("s"))
				h.release(18, false, mustBundle(t, 18), []byte("s"))
				h.release(19, false, mustBundle(t, 19), []byte("s"))
			},
			want: map[string]int{"dev": 19, "stable": 19},
		},
		"prerelease on top of a full release": {
			setup: func(h *fakeHub) {
				h.release(19, false, mustBundle(t, 19), []byte("s"))
				h.release(20, true, mustBundle(t, 20), []byte("s"))
			},
			want: map[string]int{"dev": 20, "stable": 19},
		},
		// Stable finding nothing is the normal empty-stream state (0, nil),
		// not an error.
		"only prereleases": {
			setup: func(h *fakeHub) {
				h.release(3, true, mustBundle(t, 3), []byte("s"))
				h.release(12, true, mustBundle(t, 12), []byte("s"))
				h.release(8, true, mustBundle(t, 8), []byte("s"))
			},
			want: map[string]int{"dev": 12, "stable": 0},
		},
		// Accepting full releases on dev must not relax the asset rule: a
		// full release without its signature is skipped on both channels, and
		// dev does not fall back to the lower prerelease over the full v18.
		"full release missing its signature": {
			setup: func(h *fakeHub) {
				h.release(17, true, mustBundle(t, 17), []byte("s"))
				h.release(18, false, mustBundle(t, 18), []byte("s"))
				h.unsigned(19, false)
			},
			want: map[string]int{"dev": 18, "stable": 18},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHub(t)
			c.setup(h)
			for _, channel := range []string{"dev", "stable"} {
				want := c.want[channel]
				v, bURL, sURL, err := h.fetcher(channel).Available(context.Background())
				if err != nil {
					t.Fatalf("%s: Available: %v", channel, err)
				}
				if v != want {
					t.Errorf("channel %q got v%d, want v%d", channel, v, want)
					continue
				}
				if want == 0 {
					if bURL != "" || sURL != "" {
						t.Errorf("channel %q found nothing but returned asset URLs %q %q", channel, bURL, sURL)
					}
					continue
				}
				tag := fmt.Sprintf("catalog-v%d/", want)
				if !strings.Contains(bURL, tag) || !strings.Contains(sURL, tag) {
					t.Errorf("channel %q asset URLs point at the wrong release: %s %s", channel, bURL, sURL)
				}
			}
		})
	}
}

// An empty stream is a normal state on a young channel. Reporting it as an
// error would put a red banner on every new cluster.
func TestAvailable_EmptyStreamIsNotAnError(t *testing.T) {
	h := newHub(t)
	v, _, _, err := h.fetcher("dev").Available(context.Background())
	if err != nil || v != 0 {
		t.Fatalf("got (v%d, %v), want (0, nil)", v, err)
	}
}

// One malformed publish must not wedge the fleet on an older catalog forever.
func TestAvailable_SkipsAReleaseMissingAnAsset(t *testing.T) {
	h := newHub(t)
	h.release(4, true, mustBundle(t, 4), []byte("s"))
	h.releases = append(h.releases, map[string]any{
		"tag_name": "catalog-v8", "prerelease": true,
		"assets": []map[string]any{{"name": assetBundle, "browser_download_url": "http://x/b"}},
	})
	v, _, _, err := h.fetcher("dev").Available(context.Background())
	if err != nil {
		t.Fatalf("Available: %v", err)
	}
	if v != 4 {
		t.Fatalf("got v%d; a release missing its signature must be skipped, leaving v4", v)
	}
}

func TestParseCatalogTag(t *testing.T) {
	ok := map[string]int{"catalog-v1": 1, "catalog-v42": 42}
	for tag, want := range ok {
		if v, valid := parseCatalogTag(tag); !valid || v != want {
			t.Errorf("%q -> (%d,%v), want (%d,true)", tag, v, valid, want)
		}
	}
	// Strictness is the point: anything non-integer is rejected before it can
	// reach a filename.
	for _, tag := range []string{"v1", "catalog-v", "catalog-v0", "catalog-v-1",
		"catalog-v1.2", "catalog-v01a", "catalog-v../../etc/passwd", "2026.08.4"} {
		if _, valid := parseCatalogTag(tag); valid {
			t.Errorf("%q was accepted; it must not be", tag)
		}
	}
}

// The cap is a refusal to let a remote server decide how much disk to consume
// before anything has been verified.
func TestDownload_RefusesAnOversizedAsset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blob := make([]byte, 1<<20)
		for i := 0; i < (MaxBundleBytes/len(blob))+2; i++ {
			if _, err := w.Write(blob); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	f := NewFetcher("o/r", srv.URL, "dev")
	err := f.download(context.Background(), srv.URL+"/big", t.TempDir()+"/out.bin")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want a size refusal, got %v", err)
	}
}

func TestSync_AppliesANewerCatalog(t *testing.T) {
	h := newHub(t)
	h.release(5, true, mustBundle(t, 5), []byte("sig"))
	s, _ := newStore(t, &fakeVerifier{}, bundle(1, "floor"))

	changed, err := Sync(context.Background(), h.fetcher("dev"), s)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !changed || s.Current().Version != 5 {
		t.Fatalf("changed=%v version=v%d, want true/v5", changed, s.Current().Version)
	}
}

// The daily poll is almost always a no-op. Downloading first would mean every
// cluster pulling a bundle it discards, every day, forever.
func TestSync_SkipsTheDownloadWhenNothingIsNewer(t *testing.T) {
	h := newHub(t)
	h.release(5, true, mustBundle(t, 5), []byte("sig"))
	s, _ := newStore(t, &fakeVerifier{}, bundle(5, "floor"))

	changed, err := Sync(context.Background(), h.fetcher("dev"), s)
	if err != nil || changed {
		t.Fatalf("got (changed=%v, %v), want (false, nil)", changed, err)
	}
	for path, n := range h.hits {
		if strings.HasPrefix(path, "/dl/") && n > 0 {
			t.Errorf("downloaded %s despite having nothing to gain (%d hits)", path, n)
		}
	}
}

// The reported failure, end to end: a dev cluster fresh on its v14 floor, with
// v18 and v19 already promoted to stable and v17 left as a prerelease, must
// adopt v19 — not v17, which lacks tiles current apps need.
func TestSync_FreshDevClusterAdoptsAPromotedCatalog(t *testing.T) {
	h := newHub(t)
	h.release(17, true, mustBundle(t, 17), []byte("sig"))
	h.release(18, false, mustBundle(t, 18), []byte("sig"))
	h.release(19, false, mustBundle(t, 19), []byte("sig"))
	s, _ := newStore(t, &fakeVerifier{}, bundle(14, "floor"))

	changed, err := Sync(context.Background(), h.fetcher("dev"), s)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !changed || s.Current().Version != 19 {
		t.Fatalf("changed=%v version=v%d, want true/v19", changed, s.Current().Version)
	}
}

// Promotion must not move a dev cluster that is already on the top version:
// no re-download, no change, and never a step down (ADR-0006 Decision 5).
func TestSync_PromotionDoesNotMoveADevClusterAlreadyOnIt(t *testing.T) {
	h := newHub(t)
	h.release(17, true, mustBundle(t, 17), []byte("sig"))
	h.release(18, true, mustBundle(t, 18), []byte("sig"))
	h.release(19, true, mustBundle(t, 19), []byte("sig"))
	s, _ := newStore(t, &fakeVerifier{}, bundle(14, "floor"))

	if changed, err := Sync(context.Background(), h.fetcher("dev"), s); err != nil || !changed || s.Current().Version != 19 {
		t.Fatalf("first sync: changed=%v version=v%d err=%v, want true/v19/nil", changed, s.Current().Version, err)
	}
	downloads := func() int {
		n := 0
		for path, hits := range h.hits {
			if strings.HasPrefix(path, "/dl/") {
				n += hits
			}
		}
		return n
	}
	before := downloads()

	h.promote(t, 18)
	h.promote(t, 19)
	for i := 0; i < 3; i++ {
		changed, err := Sync(context.Background(), h.fetcher("dev"), s)
		if err != nil || changed {
			t.Fatalf("sync %d after promotion: (changed=%v, %v), want (false, nil)", i, changed, err)
		}
		if got := s.Current().Version; got != 19 {
			t.Fatalf("sync %d after promotion moved the cluster to v%d; it must stay on v19", i, got)
		}
	}
	if after := downloads(); after != before {
		t.Errorf("promotion caused %d re-downloads of a catalog the cluster already runs", after-before)
	}
}

func TestSync_EmptyStreamLeavesTheFloorInPlaceWithoutError(t *testing.T) {
	h := newHub(t)
	s, _ := newStore(t, &fakeVerifier{}, bundle(2, "floor"))
	changed, err := Sync(context.Background(), h.fetcher("dev"), s)
	if err != nil {
		t.Fatalf("an empty channel must not be an error: %v", err)
	}
	if changed || s.Current().Version != 2 {
		t.Fatalf("changed=%v version=v%d", changed, s.Current().Version)
	}
}

// A refused bundle must leave the catalog untouched all the way through Sync,
// not just inside Apply.
func TestSync_RefusedBundleKeepsTheCurrentCatalog(t *testing.T) {
	h := newHub(t)
	h.release(9, true, mustBundle(t, 9), []byte("sig"))
	s, _ := newStore(t, &fakeVerifier{err: fmt.Errorf("wrong purpose")}, bundle(3, "floor"))

	changed, err := Sync(context.Background(), h.fetcher("dev"), s)
	if err == nil {
		t.Fatal("want the signature failure surfaced")
	}
	if changed || s.Current().Version != 3 {
		t.Fatalf("changed=%v version=v%d, want false/v3", changed, s.Current().Version)
	}
	if _, fetched, note := s.State(); fetched || note == "" {
		t.Errorf("operator-visible state should show the failure; fetched=%v note=%q", fetched, note)
	}
}
