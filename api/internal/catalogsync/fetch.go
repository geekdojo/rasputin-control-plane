package catalogsync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Fetcher retrieves published catalog bundles from a GitHub release stream.
//
// WHY THIS IS NOT releases.Source. That interface is the OS/firmware/CP update
// path and it does two things a catalog release cannot satisfy: it REQUIRES a
// manifest.json asset (erroring without one) and it orders releases with
// CalVer/semver Compare. A catalog release ships catalog.json + .sig and a
// plain monotonic integer. Bending a shipped, security-relevant path to
// accommodate a second shape is worse than a focused client, so this is the
// focused client — and it keeps the same property ADR-0002 cares about: the
// endpoint is configuration, not a constant.
type Fetcher struct {
	// Repo is owner/name of the catalog repository.
	Repo string
	// APIBase is the GitHub API root. Swappable for tests and for the
	// aggregation endpoint ADR-0006's revisit criteria anticipate.
	APIBase string
	// Channel selects the release stream: "dev" takes prereleases, anything
	// else takes stable, mirroring how components resolve a channel.
	Channel string

	HTTP *http.Client
}

// MaxBundleBytes caps what will be written to disk for either asset.
//
// The published catalog is ~27 KB. The cap is not a size estimate — it is a
// refusal to let a remote server decide how much of the appliance's disk to
// consume before a signature has been checked. Verification happens after the
// download, so the download itself is the unauthenticated step.
const MaxBundleBytes = 8 << 20

const (
	assetBundle = "catalog.json"
	assetSig    = "catalog.json.sig"
	tagPrefix   = "catalog-v"
)

// NewFetcher applies the defaults a control plane should run with.
func NewFetcher(repo, apiBase, channel string) *Fetcher {
	if repo == "" {
		repo = "geekdojo/rasputin-app-catalog"
	}
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	return &Fetcher{
		Repo:    repo,
		APIBase: strings.TrimRight(apiBase, "/"),
		Channel: channel,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

type ghRelease struct {
	TagName    string `json:"tag_name"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Available reports the highest published catalog version on this channel, and
// where to get its two assets. Version 0 with a nil error means the channel has
// no catalog release yet — an empty stream is a normal state on a new repo, not
// a failure to report to the operator.
func (f *Fetcher) Available(ctx context.Context) (version int, bundleURL, sigURL string, err error) {
	var rels []ghRelease
	url := fmt.Sprintf("%s/repos/%s/releases?per_page=100", f.APIBase, f.Repo)
	if err := f.getJSON(ctx, url, &rels); err != nil {
		return 0, "", "", err
	}

	wantPrerelease := f.Channel == "dev"
	best := 0
	for _, r := range rels {
		if r.Prerelease != wantPrerelease {
			continue
		}
		v, ok := parseCatalogTag(r.TagName)
		if !ok || v <= best {
			continue
		}
		var b, s string
		for _, a := range r.Assets {
			switch a.Name {
			case assetBundle:
				b = a.URL
			case assetSig:
				s = a.URL
			}
		}
		// A release missing either asset is skipped rather than failing the
		// poll: one malformed publish must not wedge a cluster on an older
		// catalog forever, and the next good release should still be reachable.
		if b == "" || s == "" {
			continue
		}
		best, bundleURL, sigURL = v, b, s
	}
	return best, bundleURL, sigURL, nil
}

// FetchInto downloads both assets into dir and returns their paths.
func (f *Fetcher) FetchInto(ctx context.Context, dir, bundleURL, sigURL string) (string, string, error) {
	bp := filepath.Join(dir, assetBundle)
	if err := f.download(ctx, bundleURL, bp); err != nil {
		return "", "", err
	}
	sp := filepath.Join(dir, assetSig)
	if err := f.download(ctx, sigURL, sp); err != nil {
		return "", "", err
	}
	return bp, sp, nil
}

// parseCatalogTag reads "catalog-v42" as 42.
//
// Strict on purpose: strconv.Atoi rejects anything that is not a plain integer,
// so a tag someone pushes by hand cannot smuggle a path separator or a
// surprising ordering into a filename downstream.
func parseCatalogTag(tag string) (int, bool) {
	rest, ok := strings.CutPrefix(tag, tagPrefix)
	if !ok {
		return 0, false
	}
	v, err := strconv.Atoi(rest)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

func (f *Fetcher) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "rasputin-control-plane")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := f.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("catalog releases: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, MaxBundleBytes)).Decode(out)
}

func (f *Fetcher) download(ctx context.Context, url, dest string) (err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "rasputin-control-plane")
	resp, err := f.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerm)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()

	// LimitReader with one spare byte, so hitting the cap is detectable rather
	// than silently producing a truncated file that then fails verification
	// with a misleading "bad signature".
	n, err := io.Copy(out, io.LimitReader(resp.Body, MaxBundleBytes+1))
	if err != nil {
		return err
	}
	if n > MaxBundleBytes {
		return fmt.Errorf("download %s: refused, exceeds %d bytes", url, MaxBundleBytes)
	}
	return nil
}

func (f *Fetcher) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}
