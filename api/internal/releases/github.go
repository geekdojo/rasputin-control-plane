package releases

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// githubPublicSource reads releases from a PUBLIC GitHub repo (the mirror
// channel, e.g. geekdojo/rasputin-releases) over anonymous HTTPS. Source repos
// stay private; only signed artifacts are mirrored to the public channel, so
// no token ever lives on an appliance — bundle signatures (verified by RAUC at
// install time) gate authenticity, not repo privacy.
type githubPublicSource struct {
	apiBase string // e.g. https://api.github.com
	repo    string // e.g. geekdojo/rasputin-releases
	meta    *http.Client
	dl      *http.Client
}

// NewGithubPublicSource builds a Source against repo (owner/name) using the
// given API base (override for tests/mirrors; default https://api.github.com).
func NewGithubPublicSource(apiBase, repo string) Source {
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	return &githubPublicSource{
		apiBase: strings.TrimRight(apiBase, "/"),
		repo:    repo,
		// Small JSON calls: bounded total timeout.
		meta: &http.Client{Timeout: 30 * time.Second},
		// Large asset downloads (100s of MB): no total timeout; cancellation
		// rides the request context instead.
		dl: &http.Client{},
	}
}

// httpError is returned when the release API or an asset host answers with a
// non-200 status. It carries the status code so callers (friendlyFetchError)
// can classify rate-limiting vs. server errors without string-matching. Its
// Error() string is unchanged from the previous inline fmt.Errorf, so logs and
// other callers see the same text.
type httpError struct {
	status int
	url    string
	body   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("GET %s: status %d: %s", e.url, e.status, e.body)
}

// ghRelease is the subset of the GitHub Releases API we read.
type ghRelease struct {
	TagName    string `json:"tag_name"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (g *githubPublicSource) LatestFor(ctx context.Context, comp Component, channel string) (*ReleaseInfo, error) {
	var rels []ghRelease
	if err := g.getJSON(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=100", g.apiBase, g.repo), &rels); err != nil {
		return nil, err
	}

	wantPrerelease := channel == "dev"
	var best *ghRelease
	var bestVer string
	for i := range rels {
		r := &rels[i]
		if !strings.HasPrefix(r.TagName, comp.TagPrefix) {
			continue
		}
		if r.Prerelease != wantPrerelease {
			continue
		}
		ver := strings.TrimPrefix(r.TagName, comp.TagPrefix)
		if best == nil {
			best, bestVer = r, ver
			continue
		}
		// Skip unparseable tags rather than letting them win.
		if c, err := Compare(comp.Scheme, bestVer, ver); err == nil && c < 0 {
			best, bestVer = r, ver
		}
	}
	if best == nil {
		return nil, nil // no matching release on this channel
	}

	info := &ReleaseInfo{
		Component: comp.ID,
		Version:   bestVer,
		Channel:   channel,
		Tag:       best.TagName,
		assetURLs: make(map[string]string, len(best.Assets)),
	}
	var manifestURL string
	for _, a := range best.Assets {
		info.assetURLs[a.Name] = a.URL
		if a.Name == "manifest.json" {
			manifestURL = a.URL
		}
	}
	if manifestURL == "" {
		return nil, fmt.Errorf("release %s has no manifest.json asset", best.TagName)
	}
	if err := g.getJSON(ctx, manifestURL, &info.Manifest); err != nil {
		return nil, fmt.Errorf("fetch manifest for %s: %w", best.TagName, err)
	}
	// Prefer the manifest's own version string if present (authoritative).
	if info.Manifest.Version != "" {
		info.Version = info.Manifest.Version
	}
	if info.Manifest.Channel != "" {
		info.Channel = info.Manifest.Channel
	}
	return info, nil
}

func (g *githubPublicSource) Open(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rasputin-control-plane")
	resp, err := g.dl.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
}

func (g *githubPublicSource) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	// GitHub requires a User-Agent; anonymous requests are rate-limited per IP
	// (60/hr) which is ample for a manual "Check for Updates" click.
	req.Header.Set("User-Agent", "rasputin-control-plane")
	req.Header.Set("Accept", "application/json")
	resp, err := g.meta.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return &httpError{status: resp.StatusCode, url: url, body: strings.TrimSpace(string(body))}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
