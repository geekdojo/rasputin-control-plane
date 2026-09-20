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

// githubPublicSource reads releases directly from each component's PUBLIC
// GitHub source repo (e.g. geekdojo/rasputin-os) over anonymous HTTPS — the
// repo comes from the Component (see ADR-0002; the old rasputin-releases mirror
// is retired). No token ever lives on an appliance: bundle signatures (verified
// by RAUC at install time) gate authenticity, not repo privacy.
type githubPublicSource struct {
	apiBase string // e.g. https://api.github.com
	meta    *http.Client
	dl      *http.Client
	// verifier checks manifest.json.sig. Nil is a valid state — a control
	// plane with no trust root — and then every component at or above its
	// signing floor fails to resolve, rather than resolving unverified.
	verifier ManifestVerifier
}

// NewGithubPublicSource builds a Source that reads each component's releases
// from the component's own source repo, using the given API base (override for
// a proxy/CDN or tests; default https://api.github.com), and verifying each
// release manifest's detached signature with v.
func NewGithubPublicSource(apiBase string, v ManifestVerifier) Source {
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	return &githubPublicSource{
		apiBase:  strings.TrimRight(apiBase, "/"),
		verifier: v,
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
	if comp.Repo == "" {
		return nil, fmt.Errorf("component %q has no source repo configured", comp.ID)
	}
	var rels []ghRelease
	if err := g.getJSON(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=100", g.apiBase, comp.Repo), &rels); err != nil {
		return nil, err
	}

	wantPrerelease := channel == ChannelDev
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
	var manifestURL, manifestSigURL string
	for _, a := range best.Assets {
		info.assetURLs[a.Name] = a.URL
		switch a.Name {
		case "manifest.json":
			manifestURL = a.URL
		case "manifest.json.sig":
			manifestSigURL = a.URL
		}
	}
	if manifestURL == "" {
		return nil, fmt.Errorf("release %s has no manifest.json asset", best.TagName)
	}
	manifestRaw, err := fetchBytes(ctx, g.meta, manifestURL)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest for %s: %w", best.TagName, err)
	}
	// Absent asset and failed fetch are deliberately the same case: whether a
	// missing signature is fatal is VerifyManifest's call, and it refuses both
	// identically above the floor.
	var sigDER []byte
	if manifestSigURL != "" {
		sigDER, _ = fetchBytes(ctx, g.meta, manifestSigURL)
	}
	res, err := VerifyManifest(g.verifier, comp, bestVer, manifestRaw, sigDER)
	if err != nil {
		return nil, err
	}
	if res != nil {
		info.Signer = res.Signer
	}
	if err := json.Unmarshal(manifestRaw, &info.Manifest); err != nil {
		return nil, fmt.Errorf("parse manifest for %s: %w", best.TagName, err)
	}
	// The manifest's own version used to win here as "authoritative". It is
	// authoritative only once it is signed — and once it is, VerifyManifest has
	// already required it to equal the tag, so there is nothing left to prefer.
	// Below the floor the two can still disagree, and taking the manifest's
	// word for which release this is would let an unsigned document rename an
	// unsigned release. The tag is what was fetched; the tag is what it is.
	if info.Manifest.Version != "" && info.Manifest.Version != bestVer {
		return nil, fmt.Errorf("%w: tag %q carries a manifest for %q", ErrManifestVersionMismatch, best.TagName, info.Manifest.Version)
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
