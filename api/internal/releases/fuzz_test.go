package releases

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The node-image resolver is reachable unauthenticated, and both of the values
// it splices into a download URL come from elsewhere: the version from a node's
// registration, the asset name from a manifest fetched over the network. The
// invariant is that neither can move the URL off the release download path —
// what flash.sh fetches must always be an asset of the release it asked for.

const (
	fuzzBase = "https://github.com"
	fuzzRepo = "geekdojo/rasputin-os"
	fuzzSKU  = "rasputin-rpi-arm64"
)

// captureTransport serves one canned manifest body and records every URL asked
// for, so the harness can assert on the request that would have gone out.
type captureTransport struct {
	body   []byte
	status int
	asked  []string
}

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.asked = append(c.asked, r.URL.String())
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(c.body)),
		Header:     make(http.Header),
		Request:    r,
	}, nil
}

// assertUnderReleaseDownloads checks that raw is a URL on the release host,
// under this repo's releases/download path, with no traversal or smuggled
// query/fragment.
func assertUnderReleaseDownloads(t *testing.T, what, raw string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("%s %q does not parse as a URL: %v", what, raw, err)
	}
	base, err := url.Parse(fuzzBase)
	if err != nil {
		t.Fatalf("base: %v", err)
	}
	if u.Scheme != base.Scheme || u.Host != base.Host {
		t.Fatalf("%s %q left the release host (%s://%s)", what, raw, base.Scheme, base.Host)
	}
	prefix := "/" + fuzzRepo + "/releases/download/"
	if !strings.HasPrefix(u.Path, prefix) {
		t.Fatalf("%s %q is outside %q", what, u.Path, prefix)
	}
	rest := strings.TrimPrefix(u.Path, prefix)
	// Exactly two segments: the tag and the asset. Anything else means one of
	// the two inputs added structure.
	segs := strings.Split(rest, "/")
	if len(segs) != 2 || segs[0] == "" || segs[1] == "" {
		t.Fatalf("%s %q has %d path segments after the prefix; want tag/asset", what, u.Path, len(segs))
	}
	for _, s := range segs {
		if s == "." || s == ".." || strings.Contains(s, "..") {
			t.Fatalf("%s %q contains a dot segment", what, u.Path)
		}
	}
	if u.RawQuery != "" || u.Fragment != "" {
		t.Fatalf("%s %q carries a query or fragment", what, raw)
	}
	if u.Opaque != "" || u.User != nil {
		t.Fatalf("%s %q carries opaque data or userinfo", what, raw)
	}
}

// FuzzPublicNodeImage fuzzes the two untrusted inputs together: the requested
// version and the manifest bytes that come back. Whenever it succeeds, both the
// URL it fetched and the URL it hands out must stay under the release's download
// path.
func FuzzPublicNodeImage(f *testing.F) {
	good := `{"version":"2026.09.2-dev.215","artifacts":[{"compatible":"rasputin-rpi-arm64",` +
		`"architecture":"arm64","image":"rasputin-os-rpi-2026.09.2-dev.215.img.xz",` +
		`"imageSha256":"8406f3240000000000000000000000000000000000000000000000000000beef"}]}`
	for _, v := range []string{
		"2026.09.2-dev.215", "2026.09.1", "v0.8.7-dev.2", "",
		"../../../evil/repo/releases/download/x", "x/../../y", "x?y", "x#y",
		"a b", strings.Repeat("v", 129), "..", ".", "%2e%2e",
	} {
		f.Add(v, []byte(good))
	}
	f.Add("2026.09.1", []byte(`{"artifacts":[{"compatible":"rasputin-rpi-arm64","image":"../../x.img","imageSha256":"ab"}]}`))
	f.Add("2026.09.1", []byte(`{"artifacts":[{"compatible":"rasputin-rpi-arm64","image":"a/b.img","imageSha256":"ab"}]}`))
	f.Add("2026.09.1", []byte(`{"artifacts":[]}`))
	f.Add("2026.09.1", []byte(`not json`))

	f.Fuzz(func(t *testing.T, version string, manifest []byte) {
		tr := &captureTransport{body: manifest}
		hc := &http.Client{Transport: tr}
		d, err := PublicNodeImage(context.Background(), hc, nil, fuzzBase, testComponent(fuzzRepo), version, fuzzSKU)

		// Whatever the outcome, any request that went out must have been on the
		// release path: a rejected version must not be fetched at all.
		for _, asked := range tr.asked {
			assertUnderReleaseDownloads(t, "requested URL", asked)
		}
		if err != nil {
			if d != nil {
				t.Fatalf("PublicNodeImage returned a descriptor alongside error %v", err)
			}
			return
		}
		if !ValidReleaseVersion(version) {
			t.Fatalf("resolved an image for invalid version %q", version)
		}
		assertUnderReleaseDownloads(t, "descriptor URL", d.URL)
		if d.Version != version {
			t.Fatalf("descriptor version %q != requested %q", d.Version, version)
		}
		if !validPathSegment(d.Image) {
			t.Fatalf("descriptor image name %q is not a single safe path segment", d.Image)
		}
		if d.SHA256 == "" {
			t.Fatal("descriptor has no sha256; flash.sh would have nothing to verify against")
		}
		if !strings.HasSuffix(d.URL, url.PathEscape(d.Image)) {
			t.Fatalf("descriptor URL %q does not end with its own escaped image name %q", d.URL, d.Image)
		}
	})
}

// FuzzValidReleaseVersion pins the gate itself: an accepted version is one URL
// path segment that survives escaping unchanged, so callers that splice it in
// cannot be surprised.
func FuzzValidReleaseVersion(f *testing.F) {
	for _, v := range []string{
		"2026.09.1", "2026.09.2-dev.215", "v0.8.7-dev.2", "a", "0",
		"", "..", ".", "-x", ".x", "a/b", "a\\b", "a?b", "a#b", "a%2fb", "a b",
		strings.Repeat("a", 128), strings.Repeat("a", 129), "a\x00b", "café",
	} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, version string) {
		if !ValidReleaseVersion(version) {
			return
		}
		if version == "" || len(version) > maxPathSegment {
			t.Fatalf("accepted version %q has length %d", version, len(version))
		}
		if url.PathEscape(version) != version {
			t.Fatalf("accepted version %q is not escaping-stable (escapes to %q)", version, url.PathEscape(version))
		}
		if strings.ContainsAny(version, "/\\?#%: \t\r\n") || strings.Contains(version, "..") {
			t.Fatalf("accepted version %q can change a URL's structure", version)
		}
		if u, err := url.Parse(fuzzBase + "/" + fuzzRepo + "/releases/download/" + version + "/manifest.json"); err != nil {
			t.Fatalf("accepted version %q makes an unparseable URL: %v", version, err)
		} else {
			assertUnderReleaseDownloads(t, "version-only URL", u.String())
		}
	})
}

// FuzzArchCompatible pins the unauthenticated arch parameter: an accepted arch
// only ever maps to one of the two SKUs the pipelines actually publish.
func FuzzArchCompatible(f *testing.F) {
	for _, a := range []string{"amd64", "arm64", "", "mips", "AMD64", "amd64 ", "arm64\x00", "../amd64"} {
		f.Add(a)
	}
	f.Fuzz(func(t *testing.T, arch string) {
		sku, ok := ArchCompatible(arch)
		if !ok {
			if sku != "" {
				t.Fatalf("ArchCompatible(%q) refused but returned SKU %q", arch, sku)
			}
			return
		}
		if arch != "amd64" && arch != "arm64" {
			t.Fatalf("ArchCompatible accepted %q; only amd64 and arm64 are built", arch)
		}
		if !validPathSegment(sku) {
			t.Fatalf("ArchCompatible(%q) returned SKU %q, which is not a single safe path segment", arch, sku)
		}
	})
}
