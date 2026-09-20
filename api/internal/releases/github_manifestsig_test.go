package releases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// LatestFor is the other path that fetches a release manifest — the update
// check and the firewall image resolve through it — and the signature work in
// it was reachable only through the full api stack until now.
//
// Its refusals matter as much as PublicNodeImage's: this is the manifest an
// update DECISION is made from, so an unverified one here means a cluster is
// offered an update whose checksums nobody vouched for.

// ghStub serves a minimal GitHub Releases API plus the release's assets, so
// LatestFor can be driven end to end without a network.
type ghStub struct {
	srv      *httptest.Server
	manifest []byte
	sig      []byte
	// omitSigAsset drops manifest.json.sig from the asset LIST (a release that
	// never published one), as opposed to serving it as a 404.
	omitSigAsset bool
	sigStatus    int
}

func newGHStub(t *testing.T, tag string, manifest, sig []byte) *ghStub {
	t.Helper()
	g := &ghStub{manifest: manifest, sig: sig, sigStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/geekdojo/rasputin-os/releases", func(w http.ResponseWriter, r *http.Request) {
		assets := []map[string]string{
			{"name": "manifest.json", "browser_download_url": g.srv.URL + "/manifest.json"},
		}
		if !g.omitSigAsset {
			assets = append(assets, map[string]string{
				"name": "manifest.json.sig", "browser_download_url": g.srv.URL + "/manifest.json.sig",
			})
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"tag_name": tag, "prerelease": false, "assets": assets},
		})
	})
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(g.manifest) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) {
		if g.sigStatus != http.StatusOK {
			w.WriteHeader(g.sigStatus)
			return
		}
		_, _ = w.Write(g.sig)
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func TestLatestFor_VerifiesTheManifestAtTheFloor(t *testing.T) {
	const tag = "2026.09.3"
	g := newGHStub(t, tag, manifestFor(tag), []byte("DER"))
	v := &fakeVerifier{signer: "Rasputin Bundle Signing leaf-003"}

	src := NewGithubPublicSource(g.srv.URL, v)
	info, err := src.LatestFor(context.Background(), osComp(), ChannelStable)
	if err != nil {
		t.Fatalf("LatestFor: %v", err)
	}
	if v.calls != 1 {
		t.Errorf("verifier calls = %d, want 1", v.calls)
	}
	if info.Signer != "Rasputin Bundle Signing leaf-003" {
		t.Errorf("signer = %q — an unattributed pass is barely better than no gate", info.Signer)
	}
	if info.Version != tag {
		t.Errorf("version = %q, want %q", info.Version, tag)
	}
}

func TestLatestFor_UnsignedAtTheFloorIsRefused(t *testing.T) {
	const tag = "2026.09.3"
	// The release never published a .sig at all: the asset is not in the list.
	// This is also what deleting the asset from a signed release looks like,
	// which is the downgrade the floor exists to refuse.
	g := newGHStub(t, tag, manifestFor(tag), nil)
	g.omitSigAsset = true

	src := NewGithubPublicSource(g.srv.URL, &fakeVerifier{})
	if _, err := src.LatestFor(context.Background(), osComp(), ChannelStable); !errors.Is(err, ErrManifestUnsigned) {
		t.Fatalf("want ErrManifestUnsigned, got %v", err)
	}
}

func TestLatestFor_UnfetchableSignatureIsTheSameAsAbsent(t *testing.T) {
	const tag = "2026.09.3"
	// The asset is listed but the host 500s. Above the floor these must be the
	// same refusal: if a failed fetch read as "no signature required", an
	// attacker who can break one request has turned verification off.
	g := newGHStub(t, tag, manifestFor(tag), nil)
	g.sigStatus = http.StatusInternalServerError

	src := NewGithubPublicSource(g.srv.URL, &fakeVerifier{})
	if _, err := src.LatestFor(context.Background(), osComp(), ChannelStable); !errors.Is(err, ErrManifestUnsigned) {
		t.Fatalf("want ErrManifestUnsigned, got %v", err)
	}
}

func TestLatestFor_TagMustMatchTheManifestVersion(t *testing.T) {
	const tag = "2026.09.3"
	// Signed for one release, served under another's tag.
	g := newGHStub(t, tag, manifestFor("2026.09.0"), []byte("DER"))

	src := NewGithubPublicSource(g.srv.URL, &fakeVerifier{})
	if _, err := src.LatestFor(context.Background(), osComp(), ChannelStable); !errors.Is(err, ErrManifestVersionMismatch) {
		t.Fatalf("want ErrManifestVersionMismatch, got %v", err)
	}
}

func TestLatestFor_BelowTheFloorResolvesUnverified(t *testing.T) {
	const tag = "2026.07.4"
	g := newGHStub(t, tag, manifestFor(tag), []byte("a leaf-001 signature"))
	v := &fakeVerifier{}

	src := NewGithubPublicSource(g.srv.URL, v)
	info, err := src.LatestFor(context.Background(), osComp(), ChannelStable)
	if err != nil {
		t.Fatalf("a release below the floor must still resolve: %v", err)
	}
	if v.calls != 0 {
		t.Errorf("the verifier ran on a release below the floor (%d calls)", v.calls)
	}
	if info.Signer != "" {
		t.Errorf("signer = %q, want empty — nothing was verified", info.Signer)
	}
}

// Even below the floor, the tag and the manifest must agree. An unsigned
// document must not be able to rename an unsigned release — that was the
// "prefer the manifest's version as authoritative" behaviour this replaced.
func TestLatestFor_BelowTheFloorStillBindsTheTag(t *testing.T) {
	const tag = "2026.07.4"
	g := newGHStub(t, tag, manifestFor("2026.07.9"), nil)
	g.omitSigAsset = true

	src := NewGithubPublicSource(g.srv.URL, &fakeVerifier{})
	if _, err := src.LatestFor(context.Background(), osComp(), ChannelStable); !errors.Is(err, ErrManifestVersionMismatch) {
		t.Fatalf("want ErrManifestVersionMismatch, got %v", err)
	}
}

func TestLatestFor_NoTrustRootRefusesRatherThanResolving(t *testing.T) {
	const tag = "2026.09.3"
	g := newGHStub(t, tag, manifestFor(tag), []byte("DER"))

	// nil verifier: a control plane with no trust root.
	src := NewGithubPublicSource(g.srv.URL, nil)
	if _, err := src.LatestFor(context.Background(), osComp(), ChannelStable); !errors.Is(err, ErrNoVerifier) {
		t.Fatalf("want ErrNoVerifier, got %v", err)
	}
}

// The operator-facing wording for each signature failure. These reach a UI
// banner, and the transport advice they used to fall through to ("check this
// node's internet connection") sends someone to look at the wrong thing.
func TestFriendlyFetchError_SignatureFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"expired signer", fmt.Errorf("x: %w", ErrManifestSignerExpired), "signing certificate has expired"},
		{"unsigned", fmt.Errorf("x: %w", ErrManifestUnsigned), "no signature on its manifest"},
		{"version mismatch", fmt.Errorf("x: %w", ErrManifestVersionMismatch), "does not match the release it was published under"},
		{"no trust root", fmt.Errorf("x: %w", ErrNoVerifier), "no publisher trust root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := friendlyFetchError(c.err)
			if got == "" {
				t.Fatal("no message")
			}
			if !strings.Contains(got, c.want) {
				t.Errorf("message %q does not mention %q", got, c.want)
			}
			if strings.Contains(got, "internet connection") {
				t.Errorf("a signature failure must not be reported as a network fault: %q", got)
			}
		})
	}
}
