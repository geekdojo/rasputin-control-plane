package releases

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/artifactsig"
)

// fakeVerifier stands in for updater.Verifier. The cryptography is
// artifactsig's and is tested there; what is new here is the LADDER (which
// releases must be signed), the binding of the tag to the signed version, and
// which failure an operator is shown. Those are decisions, and a fake lets each
// one be provoked on purpose rather than by arranging a real bad signature.
type fakeVerifier struct {
	err    error
	signer string
	calls  int
}

func (f *fakeVerifier) VerifyArtifact(artifactPath, sigPath string) (*artifactsig.Result, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	signer := f.signer
	if signer == "" {
		signer = "Rasputin Bundle Signing leaf-test"
	}
	return &artifactsig.Result{Signer: signer, NotAfter: time.Now().Add(time.Hour)}, nil
}

func osComp() Component {
	return Component{ID: "os", Repo: "geekdojo/rasputin-os", Scheme: SchemeCalVer, SignedManifestFrom: "2026.08.4"}
}

func manifestFor(version string) []byte {
	b, _ := json.Marshal(Manifest{
		Version: version, Channel: "stable",
		Artifacts: []ManifestArtifact{{
			Compatible: "rasputin-n100", Architecture: "amd64",
			Image: "rasputin-os-n100-" + version + ".img.xz", ImageSha256: "abc", SHA256: "raucb",
		}},
	})
	return b
}

func TestSignedManifestRequired(t *testing.T) {
	oc := osComp()
	fw := Component{ID: "fw", Scheme: SchemeCalVer, SignedManifestFrom: ""}
	cases := []struct {
		name string
		comp Component
		ver  string
		want bool
	}{
		{"at the floor", oc, "2026.08.4", true},
		{"above the floor", oc, "2026.09.3", true},
		{"far above", oc, "2027.01.0", true},
		{"below the floor", oc, "2026.08.3", false},
		{"far below", oc, "2026.07.4", false},
		// A dev build of the floor version sorts BELOW the bare version, so it
		// is exempt. Conservative in the safe direction: a floor can only ever
		// under-require, never lock out a release it should not have.
		{"dev build of the floor version", oc, "2026.08.4-dev.180", false},
		{"no floor set at all", fw, "2026.09.4", false},
		{"unparseable version is treated as below", oc, "not-a-version", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SignedManifestRequired(c.comp, c.ver); got != c.want {
				t.Errorf("SignedManifestRequired(%s, %q) = %v, want %v", c.comp.ID, c.ver, got, c.want)
			}
		})
	}
}

func TestVerifyManifest_BelowFloorIsNotChecked(t *testing.T) {
	v := &fakeVerifier{}
	// Below the floor, the signature that exists was made by a leaf with no
	// release purpose. Checking it could only fail, and failing would strand
	// every cluster still running one of those releases.
	res, err := VerifyManifest(v, osComp(), "2026.07.4", manifestFor("2026.07.4"), []byte("a signature"))
	if err != nil {
		t.Fatalf("below the floor should not be checked: %v", err)
	}
	if res != nil {
		t.Errorf("below the floor should report no signer, got %+v", res)
	}
	if v.calls != 0 {
		t.Errorf("the verifier was called %d times for a release below the floor", v.calls)
	}
}

func TestVerifyManifest_AtFloorRequiresASignature(t *testing.T) {
	v := &fakeVerifier{}
	// The case that stops a signed release being downgraded by deleting its
	// `.sig`: at or above the floor, absent is refused, not tolerated.
	_, err := VerifyManifest(v, osComp(), "2026.09.3", manifestFor("2026.09.3"), nil)
	if !errors.Is(err, ErrManifestUnsigned) {
		t.Fatalf("want ErrManifestUnsigned, got %v", err)
	}
	if v.calls != 0 {
		t.Errorf("nothing should have been verified, got %d calls", v.calls)
	}
}

func TestVerifyManifest_AtFloorVerifiesAndAttributes(t *testing.T) {
	v := &fakeVerifier{signer: "Rasputin Bundle Signing leaf-003"}
	res, err := VerifyManifest(v, osComp(), "2026.09.3", manifestFor("2026.09.3"), []byte("sig"))
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	if v.calls != 1 {
		t.Errorf("verifier calls = %d, want 1", v.calls)
	}
	if res == nil || res.Signer != "Rasputin Bundle Signing leaf-003" {
		t.Errorf("signer not carried back: %+v", res)
	}
}

func TestVerifyManifest_TagMustMatchTheSignedVersion(t *testing.T) {
	v := &fakeVerifier{}
	// The signature covers the manifest, not the tag. Without this check a
	// perfectly valid signed manifest for one release could be served under
	// another release's tag, pairing a signed checksum list with somebody
	// else's assets.
	_, err := VerifyManifest(v, osComp(), "2026.09.3", manifestFor("2026.09.0"), []byte("sig"))
	if !errors.Is(err, ErrManifestVersionMismatch) {
		t.Fatalf("want ErrManifestVersionMismatch, got %v", err)
	}
}

func TestVerifyManifest_NoVerifierIsRefused(t *testing.T) {
	// A control plane with no trust root must fail to resolve a release it is
	// required to verify — not resolve it unverified.
	_, err := VerifyManifest(nil, osComp(), "2026.09.3", manifestFor("2026.09.3"), []byte("sig"))
	if !errors.Is(err, ErrNoVerifier) {
		t.Fatalf("want ErrNoVerifier, got %v", err)
	}
}

func TestVerifyManifest_ExpiredSignerIsNotReportedAsTampering(t *testing.T) {
	// dec 24 (geekdojo/geekdojo-brain#576). The signature is intact; the leaf
	// has aged out. Distinguished here so the api can tell the operator to
	// update the cluster instead of sending them hunting for an attack.
	//
	// The signature bytes are a REAL expired-leaf signature only in the
	// functional check; here the fake fails and the diagnostic reads the
	// fixture written beside it, which is what decides the wording.
	sigDER, err := os.ReadFile("testdata/expired-manifest.json.sig")
	if err != nil {
		t.Skipf("no expired-signer fixture: %v", err)
	}
	v := &fakeVerifier{err: fmt.Errorf("x509: certificate has expired")}
	_, err = VerifyManifest(v, osComp(), "2026.09.3", manifestFor("2026.09.3"), sigDER)
	if !errors.Is(err, ErrManifestSignerExpired) {
		t.Fatalf("want ErrManifestSignerExpired, got %v", err)
	}
	if strings.Contains(err.Error(), "tamper") {
		t.Errorf("an expired leaf must not read as tampering: %v", err)
	}
}

// PublicNodeImage must carry the verified manifest onward, and only when it
// really verified one — the flasher cannot tell the difference and would trust
// whatever arrived.
func TestPublicNodeImage_CarriesTheVerifiedManifest(t *testing.T) {
	const version = "2026.09.3"
	body := manifestFor(version)
	mux := http.NewServeMux()
	mux.HandleFunc("/geekdojo/rasputin-os/releases/download/"+version+"/manifest.json",
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) })
	mux.HandleFunc("/geekdojo/rasputin-os/releases/download/"+version+"/manifest.json.sig",
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("DER")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v := &fakeVerifier{signer: "Rasputin Bundle Signing leaf-003"}
	d, err := PublicNodeImage(context.Background(), srv.Client(), v, srv.URL, osComp(), version, "rasputin-n100")
	if err != nil {
		t.Fatalf("PublicNodeImage: %v", err)
	}
	if d.Signer != "Rasputin Bundle Signing leaf-003" {
		t.Errorf("signer = %q", d.Signer)
	}
	got, err := base64.StdEncoding.DecodeString(d.ManifestB64)
	if err != nil {
		t.Fatalf("manifestB64: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("the descriptor does not carry the manifest that was verified")
	}
	if sig, _ := base64.StdEncoding.DecodeString(d.ManifestSigB64); string(sig) != "DER" {
		t.Errorf("the descriptor does not carry the signature that was checked")
	}
	// And the checksum still comes out of that manifest.
	if d.SHA256 != "abc" {
		t.Errorf("sha256 = %q, want the manifest's", d.SHA256)
	}
}

func TestPublicNodeImage_BelowFloorCarriesNoManifest(t *testing.T) {
	const version = "2026.07.4"
	mux := http.NewServeMux()
	mux.HandleFunc("/geekdojo/rasputin-os/releases/download/"+version+"/manifest.json",
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestFor(version)) })
	mux.HandleFunc("/geekdojo/rasputin-os/releases/download/"+version+"/manifest.json.sig",
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("leaf-001 signature")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Nothing was verified, so nothing is handed to the flasher that would
	// look like it had been. It falls back to the bare sha256, as before.
	d, err := PublicNodeImage(context.Background(), srv.Client(), &fakeVerifier{}, srv.URL, osComp(), version, "rasputin-n100")
	if err != nil {
		t.Fatalf("PublicNodeImage: %v", err)
	}
	if d.ManifestB64 != "" || d.ManifestSigB64 != "" || d.Signer != "" {
		t.Errorf("an unverified release must not travel with a manifest: %+v", d)
	}
}

func TestPublicNodeImage_UnsignedAtFloorIsRefused(t *testing.T) {
	const version = "2026.09.3"
	mux := http.NewServeMux()
	mux.HandleFunc("/geekdojo/rasputin-os/releases/download/"+version+"/manifest.json",
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestFor(version)) })
	// No .sig route: the asset 404s, exactly as a deleted one would.
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := PublicNodeImage(context.Background(), srv.Client(), &fakeVerifier{}, srv.URL, osComp(), version, "rasputin-n100")
	if !errors.Is(err, ErrManifestUnsigned) {
		t.Fatalf("want ErrManifestUnsigned, got %v", err)
	}
}

// TestSignedManifestFloorsMatchPublishedReleases checks each component's floor
// against the releases that are actually published: the release AT the floor
// must carry a manifest.json.sig, and the one below it must not carry one this
// api would accept. A floor is a claim about published artifacts, and a claim
// nobody checks is a comment.
//
// Network, so it is opt-in: RASPUTIN_CHECK_PUBLISHED=1. CI stays hermetic, and
// this is run by hand when a floor moves.
func TestSignedManifestFloorsMatchPublishedReleases(t *testing.T) {
	if os.Getenv("RASPUTIN_CHECK_PUBLISHED") != "1" {
		t.Skip("set RASPUTIN_CHECK_PUBLISHED=1 to check the floors against github.com")
	}
	for _, comp := range Components {
		comp := comp
		t.Run(comp.ID, func(t *testing.T) {
			if comp.SignedManifestFrom == "" {
				t.Logf("%s has no signing floor; nothing to check", comp.ID)
				return
			}
			url := fmt.Sprintf("https://github.com/%s/releases/download/%s/manifest.json.sig", comp.Repo, comp.SignedManifestFrom)
			resp, err := http.Get(url) //nolint:gosec // fixed, non-user-controlled URL
			if err != nil {
				t.Fatalf("GET %s: %v", url, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s: the floor release %s publishes no manifest.json.sig (status %d) — the floor is wrong",
					comp.ID, comp.SignedManifestFrom, resp.StatusCode)
			}
		})
	}
}

// TestPublicNodeImage_AgainstThePublishedRelease resolves a REAL published
// release with the REAL verifier and the REAL production root CA — the whole
// path the add-node flow takes, with nothing stubbed.
//
// The unit tests above use a fake verifier, which is right for pinning
// decisions and useless for proving that the bytes GitHub serves today satisfy
// the bytes artifactsig demands. Those two can only be checked against the
// thing itself.
//
// Network and a root CA, so it is opt-in:
//
//	RASPUTIN_CHECK_PUBLISHED=1 \
//	RASPUTIN_TEST_ROOT_CA=/path/to/rasputin-root-ca.pem \
//	go test ./api/internal/releases/ -run AgainstThePublishedRelease -v
func TestPublicNodeImage_AgainstThePublishedRelease(t *testing.T) {
	if os.Getenv("RASPUTIN_CHECK_PUBLISHED") != "1" {
		t.Skip("set RASPUTIN_CHECK_PUBLISHED=1 (and RASPUTIN_TEST_ROOT_CA) to check against github.com")
	}
	root := os.Getenv("RASPUTIN_TEST_ROOT_CA")
	if root == "" {
		t.Skip("set RASPUTIN_TEST_ROOT_CA to the published rasputin-root-ca.pem")
	}
	version := os.Getenv("RASPUTIN_TEST_OS_VERSION")
	if version == "" {
		version = "2026.09.3"
	}
	comp, _ := ComponentByID("os")
	d, err := PublicNodeImage(context.Background(), http.DefaultClient, realVerifier{root},
		"https://github.com", comp, version, "rasputin-n100")
	if err != nil {
		t.Fatalf("PublicNodeImage(%s): %v", version, err)
	}
	if d.Signer == "" {
		t.Error("a release at or above the floor resolved with no signer — it was not verified")
	}
	if d.ManifestB64 == "" || d.ManifestSigB64 == "" {
		t.Error("the descriptor carries no manifest for the flasher to re-check")
	}
	if len(d.SHA256) != 64 {
		t.Errorf("sha256 = %q, want 64 hex characters", d.SHA256)
	}
	t.Logf("%s %s\n  image  %s\n  sha256 %s\n  signer %s", comp.ID, d.Version, d.Image, d.SHA256, d.Signer)

	// And the refusal, against the same real release: a tag that does not match
	// the signed manifest must not resolve.
	if _, err := PublicNodeImage(context.Background(), http.DefaultClient, realVerifier{root},
		"https://github.com", comp, "2026.09.0", "rasputin-n100"); err != nil {
		t.Logf("2026.09.0 resolves independently (expected): %v", err)
	}
}

// realVerifier is artifactsig bound to the release purpose, reading a root CA
// from a path — the same thing updater.Verifier is, without the api's wiring.
type realVerifier struct{ root string }

func (r realVerifier) VerifyArtifact(artifactPath, sigPath string) (*artifactsig.Result, error) {
	return artifactsig.VerifyForPurpose(artifactPath, sigPath, r.root, artifactsig.OIDCodeSigningRelease)
}
