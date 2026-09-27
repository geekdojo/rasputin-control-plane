package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
)

// geekdojo/geekdojo-brain#527, bench 2026-09-27: GET /api/cluster/firewall-image
// served `signer: … leaf-003` and NO manifestB64/manifestSigB64. The api had
// verified the firewall manifest (the fw signing floor is set, #526 shipped)
// and then dropped the bytes on the floor, so flash.sh fell back to the bare
// checksum and printed "This release has no signed manifest" about a release
// that has one. These tests pin both halves: the descriptor carries the signed
// manifest, and flash.sh verifies it for a FIREWALL seed and refuses a bad one.
//
// The fixture pair in testdata/fwmanifest is minted by its gen-fixtures.sh with
// the production chain shape and the pipeline's own signing command.

const (
	fwFixtureVersion = "2026.09.4-dev.130"
	fwFixtureImage   = "rasputin-fw-n100-2026.09.4-dev.130-ab.img.gz"
	fwFixtureSHA     = "455e19da50a95802d2684bae259edce8668a07c6a80aa4a7e3efb87a1d45dafd"
)

type fwManifestFixture struct {
	manifest []byte
	sig      []byte
	rootPath string
}

func loadFWManifestFixture(t *testing.T) fwManifestFixture {
	t.Helper()
	dir := filepath.Join("testdata", "fwmanifest")
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		return b
	}
	root, err := filepath.Abs(filepath.Join(dir, "root-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return fwManifestFixture{manifest: read("manifest.json"), sig: read("manifest.json.sig"), rootPath: root}
}

// trustFixtureRoot gives the fixture an ENFORCING verifier that trusts the
// firewall-manifest fixture's root, and returns it.
func trustFixtureRoot(t *testing.T, f *apiFixture, fx fwManifestFixture) *updater.Verifier {
	t.Helper()
	pemBytes, err := os.ReadFile(fx.rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, updater.RootCAName), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	v := updater.NewVerifier(f.dir)
	if !v.TrustConfigured() {
		t.Fatalf("fixture root CA did not load from %s", f.dir)
	}
	f.srv.updaterVerifier = v
	return v
}

// fwReleaseServer publishes one firewall release the way GitHub does: a
// release listing whose assets include manifest.json and manifest.json.sig.
func fwReleaseServer(t *testing.T, manifest, sig []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/geekdojo/rasputin-openwrt-firewall/releases", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"tag_name":   fwFixtureVersion,
			"prerelease": true,
			"assets": []map[string]any{
				{"name": "manifest.json", "browser_download_url": base + "/a/manifest.json"},
				{"name": "manifest.json.sig", "browser_download_url": base + "/a/manifest.json.sig"},
				{"name": fwFixtureImage, "browser_download_url": base + "/a/" + fwFixtureImage},
			},
		}})
	})
	mux.HandleFunc("/a/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifest) })
	mux.HandleFunc("/a/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(sig) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func getFirewallDescriptor(t *testing.T, f *apiFixture) releases.NodeImageDescriptor {
	t.Helper()
	rec := f.do(t, http.MethodGet, "/api/cluster/firewall-image", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var desc releases.NodeImageDescriptor
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return desc
}

func assertCarriesSignedManifest(t *testing.T, desc releases.NodeImageDescriptor, fx fwManifestFixture) {
	t.Helper()
	if desc.Version != fwFixtureVersion || desc.Image != fwFixtureImage || desc.SHA256 != fwFixtureSHA {
		t.Fatalf("descriptor = %+v", desc)
	}
	if desc.ManifestB64 == "" || desc.ManifestSigB64 == "" {
		t.Fatalf("the firewall descriptor carries no signed manifest (manifestB64 %d bytes, manifestSigB64 %d bytes); "+
			"flash.sh would fall back to the bare checksum and say the release is unsigned", len(desc.ManifestB64), len(desc.ManifestSigB64))
	}
	m, err := base64.StdEncoding.DecodeString(desc.ManifestB64)
	if err != nil || !bytes.Equal(m, fx.manifest) {
		t.Errorf("manifestB64 is not the verified manifest's exact bytes (err=%v)", err)
	}
	s, err := base64.StdEncoding.DecodeString(desc.ManifestSigB64)
	if err != nil || !bytes.Equal(s, fx.sig) {
		t.Errorf("manifestSigB64 is not the published signature's exact bytes (err=%v)", err)
	}
	if desc.Signer == "" {
		t.Error("signer is empty on a verified firewall descriptor")
	}
}

// The ONLINE path: the release source fetched and verified the manifest, and
// the descriptor hands the same bytes on.
func TestClusterFirewallImage_CarriesTheSignedManifest(t *testing.T) {
	fx := loadFWManifestFixture(t)
	f := newAPIFixture(t)
	v := trustFixtureRoot(t, f, fx)
	rel := fwReleaseServer(t, fx.manifest, fx.sig)
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL, v), releases.ChannelDev)

	assertCarriesSignedManifest(t, getFirewallDescriptor(t, f), fx)
}

// The BAKED path (geekdojo/geekdojo-brain#595): no route to the release
// source, so the api serves the manifest rasputin-os pinned into the image —
// and that descriptor must carry the manifest just the same, or the offline
// flash is the one that silently drops to checksum-only.
func TestClusterFirewallImage_BakedFallbackCarriesTheSignedManifest(t *testing.T) {
	fx := loadFWManifestFixture(t)
	f := newAPIFixture(t)
	trustFixtureRoot(t, f, fx)

	baked := t.TempDir()
	if err := os.WriteFile(filepath.Join(baked, "manifest.json"), fx.manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baked, "manifest.json.sig"), fx.sig, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RASPUTIN_BAKED_FIREWALL_DIR", baked)
	f.srv.SetReleaseSource(failingSource{err: errors.New("no route to api.github.com")}, releases.ChannelDev)

	assertCarriesSignedManifest(t, getFirewallDescriptor(t, f), fx)
}

// ---------------------------------------------------------------------------
// flash.sh, driven for real
// ---------------------------------------------------------------------------

// fixtureRootFingerprint is the SHA-256 of the fixture root's DER — the form
// flash.sh pins (`x509 -fingerprint -sha256`, colons stripped, lowercase).
func fixtureRootFingerprint(t *testing.T, rootPath string) string {
	t.Helper()
	raw, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		t.Fatal("fixture root is not PEM")
	}
	sum := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(sum[:])
}

// testableFlashScript returns the served flash.sh with exactly two edits, both
// of which the test needs and neither of which touches the verification path:
//
//   - the root-CA fingerprint pin names the fixture root instead of the
//     production one (whose private key no test holds);
//   - the `id -u` root gate is removed, so the test runs unprivileged. Nothing
//     can be written anyway: RASPUTIN_DRY_RUN=1, and the target disk does not
//     exist.
//
// Each edit must match exactly once, so a rename in flash.sh fails here rather
// than leaving a production pin in place and a test that "passes" by never
// reaching the verifier.
func testableFlashScript(t *testing.T, fingerprint string) string {
	t.Helper()
	s := flashScriptText(t)

	pin := regexp.MustCompile(`(?m)^RASPUTIN_ROOT_CA_SHA256="[0-9a-f]{64}"$`)
	if n := len(pin.FindAllString(s, -1)); n != 1 {
		t.Fatalf("flash.sh has %d root-CA pins, want exactly 1", n)
	}
	s = pin.ReplaceAllString(s, `RASPUTIN_ROOT_CA_SHA256="`+fingerprint+`"`)

	gate := regexp.MustCompile(`(?m)^\[ "\$\(id -u\)" = "0" \] \|\| die .*$`)
	if n := len(gate.FindAllString(s, -1)); n != 1 {
		t.Fatalf("flash.sh has %d root gates, want exactly 1", n)
	}
	s = gate.ReplaceAllString(s, ":")

	path := filepath.Join(t.TempDir(), "flash.sh")
	if err := os.WriteFile(path, []byte(s), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// runFirewallFlashDryRun runs flash.sh with a FIREWALL seed against cpURL and
// returns its combined output and whether it exited 0.
func runFirewallFlashDryRun(t *testing.T, cpURL string, fx fwManifestFixture) (string, error) {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required to run flash.sh: %v", tool, err)
		}
	}
	script := testableFlashScript(t, fixtureRootFingerprint(t, fx.rootPath))
	seed := "RASPUTIN_NODE_ID='fw-527'\nRASPUTIN_NODE_ROLE='firewall'\nRASPUTIN_NATS_URL='nats://cp.invalid:4222'\n"

	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(),
		"RASPUTIN_SEED_B64="+base64.StdEncoding.EncodeToString([]byte(seed)),
		"RASPUTIN_CP_URL="+cpURL,
		"RASPUTIN_ROOT_CA_FILE="+fx.rootPath,
		"RASPUTIN_DRY_RUN=1",
		// Belt and braces with the dry run: a disk that does not exist, so the
		// run can never reach a picker or a write.
		"RASPUTIN_DISK=/nonexistent/rasputin-flash-test-disk",
		"TMPDIR="+t.TempDir(),
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// The run reached the plan line only if every check before it passed.
const fwPlanLine = "→ Rasputin Firewall " + fwFixtureVersion

// A good firewall release, served by the REAL handler: flash.sh verifies the
// signature and says so.
func TestFlashScript_FirewallVerifiesTheSignedManifest(t *testing.T) {
	fx := loadFWManifestFixture(t)
	f := newAPIFixture(t)
	v := trustFixtureRoot(t, f, fx)
	rel := fwReleaseServer(t, fx.manifest, fx.sig)
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL, v), releases.ChannelDev)
	cp := httptest.NewServer(f.handler)
	defer cp.Close()

	out, _ := runFirewallFlashDryRun(t, cp.URL, fx)
	if !strings.Contains(out, "Release signature verified") {
		t.Errorf("flash.sh did not verify the firewall manifest's signature.\n%s", out)
	}
	if strings.Contains(out, "no signed manifest") {
		t.Errorf("flash.sh claims a signed firewall release has no signed manifest.\n%s", out)
	}
	if !strings.Contains(out, fwPlanLine) {
		t.Errorf("flash.sh never reached the flash plan for a good release.\n%s", out)
	}
}

// staticDescriptor serves one hand-built firewall descriptor, for the cases the
// real handler (correctly) never produces.
func staticDescriptor(t *testing.T, d map[string]string) string {
	t.Helper()
	body, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cluster/firewall-image" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func fwDescriptor(manifest, sig []byte) map[string]string {
	d := map[string]string{
		"version":      fwFixtureVersion,
		"architecture": "amd64",
		"url":          "https://example.invalid/" + fwFixtureImage,
		"sha256":       fwFixtureSHA,
		"image":        fwFixtureImage,
	}
	if manifest != nil {
		d["manifestB64"] = base64.StdEncoding.EncodeToString(manifest)
	}
	if sig != nil {
		d["manifestSigB64"] = base64.StdEncoding.EncodeToString(sig)
	}
	return d
}

func assertRefused(t *testing.T, out string, err error, want string) {
	t.Helper()
	if err == nil {
		t.Errorf("flash.sh exited 0.\n%s", out)
	}
	if !strings.Contains(out, want) {
		t.Errorf("flash.sh did not refuse with %q.\n%s", want, out)
	}
	if strings.Contains(out, fwPlanLine) {
		t.Errorf("flash.sh went on to plan a flash after the refusal.\n%s", out)
	}
	if strings.Contains(out, "no signed manifest") {
		t.Errorf("flash.sh printed the checksum-only fallback for a firewall release.\n%s", out)
	}
}

// One checksum altered in the manifest, the original signature kept — the bench
// negative, for the firewall.
func TestFlashScript_FirewallRefusesATamperedManifest(t *testing.T) {
	fx := loadFWManifestFixture(t)
	tampered := bytes.Replace(fx.manifest, []byte(fwFixtureSHA), []byte(strings.Repeat("0", 64)), 1)
	if bytes.Equal(tampered, fx.manifest) {
		t.Fatal("the tamper did not change the manifest")
	}
	d := fwDescriptor(tampered, fx.sig)
	d["sha256"] = strings.Repeat("0", 64) // a descriptor consistent with the lie
	out, err := runFirewallFlashDryRun(t, staticDescriptor(t, d), fx)
	assertRefused(t, out, err, "signature did NOT verify")
}

// A signature that is not a signature.
func TestFlashScript_FirewallRefusesABadSignature(t *testing.T) {
	fx := loadFWManifestFixture(t)
	bad := append([]byte(nil), fx.sig...)
	bad[len(bad)/2] ^= 0xff
	out, err := runFirewallFlashDryRun(t, staticDescriptor(t, fwDescriptor(fx.manifest, bad)), fx)
	assertRefused(t, out, err, "signature did NOT verify")
}

// A firewall descriptor with no manifest at all. Every firewall release this
// control plane can serve is above the firewall's signing floor, so a missing
// manifest is a fault, not an old release — and flash.sh must say that and
// stop, rather than print "no signed manifest" and flash on a bare checksum.
func TestFlashScript_FirewallWithoutAManifestRefuses(t *testing.T) {
	fx := loadFWManifestFixture(t)
	out, err := runFirewallFlashDryRun(t, staticDescriptor(t, fwDescriptor(nil, nil)), fx)
	assertRefused(t, out, err, "did not hand over the signed release manifest")
}

// Half a pair is not a pair: a manifest without its signature must not be read
// as "unsigned".
func TestFlashScript_FirewallWithHalfAPairRefuses(t *testing.T) {
	fx := loadFWManifestFixture(t)
	out, err := runFirewallFlashDryRun(t, staticDescriptor(t, fwDescriptor(fx.manifest, nil)), fx)
	assertRefused(t, out, err, "only half of the signed release manifest")
}
