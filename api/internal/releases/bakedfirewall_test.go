package releases

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fwComp() Component {
	return Component{
		ID: "fw", Repo: "geekdojo/rasputin-openwrt-firewall",
		Compatible: FirewallCompatible, Scheme: SchemeCalVer,
		SignedManifestFrom: "2026.09.4-dev.127",
	}
}

// Shaped on the real 2026.09.4-dev.127 manifest. Note `sha256` carries the
// flashable image's checksum here -- on the OS that field covers the RAUC
// bundle and the image sha lives in `imageSha256`. Reading the wrong one would
// hand the laptop a checksum that never matches.
func bakedManifestJSON(version string) string {
	return `{"version":"` + version + `","channel":"dev","artifacts":[{` +
		`"sku":"fw-n100","architecture":"amd64","compatible":"` + FirewallCompatible + `",` +
		`"kind":"ab","image":"rasputin-fw-n100-` + version + `-ab.img.gz",` +
		`"sha256":"455e19da50a95802d2684bae259edce8668a07c6a80aa4a7e3efb87a1d45dafd",` +
		`"sizeBytes":60127009,"signedBy":"Rasputin Release ` + version + `"}]}`
}

func writeBaked(t *testing.T, manifest string, withSig bool) string {
	t.Helper()
	dir := t.TempDir()
	if manifest != "" {
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if withSig {
		if err := os.WriteFile(filepath.Join(dir, "manifest.json.sig"), []byte("DER-ish"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("RASPUTIN_BAKED_FIREWALL_DIR", dir)
	return dir
}

// The whole point: a control plane with no route still names a firewall image,
// and the descriptor it serves carries the signed manifest so flash.sh can
// repeat the check on the laptop. Nothing here touches the network.
func TestBakedFirewallImageServesAVerifiedDescriptorOffline(t *testing.T) {
	const version = "2026.09.4-dev.127"
	writeBaked(t, bakedManifestJSON(version), true)

	d, err := BakedFirewallImage(&fakeVerifier{}, "https://github.com", fwComp())
	if err != nil {
		t.Fatalf("BakedFirewallImage: %v", err)
	}
	if d.Version != version {
		t.Errorf("Version = %q, want %q", d.Version, version)
	}
	wantURL := "https://github.com/geekdojo/rasputin-openwrt-firewall/releases/download/" +
		version + "/rasputin-fw-n100-" + version + "-ab.img.gz"
	if d.URL != wantURL {
		t.Errorf("URL = %q, want %q", d.URL, wantURL)
	}
	// From `sha256`, not `imageSha256`.
	if d.SHA256 != "455e19da50a95802d2684bae259edce8668a07c6a80aa4a7e3efb87a1d45dafd" {
		t.Errorf("SHA256 = %q", d.SHA256)
	}
	if d.ManifestB64 == "" || d.ManifestSigB64 == "" {
		t.Fatal("descriptor carries no manifest+signature; flash.sh would fall back to a bare sha256")
	}
	raw, err := base64.StdEncoding.DecodeString(d.ManifestB64)
	if err != nil || string(raw) != bakedManifestJSON(version) {
		t.Errorf("ManifestB64 does not round-trip to the baked bytes (err=%v)", err)
	}
	if d.Signer == "" {
		t.Error("Signer is empty on a verified descriptor")
	}
}

// A baked manifest is trusted for being SIGNED, not for being local. If the
// signature does not verify, the offline path must refuse rather than serve an
// unverified descriptor -- otherwise baking would be a way to launder one.
func TestBakedFirewallImageRefusesABadSignature(t *testing.T) {
	writeBaked(t, bakedManifestJSON("2026.09.4-dev.127"), true)

	_, err := BakedFirewallImage(&fakeVerifier{err: errors.New("signature does not verify")}, "https://github.com", fwComp())
	if err == nil {
		t.Fatal("a manifest whose signature fails verification was accepted")
	}
	if errors.Is(err, ErrNoBakedManifest) {
		t.Error("a BAD manifest must not report as an ABSENT one; the caller treats absent as benign")
	}
}

// An image with no baked manifest -- a dev build, or one older than #595 --
// must be distinguishable from a broken one, because the caller falls back to
// its online path on absent and logs loudly on broken.
func TestBakedFirewallImageAbsentIsNotAnError(t *testing.T) {
	writeBaked(t, "", false)

	_, err := BakedFirewallImage(&fakeVerifier{}, "https://github.com", fwComp())
	if !errors.Is(err, ErrNoBakedManifest) {
		t.Fatalf("absent manifest gave %v, want ErrNoBakedManifest", err)
	}
}

// The image build installs both files or fails. So a manifest sitting there
// with no signature beside it is not the benign "older image" case -- it is a
// truncated or tampered pair, and must not read as absent.
func TestBakedFirewallImageManifestWithoutSignatureIsNotAbsent(t *testing.T) {
	writeBaked(t, bakedManifestJSON("2026.09.4-dev.127"), false)

	_, err := BakedFirewallImage(&fakeVerifier{}, "https://github.com", fwComp())
	if err == nil {
		t.Fatal("a manifest with no signature beside it was accepted")
	}
	if errors.Is(err, ErrNoBakedManifest) {
		t.Error("a half-present pair must not read as an absent one")
	}
}

func TestBakedFirewallImageRejectsJunk(t *testing.T) {
	for _, tc := range []struct{ name, manifest, want string }{
		{"not json", `{"version":`, "parse"},
		{"bogus version", `{"version":"; rm -rf /","artifacts":[]}`, "version"},
		{"no matching artifact", `{"version":"2026.09.4-dev.127","artifacts":[]}`, "no flashable"},
		{
			"asset name escaping its path segment",
			`{"version":"2026.09.4-dev.127","artifacts":[{"compatible":"` + FirewallCompatible +
				`","image":"../../etc/passwd","sha256":"deadbeef"}]}`,
			"asset",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeBaked(t, tc.manifest, true)
			_, err := BakedFirewallImage(&fakeVerifier{}, "https://github.com", fwComp())
			if err == nil {
				t.Fatalf("accepted %s", tc.name)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
