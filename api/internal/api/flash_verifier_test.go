package api

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The shared laptop-side release verifier lives in two repositories, byte for
// byte:
//
//	rasputin-site            static/bootstrap.sh        (canonical)
//	rasputin-control-plane   api/internal/api/flash.sh  (this copy)
//
// One checks the release a FIRST control plane is flashed from; the other
// checks the release a node joining an existing cluster is flashed from. They
// are different programs, and only the security decision is shared.
//
// Nothing in CI can reach the other repository — this gate is offline on
// purpose — so drift is caught by a pinned hash rather than by a comparison.
// Any edit to the block here changes the hash and fails this test, which is the
// moment to ask whether the sibling copy needs the same edit. That is a
// deliberate speed bump on exactly one thing: two verifiers that disagree about
// what a valid release looks like is worse than either of them alone.
//
// TO UPDATE, once both copies carry the same bytes:
//
//	sed -n '/# BEGIN shared release verifier/,/# END shared release verifier/p' \
//	  api/internal/api/flash.sh | shasum -a 256
//
// and put the result below with the date and the reason.
const (
	// Pinned 2026-09-19, the block's first version
	// (geekdojo/geekdojo-brain#527, #528).
	canonicalVerifierSHA256 = "24101461c016023ccba5e31557ecdcb1b8da80ec9c8cf1512a067075369dd1d3"

	verifierBeginMarker = "# BEGIN shared release verifier"
	verifierEndMarker   = "# END shared release verifier"
)

func flashScriptText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("flash.sh")
	if err != nil {
		t.Fatalf("read flash.sh: %v", err)
	}
	return string(b)
}

// verifierBlock returns the shared block exactly as it ships, including the
// banner lines the markers sit on — so a change to the surrounding comment is
// drift too. The comment is where the contract is written down.
func verifierBlock(t *testing.T) string {
	t.Helper()
	s := flashScriptText(t)
	i := strings.Index(s, verifierBeginMarker)
	if i < 0 {
		t.Fatal("flash.sh has no shared release verifier block")
	}
	// Back up to the banner line above the BEGIN marker.
	if nl := strings.LastIndex(s[:i], "\n# ====="); nl >= 0 {
		i = nl + 1
	}
	j := strings.Index(s, verifierEndMarker)
	if j < 0 {
		t.Fatal("flash.sh's verifier block has no END marker")
	}
	// Extend past the banner line below the END marker.
	rest := s[j:]
	if nl := strings.Index(rest, "\n"); nl >= 0 {
		if nl2 := strings.Index(rest[nl+1:], "\n"); nl2 >= 0 {
			j += nl + 1 + nl2 + 1
		}
	}
	return s[i:j]
}

func TestFlashScriptVerifierMatchesCanonical(t *testing.T) {
	block := verifierBlock(t)
	sum := sha256.Sum256([]byte(block))
	got := hex.EncodeToString(sum[:])
	if got != canonicalVerifierSHA256 {
		t.Errorf("the shared release verifier in flash.sh has changed.\n"+
			"  got  %s\n  want %s\n\n"+
			"This block is kept byte-identical with rasputin-site static/bootstrap.sh.\n"+
			"If this edit is intended, make the SAME edit there, then update\n"+
			"canonicalVerifierSHA256 in this file with the date and the reason.",
			got, canonicalVerifierSHA256)
	}
}

// The hash above catches ANY edit, which is what makes it a drift gate — and
// also what makes it useless at saying whether a re-pinned block is still
// correct. These check the properties that must survive a legitimate edit, so
// that re-pinning cannot quietly accept a verifier that has stopped verifying.
func TestFlashScriptVerifierProperties(t *testing.T) {
	block := verifierBlock(t)

	t.Run("pins the root CA by fingerprint", func(t *testing.T) {
		// The anchor must come from the script's own bytes. A fetched root
		// checked against nothing is just a fetched root.
		re := regexp.MustCompile(`(?m)^RASPUTIN_ROOT_CA_SHA256="[0-9a-f]{64}"$`)
		if !re.MatchString(block) {
			t.Error("no 64-hex RASPUTIN_ROOT_CA_SHA256 pin in the verifier block")
		}
	})

	t.Run("requires the release purpose OID", func(t *testing.T) {
		if !strings.Contains(block, `RASPUTIN_RELEASE_OID="1.3.6.1.4.1.66587.1.1.1"`) {
			t.Error("the verifier does not name the release purpose OID")
		}
	})

	t.Run("matches the OID as a whole token", func(t *testing.T) {
		// The raw OID is a prefix of any future …1.1.1x, so a substring test
		// would accept a purpose that has not been minted yet
		// (geekdojo/geekdojo-brain#474).
		if !strings.Contains(block, `(^|[ ,])$(printf '%s' "$RASPUTIN_RELEASE_OID" | sed 's/\./\\./g')([ ,]|\$)`) {
			t.Error("the OID match is not anchored as a whole token")
		}
	})

	t.Run("reads the EKU with -text, not -ext", func(t *testing.T) {
		// macOS ships LibreSSL, which has no `x509 -ext`. A verifier that
		// cannot run on the laptop it ships for is not a verifier.
		//
		// Checked against the CODE only: the block's own comment explains why
		// `-ext` is avoided, and matching prose would fail on the explanation
		// rather than on the thing explained.
		if strings.Contains(verifierCode(block), "x509 -ext") {
			t.Error("the verifier uses `x509 -ext`, which LibreSSL does not have")
		}
		if !strings.Contains(block, "-noout -text") {
			t.Error("the verifier does not read the EKU from `x509 -text`")
		}
	})

	t.Run("does not let the default S/MIME purpose stand in for the OID check", func(t *testing.T) {
		// `-purpose any` is deliberate: the default purpose passes today only
		// because the release leaf happens to carry emailProtection, which is
		// incidental. The OID check is the authorization.
		if !strings.Contains(block, "cms -verify -purpose any") {
			t.Error("the CMS verify does not pass -purpose any")
		}
	})

	t.Run("refuses an unsigned release rather than continuing", func(t *testing.T) {
		if !strings.Contains(block, "this release has no signature for its manifest") {
			t.Error("the verifier has no refusal for a missing signature")
		}
	})

	t.Run("reports an expired signer as a stale release", func(t *testing.T) {
		// dec 24 (geekdojo/geekdojo-brain#576): the expiry cliff must read as
		// "too old to install", carrying the caller's remedy, not as tampering.
		if !strings.Contains(block, "signing certificate expired on") {
			t.Error("the verifier does not distinguish an expired signer")
		}
		if !strings.Contains(block, "$stale_advice") {
			t.Error("the verifier does not print the caller's remedy for a stale release")
		}
	})
}

// flash.sh must actually USE the block it carries, and must take the checksum
// from the manifest it verified. Vendoring a verifier and then not calling it
// is a failure mode a hash pin cannot see.
func TestFlashScriptUsesTheVerifier(t *testing.T) {
	s := flashScriptText(t)

	if !strings.Contains(s, "rasputin_trusted_root ") {
		t.Error("flash.sh never pins the root CA")
	}
	if !strings.Contains(s, "rasputin_verify_manifest ") {
		t.Error("flash.sh never verifies the release manifest")
	}
	if !strings.Contains(s, `"Update the cluster before adding a node`) {
		t.Error("flash.sh does not pass the dec-24 remedy for an expired signer")
	}
	// The whole point: the sha used for the flash comes from the verified
	// manifest, and a descriptor that disagrees with it is refused.
	if !strings.Contains(s, "IMG_SHA=\"$MSHA\"") {
		t.Error("flash.sh does not take the checksum from the verified manifest")
	}
	if !strings.Contains(s, "does not match the signed release manifest") {
		t.Error("flash.sh does not refuse a descriptor that disagrees with the signed manifest")
	}
}

// verifierCode strips whole-line comments, so an assertion about what the
// verifier DOES is not satisfied (or defeated) by what its comments SAY.
func verifierCode(block string) string {
	var b strings.Builder
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
