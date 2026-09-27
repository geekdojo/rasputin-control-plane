package api

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Auth gate 8, validator parity (geekdojo/geekdojo-brain#495): "the laptop
// shell verifier refuses a catalog-signed manifest".
//
// The laptop verifier is the shared block in flash.sh, byte-identical with
// rasputin-site static/bootstrap.sh and pinned by
// TestFlashScriptVerifierMatchesCanonical — so running it here, through the
// served script, covers both copies. The Go side's equivalent is
// artifactsig.TestVerifyForPurpose_CrossPurposeMatrix; this is the same matrix
// for the shell, restricted to the one purpose the shell authorizes (release).
//
// Every signature below is over the SAME manifest bytes, by a leaf under the
// SAME root and intermediate, and every one verifies cryptographically (the
// precondition checks that, so a refusal cannot be a broken fixture). The only
// thing that differs is the signer's extended key usage, so the only thing that
// can refuse them is the verifier's release-purpose check. The fixtures are
// minted by testdata/fwmanifest/gen-fixtures.sh with the EKU lines
// scripts/pki-init.sh uses.

const releasePurposeOID = "1.3.6.1.4.1.66587.1.1.1"

// requireChainsToFixtureRoot proves a fixture signature verifies against the
// fixture root with no purpose restriction — i.e. that anything which refuses
// it is refusing the SIGNER'S PURPOSE, not the signature.
func requireChainsToFixtureRoot(t *testing.T, fx fwManifestFixture, sigName string) []byte {
	t.Helper()
	ssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatalf("openssl is required: %v", err)
	}
	dir := filepath.Join("testdata", "fwmanifest")
	sigPath := filepath.Join(dir, sigName)
	cmd := exec.Command(ssl, "cms", "-verify", "-purpose", "any", "-binary", "-inform", "DER",
		"-in", sigPath, "-content", filepath.Join(dir, "manifest.json"),
		"-CAfile", fx.rootPath, "-out", os.DevNull)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("precondition: %s does not verify against the fixture root, so a refusal would prove nothing about the purpose check: %v\n%s",
			sigName, err, out)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestFlashScript_VerifierAuthorizesOnlyTheReleasePurpose(t *testing.T) {
	fx := loadFWManifestFixture(t)

	t.Run("a release-signed manifest passes", func(t *testing.T) {
		sig := requireChainsToFixtureRoot(t, fx, "manifest.json.sig")
		out, err := runFirewallFlashDryRun(t, staticDescriptor(t, fwDescriptor(fx.manifest, sig)), fx)
		if !strings.Contains(out, "Release signature verified") {
			t.Errorf("the verifier did not accept the release-signed manifest (err=%v).\n%s", err, out)
		}
		if !strings.Contains(out, fwPlanLine) {
			t.Errorf("flash.sh never reached the flash plan for a release-signed manifest.\n%s", out)
		}
	})

	refusals := []struct {
		name, sig, signerCN, why string
	}{
		{
			name:     "a catalog-signed manifest is refused",
			sig:      "manifest.json.catalog.sig",
			signerCN: "Rasputin Test App Catalog Signing Leaf",
			why:      "the app-catalog identity chains to the same root; a catalog-signed manifest must not pass as a platform release",
		},
		{
			name:     "a purposeless codeSigning-signed manifest is refused",
			sig:      "manifest.json.generic.sig",
			signerCN: "Rasputin Test Generic CodeSigning Leaf",
			why:      "generic codeSigning is not an authorization; the transitional allowance is deleted on the Go side too",
		},
		{
			name:     "a manifest signed by a sibling purpose the OID is a prefix of is refused",
			sig:      "manifest.json.nearmiss.sig",
			signerCN: "Rasputin Test Near-Miss Purpose Leaf",
			why:      "…1.1.10 starts with the release OID's string; only a whole-token match refuses it",
		},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			sig := requireChainsToFixtureRoot(t, fx, c.sig)
			out, err := runFirewallFlashDryRun(t, staticDescriptor(t, fwDescriptor(fx.manifest, sig)), fx)

			// Refused, with the purpose refusal, naming the OID it wanted
			// and the signer it turned away.
			assertRefused(t, out, err, "is signed by a certificate that is NOT authorized to sign")
			if !strings.Contains(out, "(it does not carry "+releasePurposeOID+")") {
				t.Errorf("the refusal does not name the release purpose OID.\n%s", out)
			}
			if !strings.Contains(out, c.signerCN) {
				t.Errorf("the refusal does not name the signer %q.\n%s", c.signerCN, out)
			}
			// …and for the right reason: not the signature check, which this
			// signature passes, and never the success line.
			if strings.Contains(out, "signature did NOT verify") {
				t.Errorf("refused at the signature check, not the purpose check — the fixture is broken or -purpose any was dropped.\n%s", out)
			}
			if strings.Contains(out, "Release signature verified") {
				t.Errorf("the verifier reported success for a signer without the release purpose (%s).\n%s", c.why, out)
			}
		})
	}
}
