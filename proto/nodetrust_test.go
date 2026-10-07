package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

// TC-741-11 (wire half): the renamed fields keep their wire names. The
// registration key is still "meshCaFingerprint" and the enroll field is still
// "meshCaPem", so a mixed fleet reads both ways.
func TestTrustWireNamesAreUnchanged(t *testing.T) {
	if MetadataTrustFingerprint != "meshCaFingerprint" {
		t.Errorf("MetadataTrustFingerprint = %q", MetadataTrustFingerprint)
	}
	b, err := json.Marshal(MeshEnrollCmd{LegacyTrustBundlePEM: []byte("pem")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"meshCaPem":"cGVt"`) {
		t.Errorf("MeshEnrollCmd JSON %s does not carry meshCaPem", b)
	}
	var back MeshEnrollCmd
	if err := json.Unmarshal([]byte(`{"meshCaPem":"cGVt"}`), &back); err != nil || string(back.LegacyTrustBundlePEM) != "pem" {
		t.Errorf("round trip: %q %v", back.LegacyTrustBundlePEM, err)
	}
	if TrustInstallSubject("n1") != "rasputin.node.n1.cmd.trust.install" {
		t.Errorf("subject %q", TrustInstallSubject("n1"))
	}
	if _, ok := VerbMinAgentVersion(TrustInstallVerb); !ok {
		t.Error("trust.install has no floor")
	}
	if TrustFingerprint([]byte(TrustFingerprintReloadPending)) == TrustFingerprintReloadPending {
		t.Error("reload-pending collides with a fingerprint")
	}
}

// The shared TLS helper's errors now say tls:, not mesh:.
func TestCATLSConfigErrorPrefix(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("junk")} {
		if _, err := CATLSConfig(in, "src"); err == nil || !strings.HasPrefix(err.Error(), "tls: src:") {
			t.Errorf("err %v, want a tls: src: prefix", err)
		}
	}
}
