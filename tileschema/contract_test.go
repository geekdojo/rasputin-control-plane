package tileschema

import (
	"maps"
	"testing"
)

// TC-897-01: one contract version, 1.5.0, and the two old integers are aliases
// of its major rather than versions of their own.
func TestContractVersion(t *testing.T) {
	if ContractMajor != 1 || ContractMinor != 5 || ContractPatch != 0 {
		t.Fatalf("contract is %d.%d.%d, want 1.5.0", ContractMajor, ContractMinor, ContractPatch)
	}
	if SchemaVersion != ContractMajor {
		t.Errorf("SchemaVersion = %d, want ContractMajor (%d)", SchemaVersion, ContractMajor)
	}
	if BundleSchemaVersion != ContractMajor {
		t.Errorf("BundleSchemaVersion = %d, want ContractMajor (%d)", BundleSchemaVersion, ContractMajor)
	}
}

// TC-897-02: the capability history is exactly the four capabilities against
// the minors tileschema/v1.4.0 was derived from, and the legacy set is built
// from it.
func TestCapabilityHistory(t *testing.T) {
	want := map[string]int{
		"privilege-tiers-v1":    1,
		"tile.web-port":         2,
		"tile.secrets":          3,
		"tile.operator-secrets": 4,
	}
	if !maps.Equal(capabilityIntroducedIn, want) {
		t.Fatalf("capability history = %v, want %v", capabilityIntroducedIn, want)
	}
	for name, minor := range capabilityIntroducedIn {
		if minor < 1 || minor > ContractMinor {
			t.Errorf("%s is recorded at minor %d, outside [1, %d]", name, minor, ContractMinor)
		}
	}
	wantKnown := map[string]bool{
		"privilege-tiers-v1":    true,
		"tile.web-port":         true,
		"tile.secrets":          true,
		"tile.operator-secrets": true,
	}
	if !maps.Equal(KnownCapabilities, wantKnown) {
		t.Errorf("KnownCapabilities = %v, want %v", KnownCapabilities, wantKnown)
	}
}

func TestCapabilityMinor(t *testing.T) {
	for name, want := range map[string]int{
		CapabilityPrivilegeTiers:  1,
		CapabilityWebPort:         2,
		CapabilityTileSecrets:     3,
		CapabilityOperatorSecrets: 4,
	} {
		if got, ok := CapabilityMinor(name); !ok || got != want {
			t.Errorf("CapabilityMinor(%q) = %d, %v; want %d, true", name, got, ok, want)
		}
	}
	if got, ok := CapabilityMinor("tile.future"); ok || got != 0 {
		t.Errorf("CapabilityMinor of an unknown capability = %d, %v; want 0, false", got, ok)
	}
}
