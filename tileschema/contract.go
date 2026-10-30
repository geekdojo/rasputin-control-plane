package tileschema

// The contract version: one version for the tile and the bundle envelope,
// because they ship together in one signed document and are read by one
// validator (ADR-0012 Decision 1). It replaces the two separate integers,
// SchemaVersion and BundleSchemaVersion, which are kept below as deprecated
// aliases of the major.
//
// The version is also this module's own tag line, tileschema/vM.m.p, cut from
// control-plane main by .github/workflows/tileschema-tag.yml, independent of
// the CalVer release train (ADR-0012 Decision 2).
//
// What each part means (ADR-0012 Decision 3). The test is what an older reader
// of the same major does with the change:
//
//	Change                                                    Level
//	--------------------------------------------------------  -----------------------------
//	A new optional field an older reader may safely ignore    minor
//	A new field an older reader must NOT ignore, on a tile    minor + a `requires` capability
//	A validator fix that changes no field and no meaning      patch
//	A change per-tile refusal cannot contain: the envelope,   major (a new module path,
//	  the signature or asset format, a changed meaning for      tileschema/vN)
//	  an existing field, removing a field or capability, a
//	  rule every tile must obey
//
// Only the major gates a reader: a bundle from another major is refused whole.
// The minor never gates anything (ADR-0012 Decision 1); a capability a reader
// lacks is refused one tile at a time through Tile.Requires.
//
// To change the contract:
//
//  1. Bump the constant: ContractMinor for a new field or capability (and reset
//     ContractPatch to 0), ContractPatch for a validator fix alone.
//  2. Regenerate the surface golden:
//     go test ./tileschema -run TestContractSurface -update
//
// CI (scripts/tileschema-contract.sh check) refuses a changed surface that did
// not bump the minor over the latest tileschema tag.
const (
	ContractMajor = 1
	ContractMinor = 5
	ContractPatch = 0
)

// SchemaVersion is the tile-contract major this module implements.
//
// Deprecated: use ContractMajor. The tile and the bundle envelope now share one
// contract version (ADR-0012 Decision 1); this alias is kept so importers keep
// building across a v1 minor.
const SchemaVersion = ContractMajor

// BundleSchemaVersion is the catalog-bundle contract major this module
// implements.
//
// Deprecated: use ContractMajor. The tile and the bundle envelope now share one
// contract version (ADR-0012 Decision 1); this alias is kept so importers keep
// building across a v1 minor.
const BundleSchemaVersion = ContractMajor

// capabilityIntroducedIn is the only record of which minor of major 1
// introduced each must-understand capability, in the order they landed. It is
// the derivation behind the first tag, tileschema/v1.4.0.
//
// Unexported so nothing outside this package can rewrite the history; read it
// through CapabilityMinor. Adding a capability is a minor (ADR-0012 Decision
// 3): add it here with the new ContractMinor.
var capabilityIntroducedIn = map[string]int{
	CapabilityPrivilegeTiers:  1,
	CapabilityWebPort:         2,
	CapabilityTileSecrets:     3,
	CapabilityOperatorSecrets: 4,
}

// CapabilityMinor reports the contract minor that introduced capability, and
// whether this build knows the capability at all.
func CapabilityMinor(capability string) (minor int, ok bool) {
	minor, ok = capabilityIntroducedIn[capability]
	return minor, ok
}

// knownCapabilitiesFrom builds the legacy KnownCapabilities set from the
// capability history, so the set and the history cannot disagree.
func knownCapabilitiesFrom(history map[string]int) map[string]bool {
	known := make(map[string]bool, len(history))
	for capability := range history {
		known[capability] = true
	}
	return known
}
