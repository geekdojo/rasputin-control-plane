package main

import (
	"cmp"
	"os"
	"path/filepath"
	"strings"
)

// The api's security-setting resolvers (geekdojo/geekdojo-brain#591). Each one
// reads exactly one variable, by a LITERAL key, so failopenlint's FO04 rule can
// see the read and the security-resolvers register can hold it to a
// fail-closed table test. Shared logic takes the value, never the key: a helper
// handed the key would hide the read from FO04.
//
// They return values, never errors, and they do not log. A malformed RP ID or
// origin is refused one layer down, by auth.NewService, which main treats as
// fatal; the resolvers do not repeat that validation. secureCookies, the R01
// resolver, stays in main.go beside the derivation it documents.

// trustDirFromEnv resolves RASPUTIN_TRUST_DIR, the directory holding the
// bundle-signing root and the mesh CA. A blank value gives <dataDir>/trust and
// padding is trimmed, so the result is never empty.
func trustDirFromEnv(dataDir string) string {
	return cmp.Or(strings.TrimSpace(os.Getenv("RASPUTIN_TRUST_DIR")), filepath.Join(dataDir, "trust"))
}

// cpAuthorizedKeysFromEnv resolves RASPUTIN_CP_AUTHORIZED_KEYS, the control
// plane's own authorized_keys, whose first key seeds the operator SSH key
// setting. A blank value gives the dropbear default and padding is trimmed.
func cpAuthorizedKeysFromEnv() string {
	return cmp.Or(strings.TrimSpace(os.Getenv("RASPUTIN_CP_AUTHORIZED_KEYS")), "/var/lib/rasputin/dropbear/authorized_keys")
}

// rpIDFromEnv resolves RASPUTIN_RP_ID, the WebAuthn relying-party ID. A blank
// value gives the derived default: <cluster-id>.local on an appliance,
// localhost on a dev box. Padding is trimmed.
func rpIDFromEnv() string {
	return cmp.Or(strings.TrimSpace(os.Getenv("RASPUTIN_RP_ID")),
		applianceOr(func(h string) string { return h }, "localhost"))
}

// rpOriginsFromEnv resolves RASPUTIN_RP_ORIGINS, the comma-separated browser
// origins the passkey ceremony accepts. A value that yields no origin — empty,
// blank, or only commas — gives the derived default: https://<cluster-id>.local
// on an appliance, the two localhost origins on a dev box. It never returns an
// empty list, so auth.NewService's own localhost fallback is never reached.
func rpOriginsFromEnv() []string {
	if origins := splitCSV(os.Getenv("RASPUTIN_RP_ORIGINS")); len(origins) > 0 {
		return origins
	}
	return splitCSV(applianceOr(
		func(h string) string { return "https://" + h },
		"http://localhost:3000,http://localhost:8080"))
}
