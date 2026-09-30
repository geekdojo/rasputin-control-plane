package main

import (
	"cmp"
	"os"
	"slices"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/clusterdns"
)

// The agent's security-setting resolvers (geekdojo/geekdojo-brain#591). Each
// one reads exactly one variable, by a LITERAL key, so failopenlint's FO04 rule
// can see the read and the security-resolvers register can hold it to a
// fail-closed table test. Shared logic takes the value, never the key: a helper
// handed the key would hide the read from FO04.
//
// They return values, never errors, and they do not log. What an unknown value
// means is decided where it is consumed: main's switch arms record a
// configfault and leave the subsystem off, and bmc.NewHost refuses a name it
// does not carry.

// selectBackend is the shared core of the five backend selectors. set is the
// variable's value, real the backend names the subsystem's autodetect may
// answer, and detect the autodetect probe.
//
//   - set empty (absent or set-but-empty; os.Getenv cannot tell them apart):
//     detect's answer if it is one of real, otherwise backendUnavailable. A
//     probe answer outside real, "mock" included, is never honoured, so mock
//     cannot be inferred.
//   - set to "mock" or to a name in real: set, and detect is not called.
//   - anything else: set verbatim, with no trim and no case-fold, so main's
//     default arm reports exactly what the operator typed and the value can
//     never select mock or a real backend by accident. Exact matching agrees
//     with the other reader of RASPUTIN_UCI_BACKEND (agent/internal/health).
func selectBackend(set string, real []string, detect func() string) string {
	if set != "" {
		return set
	}
	if got := detect(); slices.Contains(real, got) {
		return got
	}
	return backendUnavailable
}

// dockerBackendFromEnv resolves RASPUTIN_DOCKER_BACKEND: docker | mock.
func dockerBackendFromEnv(detect func() string) string {
	return selectBackend(os.Getenv("RASPUTIN_DOCKER_BACKEND"), []string{"docker"}, detect)
}

// uciBackendFromEnv resolves RASPUTIN_UCI_BACKEND: uci | mock.
func uciBackendFromEnv(detect func() string) string {
	return selectBackend(os.Getenv("RASPUTIN_UCI_BACKEND"), []string{"uci"}, detect)
}

// updateBackendFromEnv resolves RASPUTIN_UPDATE_BACKEND: rauc | openwrt-ab | mock.
func updateBackendFromEnv(detect func() string) string {
	return selectBackend(os.Getenv("RASPUTIN_UPDATE_BACKEND"), []string{"rauc", "openwrt-ab"}, detect)
}

// storageBackendFromEnv resolves RASPUTIN_STORAGE_BACKEND: blockdev | mock.
func storageBackendFromEnv(detect func() string) string {
	return selectBackend(os.Getenv("RASPUTIN_STORAGE_BACKEND"), []string{"blockdev"}, detect)
}

// tailscaleBackendFromEnv resolves RASPUTIN_TAILSCALE_BACKEND: tailscale | mock.
func tailscaleBackendFromEnv(detect func() string) string {
	return selectBackend(os.Getenv("RASPUTIN_TAILSCALE_BACKEND"), []string{"tailscale"}, detect)
}

// bmcBackendFromEnv returns RASPUTIN_BMC_BACKEND verbatim. Empty means there is
// no env pin, so the persisted Settings selection governs. An unknown name is
// refused by bmc.New with ErrUnknownBackend, which main reports before coming
// up BMC-off.
func bmcBackendFromEnv() string {
	return os.Getenv("RASPUTIN_BMC_BACKEND")
}

// resolvedDropinDirFromEnv resolves RASPUTIN_RESOLVED_DROPIN_DIR, the
// systemd-resolved drop-in directory clusterdns pins the cluster name in. A
// blank value gives clusterdns.DefaultDir and padding is trimmed, so the
// result is never empty.
func resolvedDropinDirFromEnv() string {
	return cmp.Or(strings.TrimSpace(os.Getenv("RASPUTIN_RESOLVED_DROPIN_DIR")), clusterdns.DefaultDir)
}
