package bmc

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultBackend is the selector fallback when RASPUTIN_BMC_BACKEND is
// unset: mock everywhere until a real driver is configured.
const DefaultBackend = "mock"

// Config carries the inputs a backend constructor may need. Each driver
// picks the fields it uses and ignores the rest.
type Config struct {
	// StateDir is the agent's BMC state directory (<agentStateDir>/bmc).
	StateDir string

	// BitScope driver settings (RASPUTIN_BMC_BITSCOPE_*, design doc
	// §2a); zero values select the documented defaults.
	BitScopeDev    string // serial device (default /dev/serial0)
	BitScopeUnlock string // bus unlock sequence (default per D-4)
	BitScopeMap    string // address map path (default <StateDir>/bitscope-map.json)

	// MockTargets is the mock backend's advertised bmc-targets list
	// (RASPUTIN_BMC_MOCK_TARGETS, comma-separated) — dev-only, for
	// exercising per-node gating without hardware. Empty = advertise
	// nothing, keeping dev clusters on permissive presence-only gating.
	MockTargets []string
}

// factory constructs one named backend from Config.
type factory func(Config) (Backend, error)

// factories is the backend registry. Real drivers (bitscope, turingpi,
// the Phase 3 chassis) add themselves here; main.go selects by name via
// RASPUTIN_BMC_BACKEND and only ever talks Backend. See
// design/control-plane/bmc-bitscope.md §2a.
var factories = map[string]factory{
	"mock": func(cfg Config) (Backend, error) {
		mb, err := NewMockBackend(cfg.StateDir)
		if err != nil {
			return nil, err
		}
		mb.SetTargets(cfg.MockTargets)
		return mb, nil
	},
	"bitscope": func(cfg Config) (Backend, error) { return NewBitScopeBackend(cfg) },
}

// New constructs the backend named kind. An empty kind selects
// DefaultBackend; an unregistered kind is an error naming the valid ones.
func New(kind string, cfg Config) (Backend, error) {
	if kind == "" {
		kind = DefaultBackend
	}
	f, ok := factories[kind]
	if !ok {
		return nil, fmt.Errorf("unknown BMC backend %q (expected %s)", kind, strings.Join(Names(), "|"))
	}
	return f(cfg)
}

// Names returns the registered backend kinds, sorted.
func Names() []string {
	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
