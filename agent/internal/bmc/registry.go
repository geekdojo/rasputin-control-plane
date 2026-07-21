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
}

// factory constructs one named backend from Config.
type factory func(Config) (Backend, error)

// factories is the backend registry. Real drivers (bitscope, turingpi,
// the Phase 3 chassis) add themselves here; main.go selects by name via
// RASPUTIN_BMC_BACKEND and only ever talks Backend. See
// design/control-plane/bmc-bitscope.md §2a.
var factories = map[string]factory{
	"mock": func(cfg Config) (Backend, error) { return NewMockBackend(cfg.StateDir) },
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
