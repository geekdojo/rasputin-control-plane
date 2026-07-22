package bmc

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NewFromSelection constructs a backend from a settings-pushed
// selection (bmc-settings.md §3–4). The per-kind blob is the settings
// shape — bitscope carries its address map inline; mock carries a
// target list — distinct from the env-var shape NewBackend/Config use.
func NewFromSelection(kind string, raw json.RawMessage, stateDir string) (Backend, error) {
	switch kind {
	case "mock":
		var sel struct {
			Targets []string `json:"targets"`
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &sel); err != nil {
				return nil, fmt.Errorf("bmc: mock selection: %w", err)
			}
		}
		mb, err := NewMockBackend(stateDir)
		if err != nil {
			return nil, err
		}
		mb.SetTargets(sel.Targets)
		return mb, nil
	case "bitscope":
		var sel struct {
			Dev     string             `json:"dev,omitempty"`
			Unlock  string             `json:"unlock,omitempty"`
			Targets []bitscopeMapEntry `json:"targets"`
		}
		if err := json.Unmarshal(raw, &sel); err != nil {
			return nil, fmt.Errorf("bmc: bitscope selection: %w", err)
		}
		targets, err := buildBitScopeTargets("settings", sel.Targets)
		if err != nil {
			return nil, err
		}
		if sel.Dev == "" {
			sel.Dev = bitscopeDefaultDev
		}
		if sel.Unlock == "" {
			sel.Unlock = bitscopeDefaultUnlock
		}
		return newBitScopeOnDevice(sel.Dev, sel.Unlock, targets)
	}
	return nil, fmt.Errorf("bmc: unknown backend %q in selection (expected %s)", kind, strings.Join(Names(), "|"))
}
