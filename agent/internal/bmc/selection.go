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
	case "turingpi":
		var sel struct {
			Endpoint string `json:"endpoint"`
			User     string `json:"user"`
			Pass     string `json:"pass,omitempty"`
			CAPem    string `json:"ca_pem,omitempty"`
			Insecure bool   `json:"insecure_skip_verify,omitempty"`
			Targets  []struct {
				NodeID string `json:"node_id"`
				Slot   int    `json:"slot"`
			} `json:"targets"`
		}
		if err := json.Unmarshal(raw, &sel); err != nil {
			return nil, fmt.Errorf("bmc: turingpi selection: %w", err)
		}
		targets := make(map[string]int, len(sel.Targets))
		for _, e := range sel.Targets {
			if e.NodeID == "" {
				return nil, fmt.Errorf("bmc: turingpi selection: target with empty node_id")
			}
			if _, dup := targets[e.NodeID]; dup {
				return nil, fmt.Errorf("bmc: turingpi selection: node %q listed twice", e.NodeID)
			}
			targets[e.NodeID] = e.Slot
		}
		return NewTuringPiBackend(TuringPiOptions{
			Endpoint:           sel.Endpoint,
			User:               sel.User,
			Pass:               sel.Pass,
			Targets:            targets,
			CAPem:              sel.CAPem,
			InsecureSkipVerify: sel.Insecure,
		})
	}
	return nil, fmt.Errorf("bmc: unknown backend %q in selection (expected %s)", kind, strings.Join(Names(), "|"))
}
