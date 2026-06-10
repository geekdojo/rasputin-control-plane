package main

import (
	"path/filepath"
	"testing"
)

func TestAgentStateDir(t *testing.T) {
	// Unset (t.Setenv to "" — agentStateDir treats empty as unset):
	// dev default, relative, with the per-node suffix.
	t.Setenv("RASPUTIN_AGENT_STATE_DIR", "")
	if got, want := agentStateDir("node-dev"), filepath.Join("agent-state", "node-dev"); got != want {
		t.Errorf("default: got %q, want %q", got, want)
	}

	// Set: used verbatim — absolute, and NO nodeID suffix appended. The
	// rasputin-os systemd unit and the OpenWrt init script rely on this
	// (they point at a flat dir on persistent storage), as does the dev
	// workflow in the wiki's getting-started.md, which appends its own
	// per-node suffix.
	t.Setenv("RASPUTIN_AGENT_STATE_DIR", "/var/lib/rasputin/agent-state")
	if got, want := agentStateDir("node-dev"), "/var/lib/rasputin/agent-state"; got != want {
		t.Errorf("env override: got %q, want %q", got, want)
	}
}
