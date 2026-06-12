package main

import (
	"os"
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

func TestAutodetectUCIBackend(t *testing.T) {
	// No uci binary on PATH → mock, regardless of the config file.
	cfgDir := t.TempDir()
	cfg := filepath.Join(cfgDir, "firewall")
	if err := os.WriteFile(cfg, []byte("config defaults\n"), 0o644); err != nil {
		t.Fatalf("write fake firewall config: %v", err)
	}
	t.Setenv("PATH", t.TempDir()) // empty dir — nothing on PATH
	if got := autodetectUCIBackendAt(cfg); got != "mock" {
		t.Errorf("no uci on PATH: got %q, want mock", got)
	}

	// uci on PATH but no /etc/config/firewall (e.g. a dev box with a
	// stray uci binary) → mock.
	binDir := t.TempDir()
	fakeUCI := filepath.Join(binDir, "uci")
	if err := os.WriteFile(fakeUCI, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake uci: %v", err)
	}
	t.Setenv("PATH", binDir)
	if got := autodetectUCIBackendAt(filepath.Join(cfgDir, "missing")); got != "mock" {
		t.Errorf("uci without firewall config: got %q, want mock", got)
	}

	// Both present → uci (a real OpenWrt root).
	if got := autodetectUCIBackendAt(cfg); got != "uci" {
		t.Errorf("uci + firewall config: got %q, want uci", got)
	}
}

func TestUCIBackendSelectionEnvOverride(t *testing.T) {
	// Autodetect would say mock (nothing on PATH), but the env forces uci.
	t.Setenv("PATH", t.TempDir())
	t.Setenv("RASPUTIN_UCI_BACKEND", "uci")
	if got := envOr("RASPUTIN_UCI_BACKEND", autodetectUCIBackend()); got != "uci" {
		t.Errorf("env override: got %q, want uci", got)
	}
	// Empty env falls through to autodetect.
	t.Setenv("RASPUTIN_UCI_BACKEND", "")
	if got := envOr("RASPUTIN_UCI_BACKEND", autodetectUCIBackend()); got != "mock" {
		t.Errorf("autodetect fallback: got %q, want mock", got)
	}
}
