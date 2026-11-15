package main

import (
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The agent's relay is built from the composition root's own randomness and
// ids (F-1081-04), under the agent state directory, and a fresh state
// directory (an agent from before the relay) restores nothing
// (TC-1081-26).
func TestNewAppRelay_BuildsUnderTheStateDir(t *testing.T) {
	log, rec := logkittest.New()
	state := t.TempDir()
	relay, mgr, err := newAppRelay(state, "n1", log)
	if err != nil || relay == nil || mgr == nil {
		t.Fatalf("newAppRelay = %v, %v, %v", relay, mgr, err)
	}
	if got := appRelayDir(state); got != filepath.Join(state, "apprelay") {
		t.Errorf("relay dir %s", got)
	}
	mgr.Restore()
	if n := len(rec.Records()); n != 0 {
		t.Errorf("Restore on a state dir with no relay logged %d records", n)
	}
	if _, ok := mgr.MountDir("01J9ZK3Q0M8X7Y6W5V4T3S2R1A"); ok {
		t.Error("an app has a socket on a fresh node")
	}
	if _, _, err := newAppRelay(state, "", log); err == nil {
		t.Error("an empty node id was accepted")
	}
}
