package main

import (
	cryptorand "crypto/rand"
	"log/slog"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/apprelay"
)

// appRelayDir is where the relay keeps each app's socket, key, certificate
// and CA (geekdojo/geekdojo-brain#1081), under the agent's state directory.
func appRelayDir(stateDir string) string { return filepath.Join(stateDir, "apprelay") }

// newAppRelay builds the app relay for nodeID: the forwarder that carries an
// app's calls to the api, and the Manager that owns every app's socket. The
// key's randomness and the correlation ids are crypto/rand's, chosen here and
// nowhere else (ARCH-IOC).
func newAppRelay(stateDir, nodeID string, logger *slog.Logger) (*apprelay.Relay, *apprelay.Manager, error) {
	relay, err := apprelay.NewRelay(nodeID, apprelay.DefaultCallBound, logger)
	if err != nil {
		return nil, nil, err
	}
	mgr, err := apprelay.NewManager(apprelay.ManagerDeps{
		Dir: appRelayDir(stateDir), Rand: cryptorand.Reader, Forward: relay, IDs: cryptorand.Text, Log: logger,
	})
	if err != nil {
		return nil, nil, err
	}
	return relay, mgr, nil
}
