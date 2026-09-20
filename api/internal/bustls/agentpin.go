package bustls

import (
	"fmt"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// WriteAgentPinFile puts the live pin in busDir/agent.pin
// (proto.BusAgentPinFileName), where the controlplane's OWN agent reads it when
// nothing else gave it a pin.
//
// Why the api writes it at all, on every start, on every controlplane —
// appliance and dev alike (geekdojo/geekdojo-brain#510):
//
//   - A controlplane that self-initialised (the bootstrap.sh path) has no seed.
//     Nothing ever put RASPUTIN_BUS_PIN in its agent's environment, so before
//     this file its agent's only route to the pin was a bus.pin delivery over
//     the PLAINTEXT bus — the api's own loopback agent was, by construction,
//     the last plaintext client on the bus and the thing holding `require`
//     back.
//   - A controlplane that starts in `require` never makes that delivery: its
//     agent cannot connect at all without the pin it was going to be sent.
//
// It is written unconditionally rather than only when missing, so an identity
// restore or a regenerated key reaches the local agent on its next start with
// nobody editing a file.
//
// The pin is public — it is the hash of a public key, printed by
// GET /api/bus/tls and rendered into every seed — so the file is 0644. It sits
// inside the bus directory, which stays 0700; the agent runs as the same user
// as the api on every image we ship.
func WriteAgentPinFile(busDir string, key *Key) (path string, err error) {
	if key == nil {
		return "", fmt.Errorf("bustls: no bus key, so there is no pin to write for this controlplane's agent")
	}
	path = filepath.Join(busDir, proto.BusAgentPinFileName)
	if err := atrest.EnsureSecretDir(busDir); err != nil {
		return path, fmt.Errorf("bustls: %w", err)
	}
	if err := atrest.WritePublicFile(path, []byte(key.Pin()+"\n")); err != nil {
		return path, fmt.Errorf("bustls: write %s: %w", path, err)
	}
	return path, nil
}
