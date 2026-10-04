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
//     Nothing ever put RASPUTIN_BUS_PIN in its agent's environment.
//   - The bus accepts only TLS (geekdojo/geekdojo-brain#517), so this file is
//     the one route that agent has to the pin: without it the agent cannot
//     connect at all.
//
// It is written unconditionally rather than only when missing, so an identity
// restore or a regenerated key reaches the local agent with nobody editing a
// file: the agent reads this file again on every TLS handshake, so the new pin
// reaches the running agent on its next handshake (geekdojo/geekdojo-brain#669).
// The api writes it before its bus listens, so the agent's first handshake
// with the restarted bus already reads the new pin.
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
