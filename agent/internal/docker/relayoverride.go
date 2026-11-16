package docker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The relay override (geekdojo/geekdojo-brain#1081). An app granted a runtime
// identity has a relay directory (agent/internal/apprelay) holding its socket
// and the CA it verifies it by, and every one of its containers mounts it,
// read-only, at proto.AppRelayMountPath. The mount is not written into the
// compose: the api's compose text, its hash and the UI's preview stay what
// the owner or the catalog wrote. The agent writes a Compose override file
// beside the compose instead, binding the directory into every service of
// the compose's normalized model, and every compose call on the live file
// reads both (liveFiles). `up`, `ps`, `down` and `config --hash` then all see
// the same model, so Status does not read a relayed app as outdated.

// relayOverrideFile is the override's name in the app's state directory.
// JSON is YAML, so Compose reads it as a compose file.
const relayOverrideFile = "relay.override.json"

func (c *ComposeBackend) relayOverridePath(appID string) string {
	return filepath.Join(c.appDir(appID), relayOverrideFile)
}

// liveFiles is the compose files every call on appID's live compose reads:
// the compose, and the relay override when one exists.
func (c *ComposeBackend) liveFiles(appID string) []string {
	files := []string{c.composePath(appID)}
	if _, err := os.Stat(c.relayOverridePath(appID)); err == nil {
		files = append(files, c.relayOverridePath(appID))
	}
	return files
}

// overrideMount is one long-form volume entry of the override.
type overrideMount struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

type overrideService struct {
	Volumes []overrideMount `json:"volumes"`
}

type overrideFile struct {
	Services map[string]overrideService `json:"services"`
}

// relayOverride is the override binding relayDir read-only at
// proto.AppRelayMountPath into every service of model (composeModel). A
// model with no service is refused: there would be nothing to mount into.
func relayOverride(model any, relayDir string) ([]byte, error) {
	top, _ := model.(map[string]any)
	services, _ := top["services"].(map[string]any)
	if len(services) == 0 {
		return nil, errors.New("refusing the deploy: the compose has no service to mount the relay socket into")
	}
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	f := overrideFile{Services: make(map[string]overrideService, len(names))}
	for _, name := range names {
		f.Services[name] = overrideService{Volumes: []overrideMount{{
			Type: "bind", Source: relayDir, Target: proto.AppRelayMountPath, ReadOnly: true,
		}}}
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("encode the relay override: %w", err)
	}
	return b, nil
}

// writeRelayOverride writes appID's override, owner-only, or removes it when
// override is nil. An absent file is success.
func (c *ComposeBackend) writeRelayOverride(appID string, override []byte) error {
	if override == nil {
		if err := os.Remove(c.relayOverridePath(appID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return atrest.WriteSecretFile(c.relayOverridePath(appID), override)
}
