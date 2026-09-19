//go:build unix

package obs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAtRestModes pins the modes of every file the observability supervisor
// renders — a row of the api's at-rest inventory (api/internal/atrest,
// TestAtRestModes; gate geekdojo/geekdojo-brain#494). The compose file is
// owner-only: only the docker CLI, run by the api, reads it, and a compose
// file can carry a credential. The configs are public by design: the
// containers that read them run as fixed non-root uids, so they are 0644, set
// explicitly rather than left to the umask.
func TestAtRestModes(t *testing.T) {
	dir := t.TempDir()
	tr := true
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      dir,
		Runner:        newFakeCompose().run,
		EnableLoki:    &tr,
		EnableGrafana: &tr,
		EnableVMAlert: &tr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.prepareHostDirs(); err != nil {
		t.Fatal(err)
	}
	// An older api left the compose file 0644; the next render tightens it.
	compose := filepath.Join(dir, composeFileName)
	if err := os.WriteFile(compose, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, write := range map[string]func() error{
		"compose": sup.writeCompose,
		"alloy":   sup.writeAlloyConfig,
		"loki":    sup.writeLokiConfig,
		"grafana": sup.writeGrafanaConfig,
		"vmalert": sup.writeVMAlertConfig,
	} {
		if err := write(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	want := map[string]os.FileMode{
		composeFileName: 0o600,
		filepath.Join(alloyConfigSubdir, alloyConfigFile): 0o644,
		filepath.Join(lokiConfigSubdir, lokiConfigFile):   0o644,
		grafanaIniPath: 0o644,
		filepath.Join(vmalertConfigSubdir, vmalertRulesFile): 0o644,
	}
	for _, f := range sup.grafanaProvisioningFiles() {
		want[f.path] = 0o644
	}
	for rel, mode := range want {
		info, err := os.Stat(filepath.Join(dir, rel))
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		if got := info.Mode().Perm(); got != mode {
			t.Errorf("%s: mode %#o, want %#o", rel, got, mode)
		}
	}
}
