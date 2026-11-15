package docker

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-1081-29, the functional test of the relay mount
// (docs/testing-app-relay.md): the real ComposeBackend against real Docker
// Compose. Only Compose shows that the override reaches every container,
// read-only, that `config --hash` with the override equals the label `up`
// stamped (so Status does not read outdated), that a stop and start keep the
// mount, and that redeploying without the relay takes it away. It runs under
// RASPUTIN_APPSECRET_FUNCTIONAL, the switch this package's Compose tests
// share: CI sets it to required.

// relayCompose is two services, and with secret set the first carries a
// secret reference.
func relayCompose(secret bool) string {
	s := "services:\n  web:\n    image: " + functionalImage + "\n    command: [\"sleep\", \"3600\"]\n"
	if secret {
		s += "    environment:\n      APP_SECRET: ${RASPUTIN_SECRET_CANARY}\n"
	}
	return s + "  worker:\n    image: " + functionalImage + "\n    command: [\"sleep\", \"3600\"]\n"
}

// relayDirFixture is a relay mount directory as the agent makes one: the CA
// file and a listening socket.
func relayDirFixture(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rly")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// The real path: on macOS /tmp is a link to /private/tmp, and a bind
	// source given through the link names a directory inside Docker
	// Desktop's VM rather than the shared host one.
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, proto.AppRelayCAName), []byte("-----BEGIN CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, proto.AppRelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return dir
}

type mountInfo struct {
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

// relayMount is the container's mount at AppRelayMountPath, if it has one.
func relayMount(t *testing.T, id string) (mountInfo, bool) {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "--format", "{{json .Mounts}}", id).Output()
	if err != nil {
		t.Fatalf("docker inspect: %v", err)
	}
	var mounts []mountInfo
	if err := json.Unmarshal(out, &mounts); err != nil {
		t.Fatal(err)
	}
	for _, m := range mounts {
		if m.Destination == proto.AppRelayMountPath {
			return m, true
		}
	}
	return mountInfo{}, false
}

// assertRelayMounted fails unless every container of appID mounts the relay
// directory read-only, and lists ca.pem and relay.sock in it.
func assertRelayMounted(t *testing.T, appID string) {
	t.Helper()
	ids := projectContainers(t, appID)
	if len(ids) != 2 {
		t.Fatalf("%d containers, want 2", len(ids))
	}
	for _, id := range ids {
		m, ok := relayMount(t, id)
		if !ok || m.RW {
			t.Errorf("container %s: relay mount %+v present=%v, want it read-only", id, m, ok)
			continue
		}
		names := []string{proto.AppRelayCAName, proto.AppRelaySocketName}
		out, err := exec.Command("docker", "exec", id, "ls", "-l", proto.AppRelayMountPath).CombinedOutput()
		if runtime.GOOS != "linux" {
			// Docker Desktop's file sharing carries files into its VM but not
			// Unix sockets (ls lists the entry and cannot stat it), so the
			// socket is checked only where dockerd runs on the host: Linux,
			// which is CI and every node.
			t.Logf("%s: not checking %s inside the container: Docker Desktop does not share socket files", runtime.GOOS, proto.AppRelaySocketName)
			names, err = names[:1], nil
		}
		if err != nil {
			t.Fatalf("docker exec ls: %v %s", err, out)
		}
		for _, name := range names {
			if !strings.Contains(string(out), name) {
				t.Errorf("container %s: %s lacks %s:\n%s", id, proto.AppRelayMountPath, name, out)
			}
		}
	}
}

func TestRelayOverrideFunctional_MountStatusAndRemoval(t *testing.T) {
	requireCompose(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		env  proto.AppSecretEnv
	}{
		{"plain", nil},
		{"secret-bearing", proto.AppSecretEnv{"RASPUTIN_SECRET_CANARY": canaryValue(t)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			appID := functionalAppID(t)
			c := functionalBackend(t, appID)
			compose := relayCompose(tc.env != nil)
			relayDir := relayDirFixture(t)

			if status, detail, err := c.Deploy(ctx, appID, "fn", compose, tc.env, relayDir); err != nil || status != proto.AppStatusRunning {
				t.Fatalf("relayed Deploy = %s, %q, %v", status, detail, err)
			}
			assertRelayMounted(t, appID)
			assertRunningCurrent(t, c, appID)

			if err := c.StopApp(ctx, appID, 5); err != nil {
				t.Fatalf("StopApp: %v", err)
			}
			if err := c.StartApp(ctx, appID); err != nil {
				t.Fatalf("StartApp: %v", err)
			}
			assertRelayMounted(t, appID)
			assertRunningCurrent(t, c, appID)

			if status, detail, err := c.Deploy(ctx, appID, "fn", compose, tc.env, ""); err != nil || status != proto.AppStatusRunning {
				t.Fatalf("Deploy without the relay = %s, %q, %v", status, detail, err)
			}
			for _, id := range projectContainers(t, appID) {
				if _, ok := relayMount(t, id); ok {
					t.Errorf("container %s still mounts the relay", id)
				}
			}
			if _, err := os.Stat(c.relayOverridePath(appID)); !os.IsNotExist(err) {
				t.Error("the override survived a deploy without the relay")
			}
			assertRunningCurrent(t, c, appID)
		})
	}
}
