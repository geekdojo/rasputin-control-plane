package docker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

const relayAppID = "01J9ZK3Q0M8X7Y6W5V4T3S2R1A"

// relayHash is a config hash the fake compose prints and stamps alike.
const relayHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// argvRecorder is a docker CLI that records every argv and answers the calls
// a deploy and a status make.
type argvRecorder struct {
	mu    sync.Mutex
	argv  [][]string
	model string
}

func (r *argvRecorder) exec(_ context.Context, args ...string) ([]byte, error) {
	r.mu.Lock()
	r.argv = append(r.argv, slices.Clone(args))
	r.mu.Unlock()
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "config --no-interpolate"):
		return []byte(r.model), nil
	case strings.Contains(joined, "config --hash"):
		return []byte("web " + relayHash + "\n"), nil
	case strings.Contains(joined, " ps --format"):
		return []byte(`{"Name":"w","Service":"web","State":"running","ExitCode":0,"Labels":"com.docker.compose.config-hash=` + relayHash + `"}` + "\n"), nil
	}
	return nil, nil
}

func (r *argvRecorder) calls() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.argv)
}

func (r *argvRecorder) reset() {
	r.mu.Lock()
	r.argv = nil
	r.mu.Unlock()
}

// sub is the compose subcommand of argv: what follows "-p <project>".
func sub(argv []string) string {
	for i, a := range argv {
		if a == "-p" && i+2 <= len(argv) {
			return strings.Join(argv[i+2:], " ")
		}
	}
	return ""
}

// files is every -f argument of argv.
func files(argv []string) []string {
	var out []string
	for i, a := range argv {
		if a == "-f" && i+1 < len(argv) {
			out = append(out, argv[i+1])
		}
	}
	return out
}

func newRelayBackend(t *testing.T, model string) (*ComposeBackend, *argvRecorder) {
	t.Helper()
	r := &argvRecorder{model: model}
	c := &ComposeBackend{dir: t.TempDir()}
	c.exec = r.exec
	c.execEnv = func(ctx context.Context, _ []string, args ...string) ([]byte, error) { return r.exec(ctx, args...) }
	return c, r
}

// TC-1081-23: the override binds the relay directory read-only into every
// service of Compose's model, owner-only; every call on the live compose
// reads it exactly when it exists; with no relay a leftover is removed and
// the argv is the one before the change; RemoveCompose and TightenAppState
// cover it; pull, the guard and the volume gate never read it.
func TestRelayOverride_OverrideAndArgv(t *testing.T) {
	ctx := context.Background()
	// The model as Compose prints it once include, extends and anchors are
	// resolved: three services, one of which came from an include.
	model := `{"name":"p","services":{"web":{"image":"a"},"db":{"image":"b"},"from-include":{"image":"c"}}}`
	c, rec := newRelayBackend(t, model)
	relayDir := "/var/lib/rasputin/agent-state/apprelay/" + relayAppID + "/mnt"
	override := c.relayOverridePath(relayAppID)
	compose := c.composePath(relayAppID)

	if _, _, err := c.Deploy(ctx, relayAppID, "app", "services: {}\n", nil, relayDir); err != nil {
		t.Fatalf("relayed Deploy: %v", err)
	}
	b, err := os.ReadFile(override)
	if err != nil {
		t.Fatal(err)
	}
	var got overrideFile
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 3 {
		t.Errorf("override covers %d services, want 3", len(got.Services))
	}
	for name, svc := range got.Services {
		want := []overrideMount{{Type: "bind", Source: relayDir, Target: proto.AppRelayMountPath, ReadOnly: true}}
		if !slices.Equal(svc.Volumes, want) {
			t.Errorf("%s volumes %+v, want %+v", name, svc.Volumes, want)
		}
	}
	if m := mode(t, override); m != 0o600 {
		t.Errorf("override mode %o, want 0600", m)
	}
	for _, argv := range rec.calls() {
		s := sub(argv)
		live := slices.Contains(files(argv), compose)
		withOverride := slices.Contains(files(argv), override)
		if live && !withOverride {
			t.Errorf("%q read the live compose without the override", s)
		}
		if strings.HasPrefix(s, "config --no-interpolate") && withOverride {
			t.Error("the guard read the override")
		}
	}

	rec.reset()
	if _, _, err := c.Status(ctx, relayAppID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Stop(ctx, relayAppID, false); err != nil {
		t.Fatal(err)
	}
	if err := c.StopApp(ctx, relayAppID, 10); err != nil {
		t.Fatal(err)
	}
	if err := c.StartApp(ctx, relayAppID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Pull(ctx, relayAppID, "services: {}\n"); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, argv := range rec.calls() {
		if argv[0] != "compose" {
			continue // the volume record's own docker calls read no compose
		}
		s := sub(argv)
		f := files(argv)
		switch {
		case strings.HasPrefix(s, "pull"):
			if len(f) != 1 || f[0] == compose {
				t.Errorf("pull read %v, want only its staged file", f)
			}
		default:
			if !slices.Equal(f, []string{compose, override}) {
				t.Errorf("%q read %v, want the compose and the override", s, f)
			}
			seen[strings.Fields(s)[0]] = true
		}
	}
	for _, want := range []string{"ps", "config", "down", "stop", "start"} {
		if !seen[want] {
			t.Errorf("no %s call was checked", want)
		}
	}

	// Redeployed without the relay: the override goes, before anything reads
	// the new compose, and no model is asked for.
	rec.reset()
	if _, _, err := c.Deploy(ctx, relayAppID, "app", "services: {}\n", nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(override); !os.IsNotExist(err) {
		t.Error("the leftover override survived a deploy without the relay")
	}
	for _, argv := range rec.calls() {
		if strings.HasPrefix(sub(argv), "config --no-interpolate") {
			t.Error("a deploy with no env and no relay asked for the model")
		}
		if strings.HasPrefix(sub(argv), "up") {
			want := []string{"compose", "-f", compose, "-p", projectName(relayAppID), "up", "-d", "--remove-orphans", "--quiet-pull"}
			if !slices.Equal(argv, want) {
				t.Errorf("up argv %v, want the argv before the change %v", argv, want)
			}
		}
	}

	// RemoveCompose removes it; TightenAppState tightens it.
	if err := c.writeRelayOverride(relayAppID, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(override, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := TightenAppState(c.dir); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, override); m != 0o600 {
		t.Errorf("TightenAppState left the override %o", m)
	}
	if err := c.RemoveCompose(ctx, relayAppID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(override); !os.IsNotExist(err) {
		t.Error("RemoveCompose left the override")
	}

	// A secret-bearing relayed deploy: the two calls that carry the values
	// (runEnv) read the override too, and the model is asked for once.
	withEnv, envRec := newRelayBackend(t, `{"services":{"web":{"environment":{"P":"${RASPUTIN_SECRET_P}"}}}}`)
	if _, _, err := withEnv.Deploy(ctx, relayAppID, "app", "services: {}\n", proto.AppSecretEnv{"RASPUTIN_SECRET_P": "v"}, relayDir); err != nil {
		t.Fatalf("relayed Deploy with env: %v", err)
	}
	models := 0
	for _, argv := range envRec.calls() {
		s := sub(argv)
		if strings.HasPrefix(s, "config --no-interpolate") {
			models++
		}
		if (strings.HasPrefix(s, "up") || strings.HasPrefix(s, "config --hash")) &&
			!slices.Equal(files(argv), []string{withEnv.composePath(relayAppID), withEnv.relayOverridePath(relayAppID)}) {
			t.Errorf("%q with the values read %v, want the compose and the override", s, files(argv))
		}
	}
	if models != 1 {
		t.Errorf("the model was asked for %d times, want once for the guard and the override", models)
	}

	// A model with no service is refused before anything is written.
	empty, _ := newRelayBackend(t, `{"services":{}}`)
	if _, _, err := empty.Deploy(ctx, relayAppID, "app", "services: {}\n", nil, relayDir); err == nil {
		t.Error("a relayed deploy of a compose with no service went ahead")
	}
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// fakeMounts answers MountDir from a map.
type fakeMounts map[string]string

func (f fakeMounts) MountDir(appID string) (string, bool) {
	d, ok := f[appID]
	return d, ok
}

// TC-1081-24: Relay with no open socket fails the deploy with the sentence,
// writing nothing; with a socket the backend is given its mount directory;
// without Relay it is given "".
func TestHandleDeploy_Relay(t *testing.T) {
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatal(err)
	}
	const mnt = "/state/apprelay/A/mnt"
	if _, err := RegisterHandlers(nc, "n", mb, fakeMounts{relayAppID: mnt}); err != nil {
		t.Fatal(err)
	}
	deploy := func(cmd proto.AppDeployCmd) proto.AppDeployAck {
		t.Helper()
		b, _ := json.Marshal(cmd)
		msg, err := nc.Request(proto.AppDeploySubject("n"), b, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var ack proto.AppDeployAck
		_ = json.Unmarshal(msg.Data, &ack)
		return ack
	}
	const other = "01J9ZK3Q0M8X7Y6W5V4T3S2R1B"
	if ack := deploy(proto.AppDeployCmd{AppID: other, Name: "x", ComposeYAML: "services: {}\n", Relay: true}); ack.OK || ack.Detail != errNoRelaySocket {
		t.Errorf("no socket: %+v, want refused with %q", ack, errNoRelaySocket)
	}
	if _, err := os.Stat(filepath.Join(dir, other)); !os.IsNotExist(err) {
		t.Error("the refused deploy wrote the app's state")
	}
	if ack := deploy(proto.AppDeployCmd{AppID: relayAppID, Name: "x", ComposeYAML: "services: {}\n", Relay: true}); !ack.OK {
		t.Fatalf("with a socket: %+v", ack)
	}
	if s, _ := mb.loadState(relayAppID); s == nil || s.RelayDir != mnt {
		t.Errorf("the backend got relay dir %+v, want %s", s, mnt)
	}
	if ack := deploy(proto.AppDeployCmd{AppID: relayAppID, Name: "x", ComposeYAML: "services: {}\n"}); !ack.OK {
		t.Fatalf("without Relay: %+v", ack)
	}
	if s, _ := mb.loadState(relayAppID); s == nil || s.RelayDir != "" {
		t.Errorf("without Relay the backend got %+v, want no relay dir", s)
	}
}
